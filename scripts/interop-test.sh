#!/bin/sh
# End-to-end interoperability with Avahi, on any Linux host with Docker.
#
#   scripts/interop-test.sh
#
# Builds the image from the repository's Dockerfile and an Avahi image, then
# runs everything on a Docker bridge network of its own, in documentation
# address ranges, leaving the host's network configuration alone. The
# bridge is an interface on the Docker host, though, so a responder running
# there (an avahi-daemon on every interface, say) joins it from the
# gateway address and sees and answers this traffic like any other host on
# the link; nothing here tries to keep it out, and the checks hold with it:
#
#   host  198.51.100.10  avahi-daemon named interop-host.local, plus
#                        mdns-alias in the same network namespace
#                        (`--network container:`), both bound to port 5353
#                        as different users, as on a real host
#   peer  198.51.100.20  a second avahi-daemon: another machine on the LAN
#
# and checks, failing on the first that does not hold:
#
#   1. Resolution: Avahi resolves the aliases to the host's address, over
#      IPv4 and (when the network gets IPv6) IPv6, from the peer and from
#      the host's own avahi-daemon.
#   2. Sharing port 5353: mdns-alias announces; avahi-daemon keeps its own
#      name without a conflict, the peer still resolves it, and it still
#      probes for and claims a new name beside mdns-alias.
#   3. Conflicts: a name Avahi already holds makes mdns-alias log the
#      conflict and give it up on that link, without exiting, while its
#      other aliases keep resolving; and Avahi probing for a name
#      mdns-alias holds loses, with mdns-alias still serving it.
#   4. A legacy unicast query (scripts/mdns-query.py) is answered in the
#      shared namespace, for an alias and for Avahi's own name.
#
# It also reports, without failing on it, which of the two sockets a query
# sent straight to the host's address on port 5353 reaches.
#
# Everything it creates (containers, the network, both images) carries a
# random suffix and is removed on exit, pass or fail. The subnets are fixed
# documentation ranges, so one run per Docker host at a time: a second run
# fails to create its network. Base images it pulls
# stay in the local cache. Needs Docker and nothing else on the host.
set -eu
cd "$(dirname "$0")/.."

# The base is pinned by digest, like the Dockerfile's. The packages are
# deliberately unpinned: Alpine's branch keeps only the latest build of each,
# so an exact pin would break the build at its next security update. The
# Avahi series is checked instead, since the checks read Avahi's wording.
ALPINE=alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
PACKAGES="avahi avahi-tools dbus python3"
AVAHI_SERIES="avahi-daemon 0.9"

SUFFIX=$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')
NET=mdns-interop-$SUFFIX
HOST=mdns-interop-host-$SUFFIX
PEER=mdns-interop-peer-$SUFFIX
ALIAS=mdns-interop-alias-$SUFFIX
ALIAS_IMAGE=mdns-interop-alias:$SUFFIX
AVAHI_IMAGE=mdns-interop-avahi:$SUFFIX

SUBNET4=198.51.100.0/24
SUBNET6=2001:db8:5353::/64
HOST4=198.51.100.10
PEER4=198.51.100.20
HOST6=2001:db8:5353::10
PEER6=2001:db8:5353::20
# What Avahi publishes for the names it claims: an address nobody has.
OTHER4=198.51.100.99
OTHER4B=198.51.100.98
OTHER4C=198.51.100.97
AVAHI_NAME=interop-host

# Removal order: the containers sharing $HOST's network namespace go first.
CONTAINERS="$ALIAS $PEER $HOST"
created_net=
created_images=
ok=

log() { printf 'interop: %s\n' "$*"; }

dump() {
    for c in $CONTAINERS; do
        if docker container inspect "$c" > /dev/null 2>&1; then
            printf '\n----- docker logs %s -----\n' "$c"
            docker logs "$c" 2>&1 | tail -80
        fi
    done
}

cleanup() {
    code=$?
    if [ -z "$ok" ]; then
        log "FAILED (exit $code); container logs follow"
        dump
    fi
    for c in $CONTAINERS; do
        docker rm -f "$c" > /dev/null 2>&1 || true
    done
    if [ -n "$created_net" ]; then
        docker network rm "$NET" > /dev/null 2>&1 || true
    fi
    for i in $created_images; do
        docker image rm -f "$i" > /dev/null 2>&1 || true
    done
    exit "$code"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    log "FAIL: $*"
    exit 1
}

# wait_for SECONDS WHAT COMMAND...: runs COMMAND once a second until it
# succeeds, or fails the test naming WHAT.
wait_for() {
    limit=$1 what=$2
    shift 2
    i=0
    until "$@" > /dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -lt "$limit" ] || fail "timed out after ${limit}s waiting for $what"
        sleep 1
    done
}

# re TEXT: TEXT as an extended regular expression matching itself (dots
# are all an address or name can hold that needs escaping).
re() { printf '%s' "$1" | sed 's/\./\\./g'; }

logs_match() { docker logs "$1" 2>&1 | grep -qE "$2"; }

running() { [ "$(docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" = true ]; }

# resolve CONTAINER -4|-6 NAME: what avahi-resolve in CONTAINER gives for
# NAME, as "<name reported> <address>", or nothing.
resolve() {
    docker exec "$1" timeout 10 avahi-resolve "$2" -n "$3" 2>/dev/null |
        awk 'NF == 2 { print $1, $2; exit }'
}

# resolves_to CONTAINER FAMILY NAME ADDRESS: one try, NAME reported as itself.
resolves_to() { [ "$(resolve "$1" "$2" "$3")" = "$3 $4" ]; }

# expect_resolve CONTAINER FAMILY NAME ADDRESSES: NAME resolves to one of
# ADDRESSES (separated by spaces) from CONTAINER within 20 s, reported as
# itself.
expect_resolve() {
    c=$1 family=$2 name=$3 wants=$4
    i=0
    while :; do
        got=$(resolve "$c" "$family" "$name")
        for want in $wants; do
            if [ "$got" = "$name $want" ]; then
                log "ok: $c: avahi-resolve $family -n $name -> $got"
                return
            fi
        done
        i=$((i + 1))
        [ "$i" -lt 4 ] ||
            fail "avahi-resolve $family -n $name in $c gave '${got:-nothing}', expected $name and one of: $wants"
        sleep 2
    done
}

# legacy CONTAINER NAME: scripts/mdns-query.py, run inside CONTAINER.
legacy() {
    docker exec -i "$1" python3 - "$2" < scripts/mdns-query.py ||
        fail "legacy query for $2 in $1 got no A answer"
    log "ok: $1: legacy query for $2 answered with A"
}

# no_line CONTAINER REGEX WHY: CONTAINER's log has no line matching REGEX.
no_line() {
    if lines=$(docker logs "$1" 2>&1 | grep -E "$2"); then
        printf '%s\n' "$lines"
        fail "$3"
    fi
}

command -v docker > /dev/null || fail "docker not found"

log "building $ALIAS_IMAGE from the Dockerfile"
created_images="$ALIAS_IMAGE"
docker build -q -t "$ALIAS_IMAGE" . > /dev/null

log "building $AVAHI_IMAGE"
created_images="$created_images $AVAHI_IMAGE"
printf 'FROM %s\nRUN apk add --no-cache %s\n' "$ALPINE" "$PACKAGES" |
    docker build -q -t "$AVAHI_IMAGE" - > /dev/null
version=$(docker run --rm "$AVAHI_IMAGE" avahi-daemon --version)
case $version in
"$AVAHI_SERIES"*) log "$version" ;;
*) fail "the Avahi image has '$version'; the checks are written for $AVAHI_SERIES" ;;
esac

# IPv6 where the Docker daemon allows it on a user-defined network (any
# recent one does), IPv4 alone otherwise.
created_net=1
if err=$(docker network create --ipv6 --subnet "$SUBNET4" --subnet "$SUBNET6" "$NET" 2>&1 > /dev/null); then
    v6=1
    log "network $NET: $SUBNET4, $SUBNET6"
else
    log "an IPv6 network was refused: $err"
    v6=
    docker network create --subnet "$SUBNET4" "$NET" > /dev/null ||
        fail "cannot create $NET on $SUBNET4 (another run of this test, or a network overlapping it?)"
    log "network $NET: $SUBNET4 (IPv6 checks skipped)"
fi

# avahi-daemon in the foreground, logging to stderr (docker logs). It needs
# the system bus for avahi-resolve and avahi-publish.
AVAHI_CMD='mkdir -p /run/dbus && dbus-daemon --system && exec avahi-daemon --no-rlimits --no-chroot'

start_avahi() {
    name=$1 hostname=$2 ip4=$3 ip6=$4
    set -- --ip "$ip4"
    [ -z "$v6" ] || set -- "$@" --ip6 "$ip6"
    docker run -d --name "$name" --hostname "$hostname" --network "$NET" "$@" \
        "$AVAHI_IMAGE" sh -c "$AVAHI_CMD" > /dev/null
}

start_avahi "$HOST" "$AVAHI_NAME" "$HOST4" "$HOST6"
start_avahi "$PEER" interop-peer "$PEER4" "$PEER6"
# mdns-alias publishes every address on the interface, the link-local one
# included, and Avahi answers with whichever it likes.
HOST6S=
if [ -n "$v6" ]; then
    ll=$(docker exec "$HOST" ip -6 -o addr show dev eth0 scope link |
        awk '{ sub("/.*", "", $4); print $4; exit }')
    [ -n "$ll" ] || fail "no IPv6 link-local address on the host container's eth0"
    HOST6S="$HOST6 $ll"
fi
wait_for 30 "avahi-daemon to start on the host" logs_match "$HOST" 'Server startup complete'
wait_for 30 "avahi-daemon to start on the peer" logs_match "$PEER" 'Server startup complete'
expect_resolve "$PEER" -4 "$AVAHI_NAME.local" "$HOST4"

# The peer claims clash.local before mdns-alias starts. Nothing looks it up
# yet, so the host's later lookups are not answered from an older one.
docker exec -d "$PEER" sh -c "avahi-publish -a clash.local $OTHER4 > /tmp/clash.log 2>&1"
wait_for 20 "the peer to establish clash.local" docker exec "$PEER" grep -q Established /tmp/clash.log
if docker exec "$PEER" grep -q collision /tmp/clash.log; then
    fail "the peer saw a collision for clash.local"
fi
log "ok: the peer holds clash.local -> $OTHER4"

# mdns-alias as shipped: unprivileged, read-only, no capabilities, in the
# host container's network namespace. No `no-new-privileges`: it sets that
# on itself, and on some Docker hosts the option makes exec fail (see
# docs/design.md, Docker notes).
docker run -d --name "$ALIAS" --network "container:$HOST" --read-only \
    --cap-drop ALL "$ALIAS_IMAGE" app.local web.local clash.local > /dev/null

log "check 2 and 3: sharing port 5353, and a name Avahi already holds"
wait_for 30 "mdns-alias to announce app.local" logs_match "$ALIAS" '^mdns-alias: announced .*app\.local'
logs_match "$ALIAS" '^mdns-alias: announced .*web\.local' || fail "web.local was not announced"
wait_for 30 "mdns-alias to give up clash.local" logs_match "$ALIAS" \
    "^mdns-alias: clash\.local is claimed by $(re "$PEER4") on .*; giving up on it there for now, retrying in 5 min$"
if [ -n "$v6" ]; then
    wait_for 10 "mdns-alias to give up clash.local over IPv6" logs_match "$ALIAS" \
        "^mdns-alias: clash\.local is claimed by $(re "$PEER6") on .*; giving up on it there"
fi
docker logs "$ALIAS" 2>&1 | grep 'clash\.local is claimed by' | sed 's/^/interop: ok: /'
no_line "$ALIAS" '^mdns-alias: announced .*clash\.local' "mdns-alias announced clash.local, which the peer holds"
no_line "$ALIAS" '(app|web)\.local is claimed' "mdns-alias saw a conflict for an alias nobody else claims"
running "$ALIAS" || fail "mdns-alias exited"
log "ok: mdns-alias still running after the conflict"

log "check 1: resolution"
expect_resolve "$PEER" -4 app.local "$HOST4"
expect_resolve "$PEER" -4 web.local "$HOST4"
expect_resolve "$HOST" -4 app.local "$HOST4"
if [ -n "$v6" ]; then
    expect_resolve "$PEER" -6 app.local "$HOST6S"
    expect_resolve "$HOST" -6 web.local "$HOST6S"
fi
# From the namespace mdns-alias shares: through avahi-daemon there, and by
# a legacy query, which skips every cache and collects every answer.
expect_resolve "$HOST" -4 clash.local "$OTHER4"
got=$(docker exec -i "$HOST" python3 - clash.local << 'PY'
import socket, struct, sys, time
q = struct.pack(">6H", 9, 0, 1, 0, 0, 0)
for label in sys.argv[1].split("."):
    q += bytes([len(label)]) + label.encode()
q += b"\0" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
s.sendto(q, ("224.0.0.251", 5353))
found = set()
end = time.time() + 2
while time.time() < end:
    s.settimeout(max(end - time.time(), 0.01))
    try:
        r = s.recv(9000)
    except socket.timeout:
        break
    i = 12
    def skip(i):
        while True:
            n = r[i]
            if n == 0:
                return i + 1
            if n & 0xC0 == 0xC0:
                return i + 2
            i += 1 + n
    qd, an = struct.unpack(">HH", r[4:8])
    for _ in range(qd):
        i = skip(i) + 4
    for _ in range(an):
        i = skip(i)
        t, _, _, n = struct.unpack(">HHIH", r[i:i + 10])
        if t == 1:
            found.add(socket.inet_ntoa(r[i + 10:i + 14]))
        i += 10 + n
print(" ".join(sorted(found)))
PY
)
[ "$got" = "$OTHER4" ] || fail "a legacy query for clash.local got '${got:-nothing}', expected only $OTHER4"
log "ok: legacy query for clash.local: answered with $OTHER4 alone"

log "check 2: Avahi keeps its own name"
expect_resolve "$PEER" -4 "$AVAHI_NAME.local" "$HOST4"
[ -z "$v6" ] || expect_resolve "$PEER" -6 "$AVAHI_NAME.local" "$HOST6"
logs_match "$HOST" "Server startup complete\. Host name is $AVAHI_NAME\.local\." ||
    fail "avahi-daemon on the host did not come up as $AVAHI_NAME.local"
no_line "$HOST" '[Cc]onflict|[Cc]ollision' "avahi-daemon on the host reported a conflict"

# Avahi in the shared namespace still probes and claims a new name with
# mdns-alias bound beside it: the peer resolves it, and no collision.
docker exec -d "$HOST" sh -c "avahi-publish -a hostpub.local $OTHER4C > /tmp/publish.log 2>&1"
expect_resolve "$PEER" -4 hostpub.local "$OTHER4C"
docker exec "$HOST" grep -q 'Established' /tmp/publish.log ||
    fail "avahi-publish on the host did not establish hostpub.local"
if docker exec "$HOST" grep -q 'collision' /tmp/publish.log; then
    fail "avahi-publish on the host saw a collision for hostpub.local"
fi
log "ok: avahi-daemon on the host claimed hostpub.local beside mdns-alias"

# Not asserted, since RFC 6762 section 15.1 leaves it to the kernel: which
# of the two sockets on port 5353 a query sent straight to the host's
# address reaches (docs/design.md, Sharing port 5353). The peer, where
# avahi-daemon is alone on the port, is the baseline.
unicast_query() {
    docker exec -i "$1" python3 - "$2" "$3" << 'PY'
import socket, struct, sys
q = struct.pack(">6H", 7, 0, 1, 0, 0, 0)
for label in sys.argv[1].split("."):
    q += bytes([len(label)]) + label.encode()
q += b"\0" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(q, (sys.argv[2], 5353))
try:
    r = s.recv(9000)
except socket.timeout:
    sys.exit(1)
sys.exit(0 if struct.unpack(">H", r[6:8])[0] else 1)
PY
}
# report_unicast FROM ADDRESS NAME
report_unicast() {
    if unicast_query "$1" "$3" "$2"; then
        log "info: a unicast query to $2:5353 for $3 was answered"
    else
        log "info: a unicast query to $2:5353 for $3 went unanswered"
    fi
}
report_unicast "$HOST" "$PEER4" interop-peer.local
report_unicast "$PEER" "$HOST4" app.local
report_unicast "$PEER" "$HOST4" "$AVAHI_NAME.local"

log "check 4: legacy unicast queries in the shared namespace"
legacy "$HOST" app.local
legacy "$HOST" "$AVAHI_NAME.local"

log "check 3: Avahi probing for a name mdns-alias holds"
# mdns-alias answers the probe, so Avahi reports a collision and withdraws.
# avahi-publish 0.9 prints "Established" first (its loopback copy of the
# name has no rival) and then trips an assertion while picking a new name
# for an address; the collision line is what matters.
out=$(docker exec "$PEER" timeout 15 avahi-publish -a app.local "$OTHER4B" 2>&1 || true)
printf '%s\n' "$out" | sed 's/^/interop:   avahi-publish: /'
printf '%s\n' "$out" | grep -q 'Name collision' ||
    fail "avahi-publish -a app.local did not report a collision with mdns-alias"
no_line "$ALIAS" 'app\.local is claimed' "mdns-alias gave way to a probe for app.local"
running "$ALIAS" || fail "mdns-alias exited"
expect_resolve "$PEER" -4 app.local "$HOST4"

# Every container still up: nothing exited along the way.
for c in $CONTAINERS; do
    running "$c" || fail "$c is not running"
done
# Neither avahi-daemon reported a conflict for its own name.
for c in "$HOST" "$PEER"; do
    no_line "$c" 'Host name conflict' "avahi-daemon in $c reported a host name conflict"
done

log "mdns-alias log:"
docker logs "$ALIAS" 2>&1 | sed 's/^/interop:   /'
ok=1
log "PASS"
