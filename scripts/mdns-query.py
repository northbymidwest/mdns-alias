#!/usr/bin/env python3
"""Asks for NAME's A records over mDNS from an ephemeral port, a legacy
unicast query (RFC 6762 section 6.7), and exits 0 if the reply's answers
include an A record.

    scripts/mdns-query.py NAME
"""
import socket
import struct
import sys

A = 1
if len(sys.argv) != 2 or not sys.argv[1]:
    print("usage: mdns-query.py NAME", file=sys.stderr)
    sys.exit(2)
name = sys.argv[1]

query = struct.pack(">HHHHHH", 0x1234, 0, 1, 0, 0, 0)
for label in name.rstrip(".").split("."):
    query += bytes([len(label)]) + label.encode()
query += b"\x00" + struct.pack(">HH", 1, 1)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
sock.settimeout(3)
sock.sendto(query, ("224.0.0.251", 5353))
try:
    reply, _ = sock.recvfrom(9000)
except socket.timeout:
    print("no reply within 3 s")
    sys.exit(1)


def skip_name(b, i):
    while True:
        n = b[i]
        if n == 0:
            return i + 1
        if n & 0xC0 == 0xC0:
            return i + 2
        i += 1 + n


try:
    ident, _, questions, answers = struct.unpack(">HHHH", reply[:8])
    i = 12
    for _ in range(questions):
        i = skip_name(reply, i) + 4
    types = []
    for _ in range(answers):
        i = skip_name(reply, i)
        rtype, _, _, length = struct.unpack(">HHIH", reply[i : i + 10])
        types.append(rtype)
        i += 10 + length
except (IndexError, struct.error):
    print("truncated or malformed reply (%d bytes)" % len(reply))
    sys.exit(1)
ok = ident == 0x1234 and A in types
print("answer types %s, expected %d" % (types, A))
sys.exit(0 if ok else 1)
