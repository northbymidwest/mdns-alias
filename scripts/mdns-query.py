#!/usr/bin/env python3
"""Asks for NAME over mDNS from an ephemeral port, a legacy unicast query
(RFC 6762 section 6.7), and exits 0 if the reply holds a CNAME answer.

    scripts/mdns-query.py NAME
"""
import socket
import struct
import sys

name = sys.argv[1]
query = struct.pack(">HHHHHH", 0x1234, 0, 1, 0, 0, 0)
for label in name.rstrip(".").split("."):
    query += bytes([len(label)]) + label.encode()
query += b"\x00" + struct.pack(">HH", 1, 1)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
sock.settimeout(3)
sock.sendto(query, ("224.0.0.251", 5353))
reply, _ = sock.recvfrom(9000)
ident, _, _, answers = struct.unpack(">HHHH", reply[:8])
# A legacy reply echoes the ID and carries the CNAME (type 5, class IN).
ok = ident == 0x1234 and answers >= 1 and b"\x00\x05\x00\x01" in reply
print("CNAME answer received" if ok else "no CNAME in reply")
sys.exit(0 if ok else 1)
