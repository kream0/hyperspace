#!/usr/bin/env python3
"""UDP relay that drops a percentage of datagrams in both directions.

Usage: lossy_relay.py LISTEN_PORT HOST_PORT LOSS_PERCENT

Point the client at 127.0.0.1:LISTEN_PORT; datagrams are forwarded to the host
on 127.0.0.1:HOST_PORT. Used by scripts/e2e.sh to exercise NACK/keyframe
recovery with the real binaries.
"""
import random
import select
import socket
import sys

listen_port, host_port, loss = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]) / 100.0
rng = random.Random(1234)
front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
front.bind(("127.0.0.1", listen_port))
back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
back.connect(("127.0.0.1", host_port))
for s in (front, back):
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
client = None
seen = dropped = 0
try:
    while True:
        ready, _, _ = select.select([front, back], [], [], 30)
        if not ready:
            break
        for s in ready:
            try:
                if s is front:
                    data, client = front.recvfrom(65536)
                else:
                    data = back.recv(65536)
            except OSError:
                continue
            seen += 1
            # Never drop the handshake: connection setup has its own retry test.
            if data[:1] not in (b"\x01", b"\x02") and rng.random() < loss:
                dropped += 1
                continue
            try:
                if s is front:
                    back.send(data)
                elif client:
                    front.sendto(data, client)
            except OSError:
                pass
except KeyboardInterrupt:
    pass
print(f"relay: {seen} datagrams, {dropped} dropped", file=sys.stderr)
