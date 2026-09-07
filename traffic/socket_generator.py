#!/usr/bin/env python3
"""Custom Python-socket benign traffic  (Sec IV.C.1).

Simulates HTTP web browsing, HTTPS, database SQL querying and inter-department
file transfer as short request/response TCP exchanges between the 13 hosts.

Two modes:
  server : `python3 traffic/socket_generator.py server --port 8080`
  client : `python3 traffic/socket_generator.py client --dst 10.0.0.5 --port 3306 --profile sql`

scripts/run_testbed.sh starts one server per service port on the server hosts and
a client loop on every non-server host.
"""
from __future__ import annotations

import argparse
import random
import socket
import time

PROFILES = {           # (request bytes, response bytes, think-time seconds)
    "http": (300, 4_000, (0.5, 3.0)),
    "https": (450, 6_000, (0.5, 3.0)),
    "sql": (200, 1_200, (0.2, 1.5)),
    "file": (150, 200_000, (2.0, 6.0)),
}


def run_server(port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(64)
    while True:
        conn, _ = s.accept()
        try:
            req = conn.recv(4096)
            n = int(req.split(b" ", 1)[0]) if req and req.split(b" ", 1)[0].isdigit() else 2048
            conn.sendall(b"x" * min(n, 1_000_000))
        except Exception:
            pass
        finally:
            conn.close()


def run_client(dst: str, port: int, profile: str, duration_s: int, seed: int) -> None:
    rng = random.Random(seed)
    req_b, resp_b, think = PROFILES[profile]
    end = time.time() + duration_s
    while time.time() < end:
        try:
            c = socket.create_connection((dst, port), timeout=2)
            c.sendall(f"{resp_b} GET /{profile}\r\n".encode())
            got = 0
            while got < resp_b:
                b = c.recv(65536)
                if not b:
                    break
                got += len(b)
            c.close()
        except Exception:
            pass
        time.sleep(rng.uniform(*think))


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("server"); s.add_argument("--port", type=int, required=True)
    c = sub.add_parser("client")
    c.add_argument("--dst", required=True); c.add_argument("--port", type=int, required=True)
    c.add_argument("--profile", choices=list(PROFILES), default="http")
    c.add_argument("--duration", type=int, default=300); c.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()
    if a.mode == "server":
        run_server(a.port)
    else:
        run_client(a.dst, a.port, a.profile, a.duration, a.seed)


if __name__ == "__main__":
    main()
