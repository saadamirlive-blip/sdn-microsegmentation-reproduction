#!/usr/bin/env python3
"""Horizontal reconnaissance / internal probing from h4  (Sec IV.C.2).

"From the compromised Host (h4) a subnet on the internal subnet is probed,
hitting the HR server (h2) and DB (h5) server."  Sequential TCP connect scan
across 10.0.0.0/24, concentrating on h2 and h5 service ports.  Not in Table VII.
"""
from __future__ import annotations
import argparse, socket, time
from common import config

PRIORITY_TARGETS = ["h2", "h5"]                 # [PAPER]
SCAN_PORTS = [22, 80, 135, 139, 443, 445, 1433, 3306, 3389, 8080]


def run(duration_s: float = 20.0, seed: int = 42) -> None:
    T = config.topology()["hosts"]
    order = ([T[h]["ip"] for h in PRIORITY_TARGETS]
             + [f"10.0.0.{i}" for i in range(1, 14)])
    end = time.time() + duration_s
    while time.time() < end:
        for ip in order:
            for p in SCAN_PORTS:
                try:
                    s = socket.socket(); s.settimeout(0.3)
                    s.connect_ex((ip, p)); s.close()
                except Exception:
                    pass
            if time.time() >= end:
                break


if __name__ == "__main__":
    a = argparse.ArgumentParser(); a.add_argument("--duration", type=float, default=20.0)
    a.add_argument("--seed", type=int, default=42); n = a.parse_args(); run(n.duration, n.seed)
