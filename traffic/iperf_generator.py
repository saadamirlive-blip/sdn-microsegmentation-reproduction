#!/usr/bin/env python3
"""Benign iPerf3 background traffic for the Mininet testbed  (Sec IV.C.1).

Starts an iperf3 server on each server host (h2 HR, h3 App, h5 DB, h6 Web) and
launches low-rate client streams from the workstation / department hosts,
shaped toward the paper's benign profile (pps ~ N(0.2,0.05), bps ~ N(0.1,0.02)
in the paper's normalised units -> here rendered as a few hundred Kbps).

Invoked from scripts/run_testbed.sh with a live Mininet ``net`` handle, or
standalone inside the Mininet CLI.
"""
from __future__ import annotations

import random

from common import config

SERVERS = ["h2", "h3", "h5", "h6"]
CLIENTS = ["h1", "h7", "h8", "h9", "h10", "h11", "h12", "h13"]


def start(net, duration_s: int = 300, seed: int = 42) -> None:
    rng = random.Random(seed)
    T = config.topology()["hosts"]
    for s in SERVERS:
        net.get(s).cmd("iperf3 -s -D")                      # daemonised server
    for c in CLIENTS:
        s = rng.choice(SERVERS)
        # modest bitrate, many short streams -> benign statistical profile
        rate_kbps = int(max(50, rng.gauss(300, 80)))
        net.get(c).cmd(
            f"bash -c 'while true; do iperf3 -c {T[s]['ip']} -t 8 -b {rate_kbps}K "
            f"-P 1 --connect-timeout 1000 >/dev/null 2>&1; sleep {rng.randint(1,4)}; done' &")
    print(f"[iperf] servers on {SERVERS}; {len(CLIENTS)} client loops for {duration_s}s")
