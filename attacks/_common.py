"""Shared helpers for the testbed attack scripts (Scapy 2.5.0 preferred)."""
from __future__ import annotations

import random
import shutil
import subprocess
import time

try:
    from scapy.all import IP, ICMP, TCP, UDP, RandShort, Raw, send  # type: ignore
    HAVE_SCAPY = True
except Exception:  # pragma: no cover
    HAVE_SCAPY = False

ATTACK_PPS_MEAN, ATTACK_PPS_STD = 3.0, 0.5     # [PAPER] Sec IV.C.2 (normalised)
ATTACK_BPS_MEAN, ATTACK_BPS_STD = 1.5, 0.3     # [PAPER]

# scale the paper's normalised rate to a testbed packet rate
PPS_SCALE = 4000.0     # [ASSUMPTION] renders "pps~N(3.0,0.5)" as a few thousand pps


def target_pps(rng: random.Random) -> float:
    return max(1.0, rng.gauss(ATTACK_PPS_MEAN, ATTACK_PPS_STD)) * PPS_SCALE


def hping3(args: list[str]) -> bool:
    if not shutil.which("hping3"):
        return False
    subprocess.Popen(["hping3", *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


def scapy_train(pkt_factory, pps: float, duration_s: float, seed: int = 42) -> int:
    """Send a packet train at ~pps for duration_s. Returns packets sent."""
    rng = random.Random(seed)
    interval = 1.0 / max(pps, 1.0)
    end = time.time() + duration_s
    n = 0
    while time.time() < end:
        send(pkt_factory(rng), verbose=0)
        n += 1
        time.sleep(interval)
    return n
