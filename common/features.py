"""6-D flow feature vector  phi_k(t)   (Eq 3, Sec III.D Phase 1, Sec V.A.2).

    phi_k(t) = [ pps_k, bps_k, duration_k, tcp_ratio_k, udp_ratio_k, icmp_ratio_k ]

Sec V.A.2: "The telemetry parsing engine computes instantaneous flow arrival
rates" from the raw OpenFlow multipart statistics (packet_count, byte_count,
duration, per-protocol packet counts).  This module turns one raw flow-stats
record into that ordered 6-vector, identically for the simulation and the
Ryu testbed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence

import numpy as np

from common import config

FEATURE_ORDER: List[str] = list(config.ml()["features"]["order"])
assert FEATURE_ORDER == ["pps", "bps", "duration", "tcp_ratio", "udp_ratio", "icmp_ratio"]


@dataclass
class RawFlowStats:
    """One flow's raw OpenFlow multipart counters at a 3.0 s poll (Sec V.A.1).

    ``pps`` / ``bps`` are already in the paper's normalised unit family when
    they come from the synthetic generators; from the real testbed they are
    computed as packet_count/duration and byte_count/duration.
    """
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str                       # "tcp" | "udp" | "icmp"
    packet_count: float
    byte_count: float
    duration_s: float
    # protocol packet split observed for this (aggregate) flow over the window
    tcp_packets: float = 0.0
    udp_packets: float = 0.0
    icmp_packets: float = 0.0
    # pre-computed normalised rates (synthetic path); if <=0 they are derived
    pps: float = -1.0
    bps: float = -1.0
    meta: Dict = field(default_factory=dict)   # scenario label, host, etc. (never a feature)


def _ratios(tcp: float, udp: float, icmp: float) -> Sequence[float]:
    total = tcp + udp + icmp
    if total <= 0:
        return (0.0, 0.0, 0.0)
    return (tcp / total, udp / total, icmp / total)


def extract_vector(stats: RawFlowStats, polling_interval_s: float | None = None) -> np.ndarray:
    """Return the ordered 6-D float feature vector for one flow."""
    if polling_interval_s is None:
        polling_interval_s = float(config.experiment()["telemetry"]["polling_interval_s"])  # 3.0

    dur = max(float(stats.duration_s), 1e-9)

    pps = stats.pps if stats.pps >= 0 else stats.packet_count / dur
    bps = stats.bps if stats.bps >= 0 else stats.byte_count / dur

    tcp_r, udp_r, icmp_r = _ratios(stats.tcp_packets, stats.udp_packets, stats.icmp_packets)
    # fall back to the declared protocol if no split was recorded
    if (stats.tcp_packets + stats.udp_packets + stats.icmp_packets) <= 0:
        tcp_r = 1.0 if stats.protocol == "tcp" else 0.0
        udp_r = 1.0 if stats.protocol == "udp" else 0.0
        icmp_r = 1.0 if stats.protocol == "icmp" else 0.0

    return np.array([pps, bps, float(stats.duration_s), tcp_r, udp_r, icmp_r], dtype=float)


def extract_matrix(records: Sequence[RawFlowStats]) -> np.ndarray:
    """Stack ``extract_vector`` over many flows -> (N, 6) array."""
    if not records:
        return np.empty((0, len(FEATURE_ORDER)), dtype=float)
    return np.vstack([extract_vector(r) for r in records])
