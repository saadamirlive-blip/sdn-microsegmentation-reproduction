"""Feature extraction on the testbed -- re-exports the shared implementation.

Sec V.A.2: raw OpenFlow multipart stats -> phi_k = [pps, bps, duration,
tcp_ratio, udp_ratio, icmp_ratio].  Identical code as the simulation.
"""
from common.features import (FEATURE_ORDER, RawFlowStats, extract_matrix,
                             extract_vector)

__all__ = ["FEATURE_ORDER", "RawFlowStats", "extract_vector", "extract_matrix"]
