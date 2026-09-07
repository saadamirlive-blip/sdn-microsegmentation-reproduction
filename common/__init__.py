"""Shared, host-agnostic logic for the SDN dynamic-microsegmentation reproduction.

Everything in this package is imported by BOTH:
  * the pure-Python reference simulation  (``simulation/``, runs on any OS), and
  * the real Mininet/Ryu testbed          (``topology/``, ``controller/``, Ubuntu only).

Keeping the risk model (Eq 4), the DMCA policy logic (Algorithm 1), the severity
tiers (Sec V.A.4) and the OpenFlow rule structures in one place guarantees the
simulation and the testbed apply *identical* decision logic -- only the data
plane differs.
"""

__all__ = [
    "config",
    "seeding",
    "features",
    "risk_engine",
    "policy_engine",
    "openflow_rules",
    "constraints",
]
