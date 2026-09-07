"""False Containment Rate  (FCR %)  -- Sec IV.F.4.

    FCR = percentage of legitimate business connections mistakenly
          blocked, quarantined, or rate-limited.

Measured as the fraction of benign flows whose realised containment action is
NOT ``MONITOR`` (i.e. the flow was dropped, moved to VLAN 99, or metered).
This includes host-level collateral: benign flows sharing a host that the DMCA
marked Compromised (Algorithm 1 line 7) and subsequently contained.
"""
from __future__ import annotations

from typing import Iterable

from metrics.records import FlowOutcome


def false_containment_rate(flows: Iterable[FlowOutcome]) -> float:
    benign = [f for f in flows if f.label == "benign"]
    if not benign:
        return float("nan")
    contained = sum(1 for f in benign if f.contained)
    return 100.0 * contained / len(benign)


def false_containment_breakdown(flows: Iterable[FlowOutcome]) -> dict:
    benign = [f for f in flows if f.label == "benign"]
    out = {"BLOCK": 0, "QUARANTINE": 0, "RATE_LIMIT": 0}
    for f in benign:
        if f.contained and f.action in out:
            out[f.action] += 1
    out["total_benign"] = len(benign)
    return out
