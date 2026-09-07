"""Threat Containment Rate  (CR %)   -- Sec IV.F.1.

    CR = (successfully mitigated attack flows / total generated attack flows) * 100

"Successfully mitigated" (measured, not assumed):
  the DMCA installed a non-MONITOR rule for the flow AND that rule was installed
  before the attack flow's lifetime elapsed AND the rule is enforcing
  (BLOCK / QUARANTINE, or a RATE_LIMIT meter that throttles the flow).
"""
from __future__ import annotations

from typing import Dict, Iterable

from metrics.records import FlowOutcome


def containment_rate(flows: Iterable[FlowOutcome]) -> float:
    atk = [f for f in flows if f.label == "attack"]
    if not atk:
        return float("nan")
    mitigated = sum(1 for f in atk if f.mitigated)
    return 100.0 * mitigated / len(atk)


def containment_rate_by_vector(flows: Iterable[FlowOutcome]) -> Dict[str, float]:
    buckets: Dict[str, list] = {}
    for f in flows:
        if f.label != "attack":
            continue
        buckets.setdefault(f.scenario, []).append(f)
    return {
        vec: (100.0 * sum(1 for f in fs if f.mitigated) / len(fs)) if fs else float("nan")
        for vec, fs in buckets.items()
    }
