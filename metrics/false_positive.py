"""False Positive Rate  (FPR %)  -- Sec IV.F.3.

    FPR = percentage of benign traffic flows incorrectly flagged as malicious.

SYSTEM-LEVEL measurement: computed over the continuous runtime benign traffic
of the operational window (Sec VI.B.7 notes this differs from the 0.20% offline
classifier FPR -- both are reported, separately).
"""
from __future__ import annotations

from typing import Iterable

from metrics.records import FlowOutcome


def false_positive_rate(flows: Iterable[FlowOutcome]) -> float:
    benign = [f for f in flows if f.label == "benign"]
    if not benign:
        return float("nan")
    fp = sum(1 for f in benign if f.predicted_malicious)
    return 100.0 * fp / len(benign)
