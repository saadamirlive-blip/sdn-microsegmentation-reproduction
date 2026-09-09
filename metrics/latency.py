"""Containment Response Latency  (T_resp, seconds)  -- Sec IV.F.2.

    T_resp = total elapsed time from attack-flow initiation to OpenFlow rule
             installation on the OVS switches, averaged over mitigated attack flows.

This is MEASURED from per-flow timestamps recorded by the simulation
(``FlowOutcome.resp_latency_s``).  Response latency is measured per flow, never assumed.
"""
from __future__ import annotations

from statistics import mean, pstdev
from typing import Dict, Iterable, List

from metrics.records import FlowOutcome


def _latencies(flows: Iterable[FlowOutcome]) -> List[float]:
    return [f.resp_latency_s for f in flows
            if f.label == "attack" and f.mitigated and f.resp_latency_s is not None]


def response_latency(flows: Iterable[FlowOutcome]) -> float:
    xs = _latencies(list(flows))
    return mean(xs) if xs else float("nan")


def response_latency_stats(flows: Iterable[FlowOutcome]) -> Dict[str, float]:
    xs = _latencies(list(flows))
    if not xs:
        return {"mean": float("nan"), "std": float("nan"), "n": 0,
                "min": float("nan"), "max": float("nan")}
    return {"mean": mean(xs), "std": pstdev(xs) if len(xs) > 1 else 0.0,
            "n": len(xs), "min": min(xs), "max": max(xs)}


def response_latency_by_action(flows: Iterable[FlowOutcome]) -> Dict[str, float]:
    buckets: Dict[str, list] = {}
    for f in flows:
        if f.label == "attack" and f.mitigated and f.resp_latency_s is not None:
            buckets.setdefault(f.action, []).append(f.resp_latency_s)
    return {a: mean(v) for a, v in buckets.items() if v}
