"""Compute the 5 paper metrics + diagnostics for one TrialRecords object."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict

from common import constraints
from metrics.availability import (availability_timeline, min_availability,
                                  network_availability)
from metrics.containment import containment_rate, containment_rate_by_vector
from metrics.false_containment import (false_containment_breakdown,
                                       false_containment_rate)
from metrics.false_positive import false_positive_rate
from metrics.latency import (response_latency, response_latency_by_action,
                             response_latency_stats)
from metrics.records import TrialRecords


@dataclass
class TrialMetrics:
    trial: int
    system: str
    seed: int
    # --- the five paper metrics (Sec IV.F) ---
    cr_pct: float
    tresp_s: float
    fpr_pct: float
    fcr_pct: float
    na_pct: float
    # --- diagnostics ---
    tresp_std_s: float
    tresp_n: int
    na_min_pct: float
    n_flow_obs: int
    n_attack_obs: int
    n_benign_obs: int
    n_rules_total: int
    peak_concurrent_rules: int
    controller_load_final: float
    moop_utility: float
    cr_by_vector: Dict[str, float] = field(default_factory=dict)
    tresp_by_action: Dict[str, float] = field(default_factory=dict)
    fcr_breakdown: Dict[str, int] = field(default_factory=dict)

    def to_row(self) -> dict:
        d = asdict(self)
        d.pop("cr_by_vector"); d.pop("tresp_by_action"); d.pop("fcr_breakdown")
        return d


def compute_trial_metrics(rec: TrialRecords) -> TrialMetrics:
    flows = rec.flows
    cr = containment_rate(flows)
    lat_stats = response_latency_stats(flows)
    fpr = false_positive_rate(flows)
    fcr = false_containment_rate(flows)
    na = network_availability(rec.availability)

    n_attack = sum(1 for f in flows if f.label == "attack")
    n_benign = sum(1 for f in flows if f.label == "benign")
    # Eq 9 : L_ctrl(t) uses N_rules(t) = rules ACTIVE in a poll, so use the peak
    # concurrent count over the window, not the cumulative install total.
    n_rules_t = rec.peak_concurrent_rules
    load = constraints.controller_load(n_rules_t)
    moop = constraints.moop_utility(cr, fcr, na, n_rules_t).utility()

    return TrialMetrics(
        trial=rec.trial, system=rec.system, seed=rec.seed,
        cr_pct=cr, tresp_s=lat_stats["mean"], fpr_pct=fpr, fcr_pct=fcr, na_pct=na,
        tresp_std_s=lat_stats["std"], tresp_n=lat_stats["n"],
        na_min_pct=min_availability(rec.availability),
        n_flow_obs=len(flows), n_attack_obs=n_attack, n_benign_obs=n_benign,
        n_rules_total=rec.n_rules_total, peak_concurrent_rules=rec.peak_concurrent_rules,
        controller_load_final=load, moop_utility=moop,
        cr_by_vector=containment_rate_by_vector(flows),
        tresp_by_action=response_latency_by_action(flows),
        fcr_breakdown=false_containment_breakdown(flows),
    )
