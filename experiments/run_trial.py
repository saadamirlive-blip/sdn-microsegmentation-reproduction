"""Run ONE Monte Carlo trial of ONE system and print / return its metrics.

Usage:
    python -m experiments.run_trial --system proposed_dynamic_sdn --trial 0
    python -m experiments.run_trial --system static_sdn --trial 3
"""
from __future__ import annotations

import argparse
import json

from experiments.metrics_bundle import compute_trial_metrics
from simulation.baseline_sim import BASELINES, run_baseline_trial
from simulation.system_sim import run_proposed_trial

ALL_SYSTEMS = ["proposed_dynamic_sdn"] + BASELINES


def run_one(system: str, trial: int):
    if system == "proposed_dynamic_sdn":
        rec = run_proposed_trial(trial)
    else:
        rec = run_baseline_trial(system, trial)
    return rec, compute_trial_metrics(rec)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", choices=ALL_SYSTEMS, default="proposed_dynamic_sdn")
    ap.add_argument("--trial", type=int, default=0)
    args = ap.parse_args()

    _, m = run_one(args.system, args.trial)
    print(json.dumps(m.to_row(), indent=2))
    print("CR by vector:", {k: round(v, 2) for k, v in m.cr_by_vector.items()})


if __name__ == "__main__":
    main()
