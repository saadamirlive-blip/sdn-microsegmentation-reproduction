"""Run ONE Monte Carlo trial of the proposed system and print its metrics.

Usage:
    python -m experiments.run_trial --trial 0
"""
from __future__ import annotations

import argparse
import json

from experiments.metrics_bundle import compute_trial_metrics
from simulation.system_sim import run_proposed_trial


def run_one(trial: int):
    rec = run_proposed_trial(trial)
    return rec, compute_trial_metrics(rec)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trial", type=int, default=0)
    args = ap.parse_args()

    _, m = run_one(args.trial)
    print(json.dumps(m.to_row(), indent=2))
    print("CR by vector:", {k: round(v, 2) for k, v in m.cr_by_vector.items()})


if __name__ == "__main__":
    main()
