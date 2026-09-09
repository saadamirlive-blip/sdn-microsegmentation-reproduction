#!/usr/bin/env python
"""One-command experiment runner.

    traffic -> attack -> telemetry -> detection -> risk -> containment -> metrics -> results

Steps:
  1. verify environment (warn-only)
  2. build the 50,000-sample dataset               (Phase 1)          -> results/dataset_50k.csv
  3. train RandomForest + StandardScaler           (Phase 2)          -> results/model/{model,scaler}.pkl
  4. evaluate the offline classifier                                  -> results/classification_report.txt, ...
  5. run N Monte Carlo trials of the proposed system (Phase 3)        -> results/*.csv, results/logs/
  6. generate figures                                                 -> figures/
  7. write experiment metadata                                        -> results/experiment_metadata.json

The Mininet/Ryu data-plane testbed is a separate entry point (scripts/run_testbed.sh).

Usage:
    python run_experiment.py               # full run (10 trials)
    python run_experiment.py --trials 3    # quick run
    python run_experiment.py --skip-train  # reuse the trained model
"""
from __future__ import annotations

import argparse
import time


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trials", type=int, default=None, help="override Monte Carlo trial count")
    ap.add_argument("--skip-train", action="store_true", help="reuse results/model/model.pkl")
    ap.add_argument("--skip-plots", action="store_true")
    args = ap.parse_args()

    t0 = time.time()

    print("\n=== [1/7] verify environment ===")
    from scripts.verify_env import main as verify_env
    verify_env()

    from common import config
    n_trials = args.trials or int(config.experiment()["monte_carlo"]["trials"])

    if args.skip_train:
        print("\n=== [2-3/7] dataset + training SKIPPED (--skip-train) ===")
    else:
        print("\n=== [2/7] build 50,000-sample dataset (Phase 1) ===")
        from ml.dataset_builder import main as build_ds
        build_ds()

        print("\n=== [3/7] train RandomForest + StandardScaler (Phase 2) ===")
        from ml.train_rf import train
        train(save=True)

    print("\n=== [4/7] evaluate offline classifier ===")
    from ml.evaluate_rf import evaluate
    evaluate()

    print(f"\n=== [5/7] {n_trials} Monte Carlo trials of the proposed system (Phase 3) ===")
    from experiments.run_all_trials import run
    run(n_trials, write_logs=True)

    if args.skip_plots:
        print("\n=== [6/7] plots SKIPPED ===")
    else:
        print("\n=== [6/7] generate figures ===")
        from plots.figures import make_all
        make_all()

    print("\n=== [7/7] write experiment metadata ===")
    from experiments.make_metadata import main as make_meta
    make_meta()

    print(f"\nDONE in {time.time() - t0:.1f}s")
    print("  results/  -> CSVs, JSON, model, logs")
    print("  figures/  -> PNG figures")


if __name__ == "__main__":
    main()
