#!/usr/bin/env python
"""One-command experiment manager  (task Sec 28).

Runs the entire pure-Python reproduction pipeline end to end:

  1. verify environment
  2. build the 50,000-sample dataset (Phase 1)
  3. train the Random Forest + StandardScaler (Phase 2)  -> model.pkl / scaler.pkl
  4. evaluate the OFFLINE classifier (Table V / VI)
  5. run 10 Monte Carlo trials x {proposed + 3 baselines} (Phase 3, Sec IV.G)
  6. aggregate -> results/*.csv
  7. build results/reproduction_comparison.csv  (measured vs paper)
  8. generate every figure -> figures/
  9. write results/experiment_metadata.json

The Mininet/Ryu testbed is NOT launched here (Linux-only); see testbed/ and
scripts/run_testbed.sh.

Usage:
    python run_experiment.py                 # full run (10 trials)
    python run_experiment.py --trials 3      # quick run
    python run_experiment.py --skip-train    # reuse existing model.pkl
"""
from __future__ import annotations

import argparse
import os
import time


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trials", type=int, default=None, help="override Monte Carlo trial count")
    ap.add_argument("--skip-train", action="store_true", help="reuse the trained model")
    ap.add_argument("--skip-plots", action="store_true")
    ap.add_argument("--systems", nargs="+", default=None)
    ap.add_argument("--config-set", choices=["paper", "calibrated"], default="paper",
                    help="'paper' = faithful reproduction (default); "
                         "'calibrated' = fitted model, writes to results_calibrated/ (see CALIBRATION.md)")
    args = ap.parse_args()

    # must be set BEFORE common.config is imported anywhere
    os.environ["SDN_CONFIG_SET"] = args.config_set

    t0 = time.time()
    if args.config_set != "paper":
        print(f"\n*** CONFIG SET = {args.config_set!r} -- this is a CALIBRATED fit, "
              f"NOT the scientific reproduction. Output -> results_{args.config_set}/ ***")

    # 1 -----------------------------------------------------------------
    print("\n=== [1/9] verify environment ===")
    from scripts.verify_env import main as verify_env
    verify_env()

    from common import config
    n_trials = args.trials or int(config.experiment()["monte_carlo"]["trials"])

    # 2 + 3 -----------------------------------------------------------
    if args.skip_train:
        print("\n=== [2-3/9] dataset + training SKIPPED (--skip-train) ===")
    else:
        print("\n=== [2/9] build 50,000-sample dataset (Phase 1) ===")
        from ml.dataset_builder import main as build_ds
        build_ds()

        print("\n=== [3/9] train Random Forest + StandardScaler (Phase 2) ===")
        from ml.train_rf import train
        train(save=True)

    # 4 -------------------------------------------------------------
    print("\n=== [4/9] evaluate OFFLINE classifier (Table V / VI) ===")
    from ml.evaluate_rf import evaluate
    evaluate()

    # 5 + 6 -----------------------------------------------------
    print(f"\n=== [5-6/9] {n_trials} Monte Carlo trials x systems (Phase 3) ===")
    from experiments.run_all_trials import ALL_SYSTEMS, run
    systems = args.systems or ALL_SYSTEMS
    run(systems, n_trials, write_logs=True)

    # 7 -------------------------------------------------------
    print("\n=== [7/9] reproduction comparison vs paper ===")
    from experiments.compare_baselines import main as compare
    compare()

    # 8 ---------------------------------------------------
    if args.skip_plots:
        print("\n=== [8/9] plots SKIPPED ===")
    else:
        print("\n=== [8/9] generate figures ===")
        from plots.figures import make_all
        make_all()

    # 9 -----------------------------------------------
    print("\n=== [9/9] write experiment metadata ===")
    from experiments.make_metadata import main as make_meta
    make_meta()

    print(f"\nDONE in {time.time() - t0:.1f}s")
    print("  results/   -> CSVs, JSON, model, logs, reproduction_comparison.csv")
    print("  figures/   -> PNG figures")


if __name__ == "__main__":
    main()
