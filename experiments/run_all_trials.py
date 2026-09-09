"""Run the Monte Carlo experiment: N independent trials of the proposed
Dynamic SDN microsegmentation system, then aggregate.

Emits:
    results/raw_trial_results.csv
    results/aggregate_results.csv           (mean + std over trials)
    results/latency_results.csv
    results/containment_by_vector.csv
    results/network_availability.csv        (per-trial NA)
    results/availability_timeline.csv       (mean NA vs time)
    results/false_containment.csv
    results/logs/flows_t<k>.csv             (per-flow structured log)

Usage:
    python -m experiments.run_all_trials              # 10 trials
    python -m experiments.run_all_trials --trials 3   # quick run
"""
from __future__ import annotations

import argparse
import csv
import json
import statistics
from dataclasses import asdict
from typing import Dict, List

import pandas as pd

from common import config
from experiments.metrics_bundle import TrialMetrics, compute_trial_metrics
from metrics.availability import availability_timeline
from simulation.system_sim import run_proposed_trial

SYSTEM = "proposed_dynamic_sdn"
_METRIC_KEYS = ["cr_pct", "tresp_s", "fpr_pct", "fcr_pct", "na_pct"]


def _write_flow_log(rec, path):
    try:
        _do_write_flow_log(rec, path)
    except OSError as e:  # e.g. Windows MAX_PATH on a very deep checkout
        print(f"  [run_all_trials] flow log skipped ({path.name}): {e}")


def _do_write_flow_log(rec, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["flow_id", "trial", "label", "scenario", "src_host", "dst_host",
                    "protocol", "predicted_malicious", "p_attack", "risk_score", "compromised",
                    "action", "contained", "init_time_s", "lifetime_s",
                    "rule_installed_time_s", "resp_latency_s", "mitigated",
                    "is_critical", "is_lateral", "collateral"])
        for f in rec.flows:
            w.writerow([f.flow_id, f.trial, f.label, f.scenario, f.src_host, f.dst_host,
                        getattr(f, "protocol", ""), int(f.predicted_malicious), f"{f.p_attack:.4f}",
                        f"{f.risk_score:.2f}", int(f.compromised), f.action, int(f.contained),
                        f"{f.init_time_s:.3f}", f"{f.lifetime_s:.3f}",
                        "" if f.rule_installed_time_s is None else f"{f.rule_installed_time_s:.3f}",
                        "" if f.resp_latency_s is None else f"{f.resp_latency_s:.4f}",
                        int(f.mitigated), int(f.is_critical), int(f.is_lateral), int(f.collateral)])


def run(n_trials: int, write_logs: bool = True) -> Dict:
    rdir = config.results_dir()
    logdir = rdir / "logs"
    logdir.mkdir(parents=True, exist_ok=True)

    raw_rows: List[dict] = []
    metrics: List[TrialMetrics] = []
    na_timelines: list = []

    for k in range(n_trials):
        rec = run_proposed_trial(k)
        m = compute_trial_metrics(rec)
        metrics.append(m)
        raw_rows.append(m.to_row())
        if write_logs:
            _write_flow_log(rec, logdir / f"flows_t{k}.csv")
        na_timelines.append(availability_timeline(rec.availability))
        print(f"  trial {k}: CR={m.cr_pct:6.2f}  Tresp={m.tresp_s:5.2f}s  "
              f"FPR={m.fpr_pct:5.3f}  FCR={m.fcr_pct:5.3f}  NA={m.na_pct:6.2f}")

    # --- raw_trial_results.csv --------------------------------------------
    pd.DataFrame(raw_rows).to_csv(rdir / "raw_trial_results.csv", index=False)

    # --- aggregate_results.csv (mean + std over trials) -----------------
    agg_row = {"system": SYSTEM, "n_trials": len(metrics)}
    for key in _METRIC_KEYS + ["moop_utility", "n_rules_total",
                               "peak_concurrent_rules", "controller_load_final"]:
        vals = [getattr(m, key) for m in metrics]
        agg_row[f"{key}_mean"] = statistics.mean(vals)
        agg_row[f"{key}_std"] = statistics.pstdev(vals) if len(vals) > 1 else 0.0
    agg = pd.DataFrame([agg_row])
    agg.to_csv(rdir / "aggregate_results.csv", index=False)

    # --- latency_results.csv --------------------------------------------
    lat_rows = [{"trial": m.trial, "tresp_s": m.tresp_s, "tresp_std_s": m.tresp_std_s,
                 "tresp_n": m.tresp_n, **{f"tresp_{a}": v for a, v in m.tresp_by_action.items()}}
                for m in metrics]
    pd.DataFrame(lat_rows).to_csv(rdir / "latency_results.csv", index=False)

    # --- containment_by_vector.csv ------------------------------------
    vecs = sorted({v for m in metrics for v in m.cr_by_vector})
    cv_rows = [{"attack_vector": v,
                "cr_mean": statistics.mean([m.cr_by_vector[v] for m in metrics if v in m.cr_by_vector]),
                "cr_std": statistics.pstdev([m.cr_by_vector[v] for m in metrics if v in m.cr_by_vector])
                if len(metrics) > 1 else 0.0}
               for v in vecs]
    pd.DataFrame(cv_rows).to_csv(rdir / "containment_by_vector.csv", index=False)

    # --- network_availability.csv --------------------------------------
    pd.DataFrame([{"trial": m.trial, "na_pct": m.na_pct, "na_min_pct": m.na_min_pct}
                  for m in metrics]).to_csv(rdir / "network_availability.csv", index=False)

    # mean NA timeline
    ticks = [row["t_s"] for row in na_timelines[0]]
    tl_rows = [{"t_s": t,
                "availability_pct_mean": statistics.mean([tl[i]["availability_pct"] for tl in na_timelines]),
                "under_attack": na_timelines[0][i]["under_attack"]}
               for i, t in enumerate(ticks)]
    pd.DataFrame(tl_rows).to_csv(rdir / "availability_timeline.csv", index=False)

    # --- false_containment.csv ---------------------------------------
    pd.DataFrame([{"trial": m.trial, "fcr_pct": m.fcr_pct,
                   **{f"fcr_{k}": v for k, v in m.fcr_breakdown.items()}}
                  for m in metrics]).to_csv(rdir / "false_containment.csv", index=False)

    # --- headline summary -------------------------------------------
    summary = {k: {"mean": agg_row[f"{k}_mean"], "std": agg_row[f"{k}_std"]} for k in _METRIC_KEYS}
    with open(rdir / "run_summary.json", "w", encoding="utf-8") as fh:
        json.dump({"system": SYSTEM, "n_trials": len(metrics), "metrics": summary}, fh, indent=2)

    print(f"\n[run_all_trials] wrote result CSVs to {rdir}")
    print("  headline (mean over trials): "
          f"CR={summary['cr_pct']['mean']:.2f}%  Tresp={summary['tresp_s']['mean']:.2f}s  "
          f"FPR={summary['fpr_pct']['mean']:.2f}%  FCR={summary['fcr_pct']['mean']:.2f}%  "
          f"NA={summary['na_pct']['mean']:.2f}%")
    return {"aggregate": agg.to_dict(orient="records"),
            "trial_metrics": [asdict(m) for m in metrics], "summary": summary}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=int(config.experiment()["monte_carlo"]["trials"]))
    ap.add_argument("--no-logs", action="store_true")
    args = ap.parse_args()
    run(args.trials, write_logs=not args.no_logs)


if __name__ == "__main__":
    main()
