"""Run the full Monte Carlo experiment (Sec IV.G): 10 independent trials for the
proposed Dynamic SDN system and each of the 3 baselines, then aggregate.

Emits (task Sec 23):
    results/raw_trial_results.csv
    results/aggregate_results.csv
    results/latency_results.csv
    results/containment_by_vector.csv
    results/network_availability.csv          (per-trial NA + mean timeline)
    results/false_containment.csv
    results/logs/flows_<system>_trial<k>.csv  (structured per-flow log, task Sec 27)

Usage:
    python -m experiments.run_all_trials              # all systems, 10 trials
    python -m experiments.run_all_trials --trials 3   # quick smoke run
    python -m experiments.run_all_trials --systems proposed_dynamic_sdn
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
from simulation.baseline_sim import BASELINES, run_baseline_trial
from simulation.system_sim import run_proposed_trial

ALL_SYSTEMS = ["proposed_dynamic_sdn"] + BASELINES
_METRIC_KEYS = ["cr_pct", "tresp_s", "fpr_pct", "fcr_pct", "na_pct"]


def _run_trial(system: str, k: int):
    return run_proposed_trial(k) if system == "proposed_dynamic_sdn" else run_baseline_trial(system, k)


_SYS_SHORT = {"proposed_dynamic_sdn": "prop", "traditional_firewall": "fw",
              "ids_ips": "ids", "static_sdn": "ssdn"}


def _write_flow_log(rec, path):
    try:
        _do_write_flow_log(rec, path)
    except OSError as e:  # e.g. Windows MAX_PATH on a very deep checkout
        print(f"  [run_all_trials] flow log skipped ({path.name}): {e}")


def _do_write_flow_log(rec, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["flow_id", "trial", "system", "label", "scenario", "src_host", "dst_host",
                    "protocol", "predicted_malicious", "p_attack", "risk_score", "compromised",
                    "action", "contained", "init_time_s", "lifetime_s",
                    "rule_installed_time_s", "resp_latency_s", "mitigated",
                    "is_critical", "is_lateral", "collateral"])
        for f in rec.flows:
            w.writerow([f.flow_id, f.trial, f.system, f.label, f.scenario, f.src_host, f.dst_host,
                        getattr(f, "protocol", ""), int(f.predicted_malicious), f"{f.p_attack:.4f}",
                        f"{f.risk_score:.2f}", int(f.compromised), f.action, int(f.contained),
                        f"{f.init_time_s:.3f}", f"{f.lifetime_s:.3f}",
                        "" if f.rule_installed_time_s is None else f"{f.rule_installed_time_s:.3f}",
                        "" if f.resp_latency_s is None else f"{f.resp_latency_s:.4f}",
                        int(f.mitigated), int(f.is_critical), int(f.is_lateral), int(f.collateral)])


def run(systems: List[str], n_trials: int, write_logs: bool = True) -> Dict:
    rdir = config.results_dir()
    logdir = rdir / "logs"
    logdir.mkdir(parents=True, exist_ok=True)

    raw_rows: List[dict] = []
    per_system_metrics: Dict[str, List[TrialMetrics]] = {s: [] for s in systems}
    na_timelines: Dict[str, list] = {}

    for system in systems:
        for k in range(n_trials):
            rec = _run_trial(system, k)
            m = compute_trial_metrics(rec)
            per_system_metrics[system].append(m)
            raw_rows.append(m.to_row())
            if write_logs:
                _write_flow_log(rec, logdir / f"flows_{_SYS_SHORT.get(system, system)}_t{k}.csv")
            if system not in na_timelines:
                na_timelines[system] = [availability_timeline(rec.availability)]
            else:
                na_timelines[system].append(availability_timeline(rec.availability))
            print(f"  [{system:22s}] trial {k}: CR={m.cr_pct:6.2f}  Tresp={m.tresp_s:5.2f}s  "
                  f"FPR={m.fpr_pct:5.3f}  FCR={m.fcr_pct:5.3f}  NA={m.na_pct:6.2f}")

    # --- raw_trial_results.csv ------------------------------------------------
    pd.DataFrame(raw_rows).to_csv(rdir / "raw_trial_results.csv", index=False)

    # --- aggregate_results.csv (mean + std over trials, per system) ---------
    agg_rows = []
    for system, ms in per_system_metrics.items():
        row = {"system": system, "n_trials": len(ms)}
        for key in _METRIC_KEYS + ["moop_utility", "n_rules_total",
                                   "peak_concurrent_rules", "controller_load_final"]:
            vals = [getattr(m, key) for m in ms]
            row[f"{key}_mean"] = statistics.mean(vals)
            row[f"{key}_std"] = statistics.pstdev(vals) if len(vals) > 1 else 0.0
        agg_rows.append(row)
    agg = pd.DataFrame(agg_rows)
    agg.to_csv(rdir / "aggregate_results.csv", index=False)

    # --- latency_results.csv ----------------------------------------------
    lat_rows = []
    for system, ms in per_system_metrics.items():
        for m in ms:
            lat_rows.append({"system": system, "trial": m.trial, "tresp_s": m.tresp_s,
                             "tresp_std_s": m.tresp_std_s, "tresp_n": m.tresp_n,
                             **{f"tresp_{a}": v for a, v in m.tresp_by_action.items()}})
    pd.DataFrame(lat_rows).to_csv(rdir / "latency_results.csv", index=False)

    # --- containment_by_vector.csv --------------------------------------
    cv_rows = []
    for system, ms in per_system_metrics.items():
        vecs = sorted({v for m in ms for v in m.cr_by_vector})
        for v in vecs:
            vals = [m.cr_by_vector[v] for m in ms if v in m.cr_by_vector]
            cv_rows.append({"system": system, "attack_vector": v,
                            "cr_mean": statistics.mean(vals),
                            "cr_std": statistics.pstdev(vals) if len(vals) > 1 else 0.0})
    pd.DataFrame(cv_rows).to_csv(rdir / "containment_by_vector.csv", index=False)

    # --- network_availability.csv (per-trial NA + mean timeline) ----------
    na_rows = []
    for system, ms in per_system_metrics.items():
        for m in ms:
            na_rows.append({"system": system, "trial": m.trial, "na_pct": m.na_pct,
                            "na_min_pct": m.na_min_pct})
    pd.DataFrame(na_rows).to_csv(rdir / "network_availability.csv", index=False)

    # mean NA timeline per system (for Fig 7)
    tl_rows = []
    for system, tls in na_timelines.items():
        ticks = [row["t_s"] for row in tls[0]]
        for i, t in enumerate(ticks):
            vals = [tl[i]["availability_pct"] for tl in tls]
            tl_rows.append({"system": system, "t_s": t,
                            "availability_pct_mean": statistics.mean(vals),
                            "under_attack": tls[0][i]["under_attack"]})
    pd.DataFrame(tl_rows).to_csv(rdir / "availability_timeline.csv", index=False)

    # --- false_containment.csv -------------------------------------------
    fc_rows = []
    for system, ms in per_system_metrics.items():
        for m in ms:
            fc_rows.append({"system": system, "trial": m.trial, "fcr_pct": m.fcr_pct,
                            **{f"fcr_{k}": v for k, v in m.fcr_breakdown.items()}})
    pd.DataFrame(fc_rows).to_csv(rdir / "false_containment.csv", index=False)

    print(f"\n[run_all_trials] wrote raw/aggregate/latency/containment/availability/"
          f"false_containment CSVs to {rdir}")
    return {"aggregate": agg.to_dict(orient="records"),
            "per_system_metrics": {s: [asdict(m) for m in ms]
                                   for s, ms in per_system_metrics.items()}}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=int(config.experiment()["monte_carlo"]["trials"]))
    ap.add_argument("--systems", nargs="+", default=ALL_SYSTEMS, choices=ALL_SYSTEMS)
    ap.add_argument("--no-logs", action="store_true")
    args = ap.parse_args()
    out = run(args.systems, args.trials, write_logs=not args.no_logs)
    with open(config.results_dir() / "run_all_trials_summary.json", "w", encoding="utf-8") as fh:
        json.dump(out["aggregate"], fh, indent=2)


if __name__ == "__main__":
    main()
