"""Turn a real-packet testbed telemetry CSV into the 5 headline metrics.

Input : results/testbed/telemetry_<ts>.csv  (written by controller/ryu_controller.py)
        columns: poll_ts, dpid, flow_id, src_ip, dst_ip, protocol, pps, bps,
                 duration_s, p_attack, risk_score, compromised, action

Output: results/testbed/metrics_summary.json  +  a printed summary

Uses the SAME metric functions as the pure-Python pipeline (`metrics/`). Each
telemetry flow is collapsed into one FlowOutcome:
  * label     : attack if the source is the attacker host (h4), else benign
  * action    : the strongest action the DME applied to it over the run
  * contained : action != MONITOR
  * mitigated : an attack flow that received an enforcing action
  * T_resp    : (first poll with an enforcing action) - (flow first seen)
                + half a polling interval for the in-window detection delay

Usage:
    python -m experiments.metrics_from_testbed                     # newest CSV
    python -m experiments.metrics_from_testbed results/testbed/telemetry_1234.csv
"""
from __future__ import annotations

import csv
import glob
import json
import sys
from collections import defaultdict

from common import config
from common.policy_engine import is_critical_flow, is_lateral_flow
from metrics.containment import containment_rate, containment_rate_by_vector
from metrics.false_containment import false_containment_rate
from metrics.false_positive import false_positive_rate
from metrics.latency import response_latency, response_latency_stats
from metrics.records import FlowOutcome

_POLL = float(config.experiment()["telemetry"]["polling_interval_s"])
_ATTACKER_IP = config.topology()["hosts"][config.experiment()["attack_traffic"]["attacker_host"]]["ip"]
_ACTION_RANK = {"MONITOR": 0, "RATE_LIMIT": 1, "QUARANTINE": 2, "BLOCK": 3}
_DPORT_SCENARIO = {80: "http_flood", 53: "udp_flood", 0: "icmp_flood", 443: "mixed_ddos"}


def _newest_csv() -> str:
    files = sorted(glob.glob(str(config.results_dir() / "testbed" / "telemetry_*.csv")))
    if not files:
        raise SystemExit("no results/testbed/telemetry_*.csv -- run scripts/run_testbed.sh first")
    return files[-1]


def _dport_of(flow_id: str) -> int:
    # flow_id = "dpid:src:dst:sport:dport:proto"
    try:
        return int(flow_id.split(":")[4])
    except Exception:
        return 0


def load_outcomes(path: str):
    rows_by_flow = defaultdict(list)
    t0 = None
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            rows_by_flow[r["flow_id"]].append(r)
            ts = float(r["poll_ts"])
            t0 = ts if t0 is None else min(t0, ts)

    outcomes = []
    for fid, rows in rows_by_flow.items():
        rows.sort(key=lambda r: float(r["poll_ts"]))
        first_seen = float(rows[0]["poll_ts"]) - t0
        last_seen = float(rows[-1]["poll_ts"]) - t0
        src, dst = rows[0]["src_ip"], rows[0]["dst_ip"]
        dport = _dport_of(fid)

        strongest = max(rows, key=lambda r: _ACTION_RANK.get(r["action"], 0))["action"]
        enforce_rows = [r for r in rows if r["action"] != "MONITOR"]
        installed = (float(enforce_rows[0]["poll_ts"]) - t0) if enforce_rows else None
        contained = strongest != "MONITOR"

        is_attack = (src == _ATTACKER_IP)
        label = "attack" if is_attack else "benign"
        scenario = (_DPORT_SCENARIO.get(dport, "syn_flood") if is_attack else "benign")

        resp_lat = None
        if installed is not None:
            resp_lat = max(0.0, installed - first_seen) + _POLL / 2.0
        mitigated = bool(is_attack and contained and installed is not None)

        p_attack = max(float(r["p_attack"]) for r in rows)
        risk = max(float(r["risk_score"]) for r in rows)
        compromised = any(r["compromised"] in ("1", "True", "true") for r in rows)

        outcomes.append(FlowOutcome(
            flow_id=fid, label=label, scenario=scenario, src_host=src, dst_host=dst,
            predicted_malicious=bool(p_attack >= 0.5), p_attack=p_attack,
            risk_score=risk, compromised=compromised,
            action=strongest, contained=contained,
            init_time_s=first_seen, lifetime_s=max(_POLL, last_seen - first_seen),
            rule_installed_time_s=installed, resp_latency_s=resp_lat, mitigated=mitigated,
            is_critical=is_critical_flow(src, dst),
            is_lateral=is_lateral_flow(src, dst, dport),
            collateral=bool(label == "benign" and contained),
        ))
    return outcomes


def summarise(path: str) -> dict:
    outcomes = load_outcomes(path)
    n_attack = sum(1 for o in outcomes if o.label == "attack")
    n_benign = sum(1 for o in outcomes if o.label == "benign")

    fcr = false_containment_rate(outcomes)
    na_proxy = (100.0 - fcr) if fcr == fcr else float("nan")

    out = {
        "source_csv": path,
        "n_flows": len(outcomes),
        "n_attack_flows": n_attack,
        "n_benign_flows": n_benign,
        "containment_rate_pct": containment_rate(outcomes),
        "response_latency_s": response_latency(outcomes),
        "response_latency_stats": response_latency_stats(outcomes),
        "false_positive_rate_pct": false_positive_rate(outcomes),
        "false_containment_rate_pct": fcr,
        "network_availability_pct_proxy": na_proxy,
        "containment_rate_by_vector": containment_rate_by_vector(outcomes),
        "note": "network_availability_pct_proxy = 100 - FCR. Telemetry alone has "
                "no path-liveness data; for a measured NA run an active host-to-host "
                "path prober alongside the testbed and count operational paths / N(N-1).",
    }

    with open(config.results_dir() / "testbed" / "metrics_summary.json", "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    return out


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else _newest_csv()
    s = summarise(path)
    print(f"[metrics_from_testbed] {path}")
    print(f"  flows: {s['n_flows']}  (attack {s['n_attack_flows']} / benign {s['n_benign_flows']})")
    print(f"  Containment Rate      : {s['containment_rate_pct']:.2f} %")
    print(f"  Response Latency      : {s['response_latency_s']:.2f} s")
    print(f"  False Positive Rate   : {s['false_positive_rate_pct']:.2f} %")
    print(f"  False Containment Rate: {s['false_containment_rate_pct']:.2f} %")
    print(f"  Network Availability  : {s['network_availability_pct_proxy']:.2f} %  (proxy)")
    print(f"  -> results/testbed/metrics_summary.json")


if __name__ == "__main__":
    main()
