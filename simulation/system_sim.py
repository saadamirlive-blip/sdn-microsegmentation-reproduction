"""Proposed Dynamic SDN -- one system-level Monte Carlo trial.

Closed-loop 300 s window, telemetry polled every 3.0 s (Sec IV.A / Fig 5).
Two attack bursts initiated at t = 60 s and t = 120 s (Sec VI.B.2 / Fig 6).

Everything reported (CR, T_resp, FPR, FCR, NA) is MEASURED from per-flow /
per-path records -- no paper result is used as an input.
"""
from __future__ import annotations

import math
from typing import Callable, Dict, List

import joblib
import numpy as np

from common import config
from common.features import RawFlowStats, extract_matrix
from common.openflow_rules import ACTION_NAME, Action
from common.policy_engine import run_dmca
from common.risk_engine import RiskSignals, derive_signals_from_flow
from common.seeding import trial_seed
from metrics.records import FlowOutcome, PathAvailabilitySample, TrialRecords
from topology.topology_model import TopologyModel, load_topology
from traffic.attack_traffic import (generate_attack_flows,
                                    generate_horizontal_probe_flows)
from traffic.benign_traffic import generate_benign_flows

_EXP = config.experiment()
_POLL = float(_EXP["telemetry"]["polling_interval_s"])                     # [PAPER] 3.0
_WINDOW = int(_EXP["operational_window"]["total_seconds"])                 # [PAPER] 300
_ATTACK_STARTS = list(_EXP["operational_window"]["attack_start_times_s"])  # [PAPER] [60, 120]
_BURST = float(_EXP["runtime_traffic"]["attack_burst_duration_s"])        # [ASSUMPTION] 60
_N_BENIGN = int(_EXP["runtime_traffic"]["benign_flows_per_poll"])         # [ASSUMPTION]
_N_ATTACK = int(_EXP["runtime_traffic"]["attack_flows_per_poll"])        # [ASSUMPTION]
_LAT = _EXP["runtime_traffic"]["latency_model"]
_PROBE_ENABLED = bool(_EXP["attack_vectors"]["horizontal_probe"]["enabled"])
# weight of a rate-limited legitimate connection toward "unavailable"
# (0.0 = paper-faithful config set; > 0 only in the calibrated overlay)
_RL_IMPAIR = float(_EXP.get("availability", {}).get("rate_limit_impairment_weight", 0.0))
_TRANSIENT_FACTOR = float(_EXP.get("availability", {}).get("transient_degrade_factor", 0.35))
# Algorithm 1 marks the HOST x_i=2 and enforcement follows the host. When this
# is on, a benign flow on a Compromised host is quarantined too (host-level
# collateral) -> FCR can exceed FPR as in Table VIII. 0/off in the paper set.
_HOST_COLLATERAL = bool(_EXP.get("risk_engine", {}).get("host_collateral_on_compromise", False))


def _load_predict_proba() -> Callable[[np.ndarray], np.ndarray]:
    mdir = config.model_dir()
    clf = joblib.load(mdir / "model.pkl")
    scaler = joblib.load(mdir / "scaler.pkl")

    def predict_proba(X_raw: np.ndarray) -> np.ndarray:
        Xs = scaler.transform(X_raw)
        return clf.predict_proba(Xs)[:, 1]

    return predict_proba


def _under_attack(t: float) -> bool:
    return any(s <= t < s + _BURST for s in _ATTACK_STARTS)


def _pipeline_latency(rng: np.random.Generator, action: Action) -> float:
    """Post-detection pipeline latency (Sec IV.E), EXCLUDING the polling wait
    (the polling wait = t_poll - flow_init is added by the caller from real
    per-flow timestamps, so it is measured, not sampled twice):

        extraction   ~ N(0.30, 0.08)      [ASSUMPTION] feature calc + RF inference ("< 2.3 s" Sec V.A.3)
      + install(kind) ~ N(mu_kind, s_kind) [ASSUMPTION] OpenFlow FlowMod/MeterMod write (incl. 10-50 ms TCAM)
    """
    ext = max(0.0, float(rng.normal(_LAT["extraction_time_s"]["mean"],
                                    _LAT["extraction_time_s"]["std"])))
    kind = ACTION_NAME[action]
    ins_cfg = _LAT["install_time_s"][kind]
    ins = max(0.0, float(rng.normal(ins_cfg["mean"], ins_cfg["std"])))
    return ext + ins


def _signal_lookup_factory(rng: np.random.Generator):
    def lookup(f: RawFlowStats) -> RiskSignals:
        pps = f.pps if f.pps >= 0 else f.packet_count / max(f.duration_s, 1e-9)
        return derive_signals_from_flow(
            pps=pps,
            distinct_dst=int(f.meta.get("distinct_dst", 1)),
            failed_auth=int(f.meta.get("failed_auth", 0)),
        )
    return lookup


def run_proposed_trial(trial_index: int, *, verbose: bool = False) -> TrialRecords:
    bundle = trial_seed(trial_index)
    rng = np.random.default_rng(bundle.master)
    topo: TopologyModel = load_topology()
    predict_proba = _load_predict_proba()
    signal_lookup = _signal_lookup_factory(rng)

    total_paths = topo.n_directed_paths()          # 156
    rec = TrialRecords(trial=trial_index, system="proposed_dynamic_sdn", seed=bundle.master)

    compromised_hosts: set = set()
    rules_per_switch: Dict[str, int] = {}
    n_rules_total = 0
    concurrent_per_poll: List[int] = []

    poll_times = [round(k * _POLL, 3) for k in range(int(_WINDOW / _POLL))]
    for t in poll_times:
        atk = _under_attack(t)

        flows: List[RawFlowStats] = generate_benign_flows(rng, topo, _N_BENIGN, t)
        if atk:
            flows += generate_attack_flows(rng, topo, _N_ATTACK, t)
            if _PROBE_ENABLED:
                flows += generate_horizontal_probe_flows(rng, topo, t)

        res = run_dmca(flows, predict_proba, signal_lookup=signal_lookup)

        # tally controller load (Eq 9 uses N_rules(t) = rules ACTIVE this poll).
        # The DME installs ONE OpenFlow entry per distinct (src, dst, dst_port,
        # action) -- re-observed 5-tuples reuse the existing entry -- so count
        # DISTINCT rules, not raw flow observations.
        enforcing = [d for d in res.decisions if d.action != Action.MONITOR]
        distinct_rules = {(d.src_host, d.dst_host, d.rule.match.dst_port, int(d.action))
                          for d in enforcing}
        n_rules_total += len(distinct_rules)
        concurrent_per_poll.append(len(distinct_rules))
        for d in enforcing:
            sw = d.rule.target_switch or topo.edge_switch_of(d.src_host)
            rules_per_switch[sw] = rules_per_switch.get(sw, 0) + 1

        # persistent host compromise (Algorithm 1 line 7)
        for d in res.decisions:
            if d.compromised:
                compromised_hosts.add(d.src_host)

        down_paths = set()
        impaired_paths: set = set()
        uncontained_attack_this_poll = 0

        for f, d in zip(flows, res.decisions):
            action_name = ACTION_NAME[d.action]
            contained = d.action != Action.MONITOR

            # host-level collateral: a benign flow sharing a Compromised host is
            # swept up by the host quarantine even though the flow itself looked
            # clean (Algorithm 1 marks the host, not the flow). Calibrated set only.
            if (_HOST_COLLATERAL and not contained and f.meta["label"] == "benign"
                    and d.compromised):
                contained = True
                action_name = "QUARANTINE"

            init_t = float(f.meta["init_time_s"])
            life = float(f.meta["lifetime_s"])
            if contained:
                # measured polling wait: detection happens at this poll t;
                # flow started at init_t (<= t).  Then pipeline + install.
                installed_t = t + _pipeline_latency(rng, d.action)
                resp_lat = installed_t - init_t
            else:
                installed_t = None
                resp_lat = None

            mitigated = False
            if f.meta["label"] == "attack" and contained and installed_t is not None:
                # rule must land before the attack flow finishes
                if installed_t <= init_t + life:
                    mitigated = action_name in ("BLOCK", "QUARANTINE", "RATE_LIMIT")

            if f.meta["label"] == "attack" and not mitigated:
                uncontained_attack_this_poll += 1

            collateral = (f.meta["label"] == "benign" and contained)
            if collateral and action_name in ("BLOCK", "QUARANTINE"):
                down_paths.add((d.src_host, d.dst_host))
            elif collateral and action_name == "RATE_LIMIT" and _RL_IMPAIR > 0:
                # a legitimate business connection throttled to 100 Kbps is not
                # "fully functional" -- weight it toward unavailability.
                # [ASSUMPTION/CALIBRATION] weight is 0.0 in the paper config set.
                impaired_paths.add((d.src_host, d.dst_host))

            rec.flows.append(FlowOutcome(
                flow_id=f.flow_id, label=f.meta["label"], scenario=f.meta["scenario"],
                src_host=d.src_host, dst_host=d.dst_host,
                predicted_malicious=bool(d.p_attack >= 0.5), p_attack=float(d.p_attack),
                risk_score=float(d.risk_score), compromised=bool(d.compromised),
                action=action_name, contained=bool(contained),
                init_time_s=init_t, lifetime_s=life,
                rule_installed_time_s=installed_t, resp_latency_s=resp_lat,
                mitigated=bool(mitigated),
                is_service_call=bool(f.meta.get("is_service_call", False)),
                is_critical=bool(d.is_critical), is_lateral=bool(d.is_lateral),
                collateral=bool(collateral), trial=trial_index, system="proposed_dynamic_sdn",
            ))

        # --- availability sample for this tick (Eq 8 / Fig 7) -----------------
        # persistent loss: legit paths quarantined/blocked this poll (+ weighted
        # rate-limited paths when _RL_IMPAIR > 0, calibrated set only)
        persistent_down = len(down_paths) + _RL_IMPAIR * len(impaired_paths)
        # transient loss: un-contained attack burst saturates the attacker's
        # edge switch (s1); a fraction of the 156 paths transiting s1 degrade
        # for this single 3 s tick, then recover (Sec VI.B.3 "transient dips").
        transient_down = 0
        if atk and uncontained_attack_this_poll > 0:
            s1_paths = sum(1 for (u, v) in topo.directed_host_pairs()
                           if "s1" in topo.path_switches(u, v))
            sat = min(1.0, uncontained_attack_this_poll / max(1, _N_ATTACK))
            transient_down = int(round(_TRANSIENT_FACTOR * sat * s1_paths))  # [ASSUMPTION]

        operational = max(0.0, total_paths - persistent_down - transient_down)
        rec.availability.append(PathAvailabilitySample(
            t_s=t, operational_paths=operational, total_paths=total_paths, under_attack=atk,
        ))

    rec.n_rules_total = n_rules_total
    rec.peak_concurrent_rules = max(concurrent_per_poll) if concurrent_per_poll else 0
    rec.mean_concurrent_rules = (sum(concurrent_per_poll) / len(concurrent_per_poll)
                                 if concurrent_per_poll else 0.0)
    rec.rules_per_switch = rules_per_switch
    if verbose:
        from metrics.containment import containment_rate
        from metrics.latency import response_latency
        from metrics.false_positive import false_positive_rate
        from metrics.false_containment import false_containment_rate
        from metrics.availability import network_availability
        print(f"  trial {trial_index}: CR={containment_rate(rec.flows):.2f} "
              f"Tresp={response_latency(rec.flows):.3f} "
              f"FPR={false_positive_rate(rec.flows):.3f} "
              f"FCR={false_containment_rate(rec.flows):.3f} "
              f"NA={network_availability(rec.availability):.3f}")
    return rec
