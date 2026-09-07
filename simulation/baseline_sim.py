"""Comparative baseline defense paradigms  (Sec IV.E, Table IV).

    Traditional Firewall  -- static subnet ACLs, 45.0 s response latency
    IDS / IPS Baseline    -- passive Snort signature match, 30.0 s
    Static SDN Baseline   -- reactive per-5-tuple binary FlowMod drop, 15.0 s

The three baseline RESPONSE LATENCIES (45 / 30 / 15 s) are stated by the paper
as given modelling assumptions -> [PAPER].  Their CR / FPR / FCR / NA are
reproduced here by mechanism models whose knobs live in
``config/experiment.yaml : baseline_models`` -- [ASSUMPTION], ASSUMPTIONS.md #17,
set once from the qualitative descriptions in Sec II / Table I / Table IV and
NOT tuned to the Table VIII numbers.

Each baseline is evaluated on the SAME sampled traffic as the proposed system
(same per-trial seed) so the comparison is apples-to-apples.
"""
from __future__ import annotations

from typing import Dict, List

import joblib
import numpy as np

from common import config
from common.features import extract_vector
from common.seeding import trial_seed
from metrics.records import FlowOutcome, PathAvailabilitySample, TrialRecords
from topology.topology_model import load_topology
from traffic.attack_traffic import (generate_attack_flows,
                                    generate_horizontal_probe_flows)
from traffic.benign_traffic import generate_benign_flows

_EXP = config.experiment()
_POLL = float(_EXP["telemetry"]["polling_interval_s"])
_WINDOW = int(_EXP["operational_window"]["total_seconds"])
_ATTACK_STARTS = list(_EXP["operational_window"]["attack_start_times_s"])
_BURST = float(_EXP["runtime_traffic"]["attack_burst_duration_s"])
_N_BENIGN = int(_EXP["runtime_traffic"]["benign_flows_per_poll"])
_N_ATTACK = int(_EXP["runtime_traffic"]["attack_flows_per_poll"])
_BASE = _EXP["baselines"]
_BMODEL = _EXP["baseline_models"]

BASELINES = ["traditional_firewall", "ids_ips", "static_sdn"]


def _under_attack(t: float) -> bool:
    return any(s <= t < s + _BURST for s in _ATTACK_STARTS)


def _load_clf():
    mdir = config.model_dir()
    return joblib.load(mdir / "model.pkl"), joblib.load(mdir / "scaler.pkl")


def run_baseline_trial(system: str, trial_index: int) -> TrialRecords:
    assert system in BASELINES, system
    bundle = trial_seed(trial_index)
    rng = np.random.default_rng(bundle.master)
    topo = load_topology()
    total_paths = topo.n_directed_paths()

    latency = float(_BASE[system]["response_latency_s"])      # [PAPER]
    model = _BMODEL[system]
    clf, scaler = _load_clf()

    rec = TrialRecords(trial=trial_index, system=system, seed=bundle.master)

    # Containment-rate semantics [ASSUMPTION -- ASSUMPTIONS.md #17]:
    #   Traditional Firewall / IDS-IPS -- CR is governed by DETECTION capability
    #     (does a static ACL / Snort signature ever match this vector?); their
    #     45 s / 30 s slowness is captured by T_resp, not by CR.  So a
    #     signature-detected attack flow counts as mitigated regardless of
    #     whether the block beat the flow's end.
    #   Static SDN -- fast reactive controller: an attack flow counts as
    #     mitigated only if the 5-tuple drop lands before the flow ends
    #     (15 s idle-timeout latency still lets short flows escape).
    timing_gated = system == "static_sdn"
    n_rules_total = 0
    concurrent_per_poll: List[int] = []

    poll_times = [round(k * _POLL, 3) for k in range(int(_WINDOW / _POLL))]
    for t in poll_times:
        atk = _under_attack(t)
        poll_rule_set: set = set()
        flows = generate_benign_flows(rng, topo, _N_BENIGN, t)
        if atk:
            flows += generate_attack_flows(rng, topo, _N_ATTACK, t)
            if bool(_EXP["attack_vectors"]["horizontal_probe"]["enabled"]):
                flows += generate_horizontal_probe_flows(rng, topo, t)

        X = np.vstack([extract_vector(f) for f in flows]) if flows else np.empty((0, 6))
        # Static SDN uses the SAME RF classifier (Wainwright base paper);
        # firewall / IDS use signature/family heuristics instead.
        if system == "static_sdn" and len(X):
            p = clf.predict_proba(scaler.transform(X))[:, 1]
        else:
            p = np.zeros(len(flows))

        down_paths = set()
        uncontained_attack = 0

        for i, f in enumerate(flows):
            label = f.meta["label"]
            scenario = f.meta["scenario"]
            family = f.meta.get("family", "benign")
            init_t = float(f.meta["init_time_s"])
            life = float(f.meta["lifetime_s"])

            detected = False
            action = "MONITOR"

            if system == "static_sdn":
                detected = bool(p[i] >= 0.5)
                if detected:
                    action = "BLOCK"                      # [PAPER] Table IV "Binary Flow Drop"
            elif system in ("traditional_firewall", "ids_ips"):
                if label == "attack" and family in model["detects_families"]:
                    pv = float(model["per_vector_detection_prob"].get(scenario, 0.0))
                    detected = rng.random() < pv
                if detected:
                    action = "BLOCK"                      # coarse IP drop / async IP drop

            contained = action != "MONITOR"

            # collateral: coarse enforcement also blocks a fixed fraction of
            # benign flows (subnet drop / async IP drop / 5-tuple drop of FP).
            collateral = False
            if label == "benign":
                cbf = float(model.get("collateral_block_fraction", 0.0))
                if system == "static_sdn":
                    # only misclassified benign flows are dropped
                    collateral = bool(p[i] >= 0.5) and (rng.random() < 1.0)
                else:
                    collateral = rng.random() < cbf
                if collateral:
                    contained = True
                    action = "BLOCK"

            installed_t = None
            resp_lat = None
            if contained:
                installed_t = init_t + latency + float(abs(rng.normal(0, latency * 0.06)))
                resp_lat = installed_t - init_t

            if contained and system == "static_sdn":
                poll_rule_set.add((f.meta["src_host"], f.meta["dst_host"],
                                   int(f.dst_port), action))

            mitigated = False
            if label == "attack" and contained and installed_t is not None:
                mitigated = (installed_t <= init_t + life) if timing_gated else True

            if label == "attack" and not mitigated:
                uncontained_attack += 1
            if label == "benign" and contained:
                down_paths.add((f.meta["src_host"], f.meta["dst_host"]))

            rec.flows.append(FlowOutcome(
                flow_id=f.flow_id, label=label, scenario=scenario,
                src_host=f.meta["src_host"], dst_host=f.meta["dst_host"],
                predicted_malicious=bool(detected or (label == "benign" and collateral)),
                p_attack=float(p[i]) if len(p) else 0.0,
                risk_score=0.0, compromised=bool(contained and label == "attack"),
                action=action, contained=bool(contained),
                init_time_s=init_t, lifetime_s=life,
                rule_installed_time_s=installed_t, resp_latency_s=resp_lat,
                mitigated=bool(mitigated),
                is_service_call=bool(f.meta.get("is_service_call", False)),
                is_critical=False, is_lateral=False,
                collateral=bool(label == "benign" and contained),
                trial=trial_index, system=system,
            ))

        # availability: persistent loss from collateral blocks + transient loss
        # from the long time the attack runs un-contained (latency >> burst).
        persistent_down = len(down_paths)
        transient_down = 0
        if atk and uncontained_attack > 0:
            s1_paths = sum(1 for (u, v) in topo.directed_host_pairs()
                           if "s1" in topo.path_switches(u, v))
            sat = min(1.0, uncontained_attack / max(1, _N_ATTACK))
            # baselines suppress the burst slower than the proposed system ->
            # deeper transient dip. [ASSUMPTION -- ASSUMPTIONS.md #17]
            tdf = float(model.get("transient_degrade_factor", 0.45))
            transient_down = int(round(tdf * sat * s1_paths))
        operational = max(0, total_paths - persistent_down - transient_down)
        rec.availability.append(PathAvailabilitySample(
            t_s=t, operational_paths=operational, total_paths=total_paths, under_attack=atk))
        n_rules_total += len(poll_rule_set)
        concurrent_per_poll.append(len(poll_rule_set))

    rec.n_rules_total = n_rules_total
    rec.peak_concurrent_rules = max(concurrent_per_poll) if concurrent_per_poll else 0
    rec.mean_concurrent_rules = (sum(concurrent_per_poll) / len(concurrent_per_poll)
                                 if concurrent_per_poll else 0.0)
    return rec
