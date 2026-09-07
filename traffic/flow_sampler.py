"""Shared 6-D flow-feature sampler.

Single source of the per-class / per-vector feature distributions so that
  * the OFFLINE dataset  (ml/dataset_builder.py)  and
  * the ONLINE simulation traffic  (traffic/benign_traffic.py, attack_traffic.py)
draw flows from an IDENTICAL distribution -- the Random Forest therefore always
sees in-distribution data at runtime.

[PAPER]  pps/bps N(mu,sigma) per class (Sec IV.C).
[ASSUMPTION -- ASSUMPTIONS.md #6] everything else (duration, protocol ratios,
benign burst mixture, low-rate stealth fraction, jitter) -- all read from
``config/ml_config.yaml : synthetic_features`` and FROZEN there.
"""
from __future__ import annotations

from typing import Dict

import numpy as np

from common import config

_SF = config.ml()["synthetic_features"]
LOW_RATE = {"slowloris", "http_flood"}
VECTORS = ["syn_flood", "udp_flood", "icmp_flood", "mixed_ddos", "slowloris", "http_flood"]
FEATURES = ["pps", "bps", "duration", "tcp_ratio", "udp_ratio", "icmp_ratio"]


def _tn(rng, mean, std, size, lo):
    return np.clip(rng.normal(mean, std, size=size), lo, None)


def _ratios(rng, conc: Dict[str, float], size: int) -> np.ndarray:
    a = np.array([conc["tcp"], conc["udp"], conc["icmp"]], dtype=float)
    return rng.dirichlet(a, size=size)


def _jitter(rng, arr):
    j = float(_SF.get("feature_jitter_std", 0.0))
    return arr if j <= 0 else arr * (1.0 + rng.normal(0.0, j, size=len(arr)))


def sample_benign(rng: np.random.Generator, n: int,
                  bursty_fraction: float | None = None) -> Dict[str, np.ndarray]:
    """2-component benign mixture: steady browsing + bursty iPerf3 file transfer.

    ``bursty_fraction`` defaults to the training-set value
    (config: synthetic_features.benign_mixture.bursty_fraction).  The online
    simulation passes a higher runtime value (Sec VI.B.7).
    """
    mix = _SF["benign_mixture"]
    bf = float(mix["bursty_fraction"]) if bursty_fraction is None else float(bursty_fraction)
    n_burst = int(round(n * bf))
    n_steady = n - n_burst
    n_heavy = int(round(n_burst * float(mix.get("heavy_spike_fraction", 0.0))))
    n_soft = n_burst - n_heavy

    d = _SF["duration"]["benign"]
    hp = mix.get("heavy_spike_pps", mix["bursty_pps"])
    hb = mix.get("heavy_spike_bps", mix["bursty_bps"])
    pps = np.concatenate([
        _tn(rng, _SF["pps"]["benign"]["mean"], _SF["pps"]["benign"]["std"], n_steady, 1e-4),
        _tn(rng, mix["bursty_pps"]["mean"], mix["bursty_pps"]["std"], n_soft, mix["bursty_pps"]["min"]),
        _tn(rng, hp["mean"], hp["std"], n_heavy, hp["min"]),
    ])
    bps = np.concatenate([
        _tn(rng, _SF["bps"]["benign"]["mean"], _SF["bps"]["benign"]["std"], n_steady, 1e-4),
        _tn(rng, mix["bursty_bps"]["mean"], mix["bursty_bps"]["std"], n_soft, mix["bursty_bps"]["min"]),
        _tn(rng, hb["mean"], hb["std"], n_heavy, hb["min"]),
    ])
    dur = np.concatenate([
        _tn(rng, d["mean"], d["std"], n_steady, d["min"]),
        _tn(rng, mix["bursty_duration"]["mean"], mix["bursty_duration"]["std"], n_soft, mix["bursty_duration"]["min"]),
        _tn(rng, mix["bursty_duration"]["mean"], mix["bursty_duration"]["std"], n_heavy, mix["bursty_duration"]["min"]),
    ])
    r = _ratios(rng, _SF["protocol_mix"]["benign"], n)
    idx = rng.permutation(n)
    return {
        "pps": np.clip(_jitter(rng, pps), 1e-4, None)[idx],
        "bps": np.clip(_jitter(rng, bps), 1e-4, None)[idx],
        "duration": np.clip(_jitter(rng, dur), 1e-3, None)[idx],
        "tcp_ratio": r[:, 0], "udp_ratio": r[:, 1], "icmp_ratio": r[:, 2],
    }


def sample_attack(rng: np.random.Generator, vector: str, n: int) -> Dict[str, np.ndarray]:
    pm, bm = _SF["pps"]["attack"], _SF["bps"]["attack"]
    pmean, pstd, bmean, bstd = pm["mean"], pm["std"], bm["mean"], bm["std"]
    if vector in LOW_RATE:
        pmean *= _SF["low_rate_pps_scale"]; pstd *= _SF["low_rate_pps_scale"]
        bmean *= _SF["low_rate_bps_scale"]; bstd *= _SF["low_rate_bps_scale"]
    pps = _tn(rng, pmean, pstd, n, 1e-4)
    bps = _tn(rng, bmean, bstd, n, 1e-4)
    dv = _SF["duration"]["attack_by_vector"][vector]
    dur = _tn(rng, dv["mean"], dv["std"], n, dv["min"])

    if vector in LOW_RATE:                       # stealthy sub-fraction ~ benign HTTP (Sec VI.B.4)
        sf = float(_SF.get("low_rate_stealth_fraction", 0.0))
        k = int(round(n * sf))
        if k > 0:
            bmix = _SF["benign_mixture"]
            pps[:k] = _tn(rng, _SF["pps"]["benign"]["mean"], _SF["pps"]["benign"]["std"], k, 1e-4)
            bps[:k] = _tn(rng, _SF["bps"]["benign"]["mean"], _SF["bps"]["benign"]["std"], k, 1e-4)
            dur[:k] = _tn(rng, bmix["bursty_duration"]["mean"], bmix["bursty_duration"]["std"], k, 0.05)

    r = _ratios(rng, _SF["protocol_mix"][vector], n)
    idx = rng.permutation(n)
    return {
        "pps": np.clip(_jitter(rng, pps), 1e-4, None)[idx],
        "bps": np.clip(_jitter(rng, bps), 1e-4, None)[idx],
        "duration": np.clip(_jitter(rng, dur), 1e-3, None)[idx],
        "tcp_ratio": r[:, 0], "udp_ratio": r[:, 1], "icmp_ratio": r[:, 2],
    }
