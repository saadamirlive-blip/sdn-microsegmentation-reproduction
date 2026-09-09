"""Host Threat Risk Score  R_i(t)   (Eq 4, Sec III.D Phase 3, Sec V.A.3).

    R_i(t) = [ w_rf * P_attack(h_i)
             + w1 * delta_{i,1}(t)      (traffic volume spike)
             + w2 * delta_{i,2}(t)      (port scanning score)
             + w3 * delta_{i,3}(t) ]    (authentication failure score)
             * 100                       -> R_i(t) in [0, 100]

If  R_i(t) >= risk  the host transitions to state x_i(t) = 2 (Compromised)
(Algorithm 1 line 6-7).

Values the paper DOES specify:
  * the functional form above (Eq 4);
  * R_i(t) in [0, 100];
  * the four contributing signals and their names;
  * the compromise rule  R_i(t) >= risk.

Values the paper does NOT specify  -> , isolated in
``config/experiment.yaml``:
  * the weights  w_rf, w1, w2, w3            (MODELING_NOTES.md #9)
  * the threshold  ``risk``                  (MODELING_NOTES.md #9)
  * how the three delta_{i,*} telemetry signals are computed from raw stats
    (MODELING_NOTES.md #6)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from common import config

# --- weights & threshold : , read from config ---------------------
_RISK_CFG = config.experiment().get("risk_engine", {})

# Defaults live here (and are echoed into MODELING_NOTES.md); config can override.
W_RF = float(_RISK_CFG.get("w_rf", 0.70))     # RF prediction weight (dominant)
W1 = float(_RISK_CFG.get("w1", 0.15))         # traffic volume spike weight
W2 = float(_RISK_CFG.get("w2", 0.10))         # port-scan weight
W3 = float(_RISK_CFG.get("w3", 0.05))         # auth-failure weight
RISK_THRESHOLD = float(_RISK_CFG.get("risk_threshold", 60.0))            # x_i = 2 (Compromised)
RISK_SUSPECTED_THRESHOLD = float(_RISK_CFG.get("risk_suspected_threshold", 35.0))  # x_i = 1 (Suspected)


def host_state(risk_score: float) -> int:
    """Eq 2 : discrete host security state x_i(t) in {0, 1, 2}."""
    if risk_score >= RISK_THRESHOLD:
        return 2
    if risk_score >= RISK_SUSPECTED_THRESHOLD:
        return 1
    return 0

assert abs((W_RF + W1 + W2 + W3) - 1.0) < 1e-9, "Eq 4 weights must sum to 1 (assumed convex combination)"


@dataclass
class RiskSignals:
    """The three non-ML telemetry signals feeding Eq 4, each in [0, 1].

    on how each is derived from raw telemetry:

      delta1  volume spike : min(1, pps / attack_pps_mean)      -- a flow whose
              packet rate approaches the attack regime scores ~1.
      delta2  port-scan    : min(1, distinct_dst_contacted / scan_cap)  -- the
              horizontal probe touching many hosts/ports scores ~1.
      delta3  auth-failure : min(1, failed_auth_events / auth_cap)      -- only
              non-zero for probe/brute traffic toward the HR (h2) / DB (h5)
              service hosts.
    """
    volume_spike: float = 0.0        # delta_{i,1}
    port_scan: float = 0.0           # delta_{i,2}
    auth_failure: float = 0.0        # delta_{i,3}

    def clipped(self) -> "RiskSignals":
        c = lambda v: 0.0 if v < 0 else (1.0 if v > 1 else float(v))
        return RiskSignals(c(self.volume_spike), c(self.port_scan), c(self.auth_failure))


def host_risk_score(p_attack: float, signals: RiskSignals) -> float:
    """Evaluate Eq 4.  Returns R_i(t) in [0, 100]."""
    s = signals.clipped()
    p = 0.0 if p_attack < 0 else (1.0 if p_attack > 1 else float(p_attack))
    r = (W_RF * p + W1 * s.volume_spike + W2 * s.port_scan + W3 * s.auth_failure) * 100.0
    return max(0.0, min(100.0, r))


def is_compromised(risk_score: float, threshold: float | None = None) -> bool:
    """Algorithm 1 line 6 :  R_i(t) >= risk  ->  x_i(t) = 2."""
    thr = RISK_THRESHOLD if threshold is None else float(threshold)
    return risk_score >= thr


def derive_signals_from_flow(*, pps: float, distinct_dst: int, failed_auth: int) -> RiskSignals:
    """Reference derivation of the three signals (used by the simulation).

    Caps are (MODELING_NOTES.md #6):
      attack_pps_mean from config; scan_cap = 8 distinct destinations;
      auth_cap = 5 failed events.
    """
    exp = config.experiment()
    attack_pps_mean = float(exp["attack_traffic"]["pps_mean"])   # 3.0
    scan_cap = float(_RISK_CFG.get("scan_cap", 8.0))             # 
    auth_cap = float(_RISK_CFG.get("auth_cap", 5.0))             # 
    return RiskSignals(
        volume_spike=min(1.0, max(0.0, pps / attack_pps_mean)),
        port_scan=min(1.0, distinct_dst / scan_cap),
        auth_failure=min(1.0, failed_auth / auth_cap),
    ).clipped()


PARAMS: Dict[str, float] = {
    "w_rf": W_RF, "w1": W1, "w2": W2, "w3": W3,
    "risk_threshold": RISK_THRESHOLD,
    "risk_suspected_threshold": RISK_SUSPECTED_THRESHOLD,
}
