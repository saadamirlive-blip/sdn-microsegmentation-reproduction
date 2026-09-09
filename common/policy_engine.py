"""Dynamic Microsegmentation Engine  -- Algorithm 1 (DMCA), Sec III.G / IV.

Algorithm 1 (verbatim structure):

    1  R_OF <- {}
    2  for each active flow f_k in F(t):
    3      phi_k        <- ExtractFeatureVector(f_k)
    4      P_attack     <- PredictRandomForest(phi_k)
    5      R_i(t)       <- host risk score via Eq 4          <-- HOST-level (Eq 4)
    6      if R_i(t) >= risk:
    7          x_i(t) <- 2                      (mark host compromised)
    8          if f_k in F_critical:  r_k <- CreateMeterRule(f_k, Rate = 100K)
   10          elif f_k in F_lateral: r_k <- CreateVLANRule(f_k, VLAN = 99)
   12          else:                  r_k <- CreateDropRule(f_k, Priority = 200)
   15      else:                      r_k <- CreateMonitorRule(f_k)
   18      R_OF <- R_OF u {r_k}
   19-22  for each switch s_m in S: PushOpenFlowFlowMod(s_m, R_OF)
   23  return R_OF, X(t+1)

Key modelling decision :
  Eq 4 defines a *host* risk score R_i(t) ("host endpoint h_i is tracked using a
  discrete security state variable x_i(t)").  Line 5 is therefore evaluated
  ONCE PER SOURCE HOST per poll, aggregating that host's active flows:
      P_attack(h_i) = mean_k P_attack(f_k)  over the host's flows this poll
      delta_{i,1}   = max_k (pps_k / attack_pps_mean)      (volume spike)
      delta_{i,2}   = distinct destinations contacted / scan_cap
      delta_{i,3}   = failed-auth events / auth_cap
  A flow is contained only if its SOURCE HOST is Compromised; the per-flow
  action within that host still follows the critical / lateral / severity split.

Reconciliation of Algorithm 1's "else -> drop" with the graded severity tiers
(Sec V.A.4) is controlled by ``policy_mode`` -- see MODELING_NOTES.md #11.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence

import numpy as np

from common import config, openflow_rules as ofr
from common.features import RawFlowStats, extract_vector
from common.openflow_rules import Action, FlowMatch, OpenFlowRule
from common.risk_engine import (RiskSignals, host_risk_score, host_state,
                                is_compromised)

_TOPO = config.topology()
_EXP = config.experiment()
_CRITICAL_HOSTS = set(_TOPO["critical_hosts"])
_HOST_IP = {name: h["ip"] for name, h in _TOPO["hosts"].items()}
_IP_HOST = {ip: name for name, ip in _HOST_IP.items()}
_SERVER_IPS = {h["ip"] for h in _TOPO["hosts"].values() if h.get("server")}
_CRITICAL_IPS = {_HOST_IP[h] for h in _CRITICAL_HOSTS}
_POLICY_MODE = _EXP.get("policy", {}).get("mode", "hybrid")
_ATTACK_PPS_MEAN = float(_EXP["attack_traffic"]["pps_mean"])
_RISK_CFG = _EXP.get("risk_engine", {})
_SCAN_CAP = float(_RISK_CFG.get("scan_cap", 8.0))
_AUTH_CAP = float(_RISK_CFG.get("auth_cap", 5.0))
_SERVICE_PORTS = {80, 443, 3306, 5432, 1433, 8080, 53}


@dataclass
class FlowDecision:
    flow_id: str
    src_host: str
    dst_host: str
    protocol: str
    p_attack: float                 # per-flow RF probability
    severity: float                 # S_k := per-flow P_attack  
    risk_score: float               # HOST R_i(t)  (Eq 4)
    compromised: bool               # HOST x_i(t) == 2
    is_critical: bool
    is_lateral: bool
    action: Action
    rule: OpenFlowRule
    label_true: Optional[str] = None
    scenario: Optional[str] = None


@dataclass
class DMCAResult:
    decisions: List[FlowDecision] = field(default_factory=list)
    rules: List[OpenFlowRule] = field(default_factory=list)
    compromised_hosts: set = field(default_factory=set)
    host_risk: Dict[str, float] = field(default_factory=dict)
    n_rules_by_action: Dict[str, int] = field(default_factory=dict)


def _host_of(ip: str) -> str:
    return _IP_HOST.get(ip, ip)


def is_critical_flow(src_ip: str, dst_ip: str) -> bool:
    """f_k in F_critical (Algorithm 1 line 8) -- either endpoint is a critical service host."""
    return (src_ip in _CRITICAL_IPS) or (dst_ip in _CRITICAL_IPS)


def is_lateral_flow(src_ip: str, dst_ip: str, dst_port: int) -> bool:
    """f_k in F_lateral (Algorithm 1 line 10) -- east-west, non-service, source not a server."""
    both_internal = (src_ip in _IP_HOST) and (dst_ip in _IP_HOST)
    src_is_server = src_ip in _SERVER_IPS
    non_service = int(dst_port) not in _SERVICE_PORTS
    return both_internal and (not src_is_server) and non_service


def _match(s: RawFlowStats) -> FlowMatch:
    return FlowMatch(s.src_ip, s.dst_ip, int(s.src_port), int(s.dst_port), s.protocol)


def _host_signals(flows: Sequence[RawFlowStats], feats: np.ndarray) -> RiskSignals:
    """Aggregate delta_{i,1..3} for one source host over its flows this poll."""
    pps_vals = feats[:, 0]
    volume_spike = float(np.max(pps_vals) / _ATTACK_PPS_MEAN) if len(pps_vals) else 0.0
    distinct_dst = max((int(f.meta.get("distinct_dst", 1)) for f in flows), default=1)
    failed_auth = sum(int(f.meta.get("failed_auth", 0)) for f in flows)
    return RiskSignals(
        volume_spike=min(1.0, volume_spike),
        port_scan=min(1.0, distinct_dst / _SCAN_CAP),
        auth_failure=min(1.0, failed_auth / _AUTH_CAP),
    ).clipped()


def run_dmca(
    flows: Sequence[RawFlowStats],
    predict_proba: Callable[[np.ndarray], np.ndarray],
    *,
    risk_threshold: float | None = None,
    policy_mode: str | None = None,
    signal_lookup: Optional[Callable[[RawFlowStats], RiskSignals]] = None,  # kept for API compat
) -> DMCAResult:
    mode = policy_mode or _POLICY_MODE
    result = DMCAResult()
    if not flows:
        return result

    X = np.vstack([extract_vector(f) for f in flows])
    p_flow = np.asarray(predict_proba(X), dtype=float).reshape(-1)

    # --- group by source host, evaluate Eq 4 ONCE per host ------------------
    by_host: Dict[str, List[int]] = defaultdict(list)
    for idx, f in enumerate(flows):
        by_host[_host_of(f.src_ip)].append(idx)

    host_state_map: Dict[str, int] = {}
    for host, idxs in by_host.items():
        pv = p_flow[idxs]
        # P_attack(h_i): blend of mean and max over the host's flows this poll
        # 
        p_host = float(0.5 * np.mean(pv) + 0.5 * np.max(pv))
        sig = _host_signals([flows[i] for i in idxs], X[idxs])
        r_i = host_risk_score(p_host, sig)                    # Eq 4
        result.host_risk[host] = r_i
        st = host_state(r_i)                                  # Eq 2 : {0,1,2}
        host_state_map[host] = st
        if st == 2:
            result.compromised_hosts.add(host)

    # --- per-flow action ---------------------------------------------------
    meter_id_seq = 1
    for idx, f in enumerate(flows):
        host = _host_of(f.src_ip)
        p = float(p_flow[idx])
        severity = p                                          # S_k := P_attack(f_k)
        st = host_state_map[host]
        comp = st == 2
        crit = is_critical_flow(f.src_ip, f.dst_ip)
        lat = is_lateral_flow(f.src_ip, f.dst_ip, f.dst_port)
        m = _match(f)

        if st == 0:
            rule = ofr.create_monitor_rule(m, flow_id=f.flow_id)      # line 15
        elif st == 1:
            # Suspected: precautionary rate-limit of RF-flagged flows only
            if p >= 0.5:
                rule = ofr.create_meter_rule(m, meter_id=meter_id_seq, flow_id=f.flow_id)
                meter_id_seq += 1
            else:
                rule = ofr.create_monitor_rule(m, flow_id=f.flow_id)
        else:  # st == 2 : Compromised -> full DMCA enforcement
            if mode == "severity_tiers":
                rule = ofr.severity_tier_rule(m, severity, meter_id=meter_id_seq, flow_id=f.flow_id)
            elif mode == "algorithm1":
                if crit:
                    rule = ofr.create_meter_rule(m, meter_id=meter_id_seq, flow_id=f.flow_id)
                elif lat:
                    rule = ofr.create_vlan_rule(m, flow_id=f.flow_id)
                else:
                    rule = ofr.create_drop_rule(m, flow_id=f.flow_id)
            else:  # hybrid (default)
                if crit:
                    rule = ofr.create_meter_rule(m, meter_id=meter_id_seq, flow_id=f.flow_id)
                elif lat:
                    rule = ofr.create_vlan_rule(m, flow_id=f.flow_id)
                else:
                    rule = ofr.severity_tier_rule(m, severity, meter_id=meter_id_seq, flow_id=f.flow_id)
            if rule.action == Action.RATE_LIMIT:
                meter_id_seq += 1

        rule.target_switch = f.meta.get("switch")
        dec = FlowDecision(
            flow_id=f.flow_id, src_host=host, dst_host=_host_of(f.dst_ip),
            protocol=f.protocol, p_attack=p, severity=severity,
            risk_score=result.host_risk[host], compromised=comp,
            is_critical=crit, is_lateral=lat, action=rule.action, rule=rule,
            label_true=f.meta.get("label"), scenario=f.meta.get("scenario"),
        )
        result.decisions.append(dec)
        result.rules.append(rule)

    for d in result.decisions:
        k = ofr.ACTION_NAME[d.action]
        result.n_rules_by_action[k] = result.n_rules_by_action.get(k, 0) + 1
    return result


POLICY_CONSTANTS = {
    "policy_mode_default": _POLICY_MODE,
    "critical_hosts": sorted(_CRITICAL_HOSTS),
    "service_ports": sorted(_SERVICE_PORTS),
    "risk_score_scope": "per source host per poll (Eq 4 is a host score)",
    "severity_definition": "S_k := P_attack(f_k)  ",
}
