"""OpenFlow 1.3 rule structures produced by the Dynamic Microsegmentation Engine.

These dataclasses are protocol-neutral descriptions of the FlowMod / MeterMod
messages the Ryu controller serialises (Sec V.A.5).  The pure-Python simulation
consumes them directly to decide a flow's fate; ``controller/openflow_rules.py``
turns the same structures into real ``parser.OFPFlowMod`` / ``parser.OFPMeterMod``
messages on the testbed.

Enforcement tiers and their fixed parameters come straight from the paper:

  Algorithm 1 (DMCA)                        Sec III.D / Sec V.A.4 (severity tiers)
  --------------------------------------    -------------------------------------
  line  9  CreateMeterRule(Rate = 100K)     RATE_LIMIT : meter band 100 Kbps
  line 11  CreateVLANRule(VLAN = 99)         QUARANTINE : reassign to VLAN 99
  line 13  CreateDropRule(Priority = 200)    BLOCK      : hard drop, priority 200
  line 16  CreateMonitorRule(...)            MONITOR    : log only, forward flow
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from common import config

_EXP = config.experiment()
_METER_RATE_KBPS = 100          # Algorithm 1 line 9 "Rate = 100K" / Sec III.D "100 Kbps"
_QUARANTINE_VLAN = int(config.topology()["quarantine_vlan"])   # 99
_DROP_PRIORITY = 200           # Algorithm 1 line 13 / Sec V.A.4 "Priority 200"
_MONITOR_PRIORITY = 10         # low priority, below any enforcement rule. MODELING_NOTES.md #15
_METER_PRIORITY = 150         # between monitor and drop
_QUARANTINE_PRIORITY = 175    # 


class Action(enum.IntEnum):
    """Discrete containment action C_k(t)  (Constraint 5: C_k in {0,1,2,3})."""
    MONITOR = 0          # allow + log
    RATE_LIMIT = 1       # OFPMT_METER band, 100 Kbps
    QUARANTINE = 2       # VLAN 99
    BLOCK = 3            # hard drop, priority 200


ACTION_NAME = {
    Action.MONITOR: "MONITOR",
    Action.RATE_LIMIT: "RATE_LIMIT",
    Action.QUARANTINE: "QUARANTINE",
    Action.BLOCK: "BLOCK",
}


@dataclass
class FlowMatch:
    """5-tuple match  (Eq 1)."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    def as_dict(self) -> Dict:
        return {
            "eth_type": 0x0800,
            "ipv4_src": self.src_ip,
            "ipv4_dst": self.dst_ip,
            "ip_proto": {"tcp": 6, "udp": 17, "icmp": 1}.get(self.protocol, 0),
            "src_port": self.src_port,
            "dst_port": self.dst_port,
        }


@dataclass
class OpenFlowRule:
    """A single rule modification structure  r_k  in  R_OF  (Algorithm 1)."""
    kind: str                       # "flow_mod" | "meter_mod"
    action: Action
    match: Optional[FlowMatch]
    priority: int = 0
    # meter
    meter_id: Optional[int] = None
    meter_rate_kbps: Optional[int] = None
    # quarantine
    set_vlan: Optional[int] = None
    # timeouts
    idle_timeout_s: int = 0
    hard_timeout_s: int = 0
    # bookkeeping (not serialised)
    target_switch: Optional[str] = None
    flow_id: Optional[str] = None
    created_at: float = field(default_factory=time.perf_counter)
    notes: str = ""

    def summary(self) -> str:
        return f"{ACTION_NAME[self.action]}(prio={self.priority}, meter={self.meter_rate_kbps}, vlan={self.set_vlan})"


# --- factory functions : one per Algorithm 1 branch ---------------------------

def create_meter_rule(match: FlowMatch, *, meter_id: int, rate_kbps: int = _METER_RATE_KBPS,
                      flow_id: str | None = None) -> OpenFlowRule:
    """Algorithm 1 line 9 : CreateMeterRule(f_k, Rate = 100K).

    Emits BOTH a meter band (the OFPMT_METER 100 Kbps drop band) and the
    flow rule that directs the matched flow through that meter.
    """
    return OpenFlowRule(
        kind="meter_mod", action=Action.RATE_LIMIT, match=match,
        priority=_METER_PRIORITY, meter_id=meter_id, meter_rate_kbps=rate_kbps,
        flow_id=flow_id, notes="OFPMT_METER 100Kbps drop band (critical-flow safe rate-limit)",
    )


def create_vlan_rule(match: FlowMatch, *, vlan: int = _QUARANTINE_VLAN,
                     flow_id: str | None = None) -> OpenFlowRule:
    """Algorithm 1 line 11 : CreateVLANRule(f_k, VLAN = 99)."""
    return OpenFlowRule(
        kind="flow_mod", action=Action.QUARANTINE, match=match,
        priority=_QUARANTINE_PRIORITY, set_vlan=vlan, flow_id=flow_id,
        notes="reassign lateral flow to isolated VLAN 99",
    )


def create_drop_rule(match: FlowMatch, *, priority: int = _DROP_PRIORITY,
                     flow_id: str | None = None) -> OpenFlowRule:
    """Algorithm 1 line 13 : CreateDropRule(f_k, Priority = 200)."""
    return OpenFlowRule(
        kind="flow_mod", action=Action.BLOCK, match=match, priority=priority,
        flow_id=flow_id, notes="high-priority hard drop (empty action set)",
    )


def create_monitor_rule(match: FlowMatch, *, flow_id: str | None = None) -> OpenFlowRule:
    """Algorithm 1 line 16 : CreateMonitorRule(f_k) -- log telemetry, keep forwarding."""
    return OpenFlowRule(
        kind="flow_mod", action=Action.MONITOR, match=match, priority=_MONITOR_PRIORITY,
        flow_id=flow_id, notes="telemetry-only, normal forwarding preserved",
    )


def severity_tier_rule(match: FlowMatch, severity: float, *, meter_id: int,
                       flow_id: str | None = None) -> OpenFlowRule:
    """Sec V.A.4 / Sec III.D : resolve a severity score S_k in [0,1] into a rule.

        S_k <= 0.4          -> MONITOR
        0.4 < S_k <= 0.6    -> RATE_LIMIT  (meter 100 Kbps)
        0.6 < S_k <= 0.8    -> QUARANTINE  (VLAN 99)
        S_k >  0.8          -> BLOCK        (drop, priority 200)
    """
    if severity <= 0.4:
        return create_monitor_rule(match, flow_id=flow_id)
    if severity <= 0.6:
        return create_meter_rule(match, meter_id=meter_id, flow_id=flow_id)
    if severity <= 0.8:
        return create_vlan_rule(match, flow_id=flow_id)
    return create_drop_rule(match, flow_id=flow_id)


CONSTANTS = {
    "meter_rate_kbps": _METER_RATE_KBPS,      # 
    "quarantine_vlan": _QUARANTINE_VLAN,      # 
    "drop_priority": _DROP_PRIORITY,          # 
    "monitor_priority": _MONITOR_PRIORITY,    # 
    "meter_priority": _METER_PRIORITY,        # 
    "quarantine_priority": _QUARANTINE_PRIORITY,  # 
}
