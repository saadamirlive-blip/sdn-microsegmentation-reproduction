"""Turn shared ``OpenFlowRule`` structures into real Ryu OF 1.3 messages.

Sec V.A.5:  R_OF -> OFPT_METER_MOD (100 Kbps drop band) for rate-limiting,
            OFPT_FLOW_MOD (prioritised match/action) for quarantine / block /
            monitor.  Only imported on the Ubuntu testbed (needs ``ryu``).
"""
from __future__ import annotations

from common.openflow_rules import (CONSTANTS, Action, FlowMatch, OpenFlowRule,
                                   create_drop_rule, create_meter_rule,
                                   create_monitor_rule, create_vlan_rule,
                                   severity_tier_rule)

try:
    from ryu.ofproto import ofproto_v1_3 as ofp
    from ryu.ofproto import ofproto_v1_3_parser as parser
    _HAVE_RYU = True
except Exception:  # pragma: no cover
    _HAVE_RYU = False

__all__ = ["CONSTANTS", "Action", "FlowMatch", "OpenFlowRule",
           "create_drop_rule", "create_meter_rule", "create_monitor_rule",
           "create_vlan_rule", "severity_tier_rule",
           "to_flow_mod", "to_meter_mod"]

_IP_PROTO = {"tcp": 6, "udp": 17, "icmp": 1}


def _match(datapath, m: FlowMatch):
    kw = dict(eth_type=0x0800, ipv4_src=m.src_ip, ipv4_dst=m.dst_ip)
    p = _IP_PROTO.get(m.protocol)
    if p:
        kw["ip_proto"] = p
        if m.protocol == "tcp":
            if m.src_port:
                kw["tcp_src"] = int(m.src_port)
            if m.dst_port:
                kw["tcp_dst"] = int(m.dst_port)
        elif m.protocol == "udp":
            if m.src_port:
                kw["udp_src"] = int(m.src_port)
            if m.dst_port:
                kw["udp_dst"] = int(m.dst_port)
    return datapath.ofproto_parser.OFPMatch(**kw)


def to_meter_mod(datapath, rule: OpenFlowRule):
    """OFPMeterMod : one 100 Kbps DROP band (Algorithm 1 line 9 / Sec V.A.5)."""
    if not _HAVE_RYU:  # pragma: no cover
        raise RuntimeError("ryu not installed -- testbed only")
    ofproto = datapath.ofproto
    psr = datapath.ofproto_parser
    band = psr.OFPMeterBandDrop(rate=int(rule.meter_rate_kbps or CONSTANTS["meter_rate_kbps"]),
                                burst_size=0)
    return psr.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD,
                           flags=ofproto.OFPMF_KBPS, meter_id=int(rule.meter_id or 1),
                           bands=[band])


def to_flow_mod(datapath, rule: OpenFlowRule, table_id: int = 0):
    """OFPFlowMod for MONITOR / RATE_LIMIT / QUARANTINE / BLOCK."""
    if not _HAVE_RYU:  # pragma: no cover
        raise RuntimeError("ryu not installed -- testbed only")
    ofproto = datapath.ofproto
    psr = datapath.ofproto_parser
    match = _match(datapath, rule.match)

    if rule.action == Action.BLOCK:
        inst = []                                    # empty action set -> drop
    elif rule.action == Action.RATE_LIMIT:
        inst = [psr.OFPInstructionMeter(int(rule.meter_id or 1)),
                psr.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                          [psr.OFPActionOutput(ofproto.OFPP_NORMAL)])]
    elif rule.action == Action.QUARANTINE:
        acts = [psr.OFPActionPushVlan(0x8100),
                psr.OFPActionSetField(vlan_vid=(0x1000 | int(rule.set_vlan or CONSTANTS["quarantine_vlan"]))),
                psr.OFPActionOutput(ofproto.OFPP_NORMAL)]
        inst = [psr.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, acts)]
    else:  # MONITOR
        inst = [psr.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                          [psr.OFPActionOutput(ofproto.OFPP_NORMAL)])]

    return psr.OFPFlowMod(datapath=datapath, table_id=table_id,
                          priority=int(rule.priority), match=match,
                          idle_timeout=int(rule.idle_timeout_s),
                          hard_timeout=int(rule.hard_timeout_s),
                          instructions=inst)
