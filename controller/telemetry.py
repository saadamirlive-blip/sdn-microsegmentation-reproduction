"""3.0-second flow-telemetry polling for the Ryu controller  (Sec IV.A, V.A.1).

Issues periodic OFPFlowStatsRequest to every connected datapath and turns the
replies into ``common.features.RawFlowStats`` records (the same structure the
simulation feeds to the DMCA).
"""
from __future__ import annotations

import time
from typing import Dict, List

from common import config
from common.features import RawFlowStats

POLLING_INTERVAL_S = float(config.experiment()["telemetry"]["polling_interval_s"])  # 3.0


def build_flow_stats_request(datapath):
    """OFPFlowStatsRequest for all tables / all flows on one datapath."""
    parser = datapath.ofproto_parser
    return parser.OFPFlowStatsRequest(datapath)


def _proto_name(ip_proto: int) -> str:
    return {6: "tcp", 17: "udp", 1: "icmp"}.get(int(ip_proto or 0), "tcp")


def parse_flow_stats_reply(body, *, dpid: int, prev: Dict[str, dict] | None = None) -> List[RawFlowStats]:
    """Convert an OFPFlowStatsReply body into RawFlowStats.

    ``prev`` holds the previous poll's (packet_count, byte_count) per flow key so
    per-interval pps/bps can be computed as deltas over the 3.0 s window.
    """
    prev = prev or {}
    now = time.time()
    out: List[RawFlowStats] = []
    for stat in body:
        m = stat.match
        src = m.get("ipv4_src", "0.0.0.0")
        dst = m.get("ipv4_dst", "0.0.0.0")
        ipp = m.get("ip_proto", 0)
        proto = _proto_name(ipp)
        sport = m.get("tcp_src", m.get("udp_src", 0))
        dport = m.get("tcp_dst", m.get("udp_dst", 0))
        key = f"{dpid}:{src}:{dst}:{sport}:{dport}:{proto}"

        dpk = stat.packet_count - prev.get(key, {}).get("pkt", 0)
        dby = stat.byte_count - prev.get(key, {}).get("byt", 0)
        dpk = max(dpk, 0); dby = max(dby, 0)
        dur = stat.duration_sec + stat.duration_nsec / 1e9
        pps = dpk / POLLING_INTERVAL_S
        bps = dby / POLLING_INTERVAL_S

        rec = RawFlowStats(
            flow_id=key, src_ip=src, dst_ip=dst, src_port=int(sport), dst_port=int(dport),
            protocol=proto, packet_count=float(dpk), byte_count=float(dby),
            duration_s=float(dur),
            tcp_packets=float(dpk) if proto == "tcp" else 0.0,
            udp_packets=float(dpk) if proto == "udp" else 0.0,
            icmp_packets=float(dpk) if proto == "icmp" else 0.0,
            pps=pps, bps=bps,
            meta={"dpid": dpid, "poll_time": now, "label": None},
        )
        out.append(rec)
        prev[key] = {"pkt": stat.packet_count, "byt": stat.byte_count}
    return out
