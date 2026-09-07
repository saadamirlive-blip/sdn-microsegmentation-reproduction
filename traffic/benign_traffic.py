"""Benign background traffic -- simulation generator  (Sec IV.C.1).

Emits ``RawFlowStats`` telemetry records for legitimate enterprise flows:
HTTP / HTTPS / SQL / inter-department file transfer, between the 13 hosts,
with 6-D features drawn from ``traffic.flow_sampler.sample_benign`` (identical
to the training distribution).

Real-testbed counterpart: ``traffic/iperf_generator.py`` + ``traffic/socket_generator.py``.
"""
from __future__ import annotations

from typing import List

import numpy as np

from common import config
from common.features import RawFlowStats
from topology.topology_model import TopologyModel
from traffic.flow_sampler import sample_benign

_SERVICE_PORTS = {"HTTP": 80, "HTTPS": 443, "SQL": 3306, "file_transfer": 8080}
_PROTO_PORTS = list(_SERVICE_PORTS.items())


def generate_benign_flows(
    rng: np.random.Generator,
    topo: TopologyModel,
    n_flows: int,
    poll_time_s: float,
) -> List[RawFlowStats]:
    """Return ``n_flows`` benign flow-telemetry records active at ``poll_time_s``."""
    exp = config.experiment()
    polling = float(exp["telemetry"]["polling_interval_s"])
    life = float(exp["runtime_traffic"]["flow_lifetime_s"]["benign"])
    bf_runtime = float(exp["runtime_traffic"].get("benign_bursty_fraction_runtime", 0.10))

    feats = sample_benign(rng, n_flows, bursty_fraction=bf_runtime)
    hosts = topo.host_names()
    non_attacker = [h for h in hosts if h != topo.attacker]
    servers = [h for h in hosts if topo.is_server(h)]

    out: List[RawFlowStats] = []
    for i in range(n_flows):
        src = non_attacker[int(rng.integers(len(non_attacker)))]
        # 70% of benign flows are client->server service calls; 30% peer-to-peer file xfer
        if rng.random() < 0.70 and servers:
            dst = servers[int(rng.integers(len(servers)))]
            if dst == src:
                dst = servers[(servers.index(dst) + 1) % len(servers)]
            proto_name, dport = _PROTO_PORTS[int(rng.integers(len(_PROTO_PORTS)))]
        else:
            dst = non_attacker[int(rng.integers(len(non_attacker)))]
            if dst == src:
                dst = non_attacker[(non_attacker.index(dst) + 1) % len(non_attacker)]
            proto_name, dport = "file_transfer", 8080

        # protocol of record: benign is overwhelmingly TCP; a few UDP (SQL/DNS-ish)
        proto = "udp" if (proto_name == "SQL" and rng.random() < 0.15) else "tcp"
        pps = float(feats["pps"][i]); bps = float(feats["bps"][i])
        dur = float(feats["duration"][i])
        pkt = pps * polling
        byt = bps * polling
        tcp_r = float(feats["tcp_ratio"][i]); udp_r = float(feats["udp_ratio"][i]); icmp_r = float(feats["icmp_ratio"][i])

        out.append(RawFlowStats(
            flow_id=f"b-{poll_time_s:.0f}-{i}",
            src_ip=topo.hosts[src].ip, dst_ip=topo.hosts[dst].ip,
            src_port=int(30000 + rng.integers(0, 20000)), dst_port=int(dport),
            protocol=proto,
            packet_count=pkt, byte_count=byt, duration_s=dur,
            tcp_packets=pkt * tcp_r, udp_packets=pkt * udp_r, icmp_packets=pkt * icmp_r,
            pps=pps, bps=bps,
            meta={
                "label": "benign", "scenario": "benign",
                "src_host": src, "dst_host": dst,
                "switch": topo.edge_switch_of(src),
                "init_time_s": poll_time_s - float(rng.random()) * polling,
                "lifetime_s": max(polling, life * (0.5 + rng.random())),
                "distinct_dst": 1, "failed_auth": 0,
                "is_service_call": proto_name in _SERVICE_PORTS,
            },
        ))
    return out
