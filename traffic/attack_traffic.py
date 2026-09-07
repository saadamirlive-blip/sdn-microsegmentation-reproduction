"""Malicious traffic -- simulation generator  (Sec IV.C.2, Table VII).

All attack flows originate from the attacker host h4.  Six vectors are mixed by
their Table VII traffic shares; a horizontal reconnaissance probe (h4 -> {h2,h5})
is added on top (Sec IV.C.2, absent from Table VII).

6-D features come from ``traffic.flow_sampler.sample_attack`` (identical to the
training distribution).  ``.meta`` carries the true label, the scenario, the
per-flow lifetime, and the port-scan / auth-failure telemetry that feed the
risk-score signals delta_{i,2}, delta_{i,3} (Eq 4).

Real-testbed counterpart: ``attacks/*.py`` (Scapy 2.5.0 / hping3).
"""
from __future__ import annotations

from typing import Dict, List

import numpy as np

from common import config
from common.features import RawFlowStats
from topology.topology_model import TopologyModel
from traffic.flow_sampler import sample_attack

_VOLUMETRIC = {"syn_flood", "udp_flood", "icmp_flood", "mixed_ddos"}
_LOW_RATE = {"slowloris", "http_flood"}
_VECTOR_PROTO = {
    "syn_flood": "tcp", "udp_flood": "udp", "icmp_flood": "icmp",
    "mixed_ddos": "tcp", "slowloris": "tcp", "http_flood": "tcp",
}
_VECTOR_DPORT = {
    "syn_flood": 80, "udp_flood": 53, "icmp_flood": 0,
    "mixed_ddos": 443, "slowloris": 80, "http_flood": 80,
}


def _shares() -> Dict[str, float]:
    av = config.experiment()["attack_vectors"]
    return {k: float(v["traffic_share"]) for k, v in av.items()
            if isinstance(v, dict) and "traffic_share" in v and v["traffic_share"] > 0}


def _split_counts(total: int, shares: Dict[str, float]) -> Dict[str, int]:
    raw = {k: total * v for k, v in shares.items()}
    base = {k: int(np.floor(x)) for k, x in raw.items()}
    rem = total - sum(base.values())
    order = sorted(shares, key=lambda k: raw[k] - base[k], reverse=True)
    for i in range(rem):
        base[order[i % len(order)]] += 1
    return base


def generate_attack_flows(
    rng: np.random.Generator,
    topo: TopologyModel,
    n_flows: int,
    poll_time_s: float,
) -> List[RawFlowStats]:
    exp = config.experiment()
    polling = float(exp["telemetry"]["polling_interval_s"])
    lifetimes = exp["runtime_traffic"]["flow_lifetime_s"]
    attacker = topo.attacker
    a_ip = topo.hosts[attacker].ip
    a_switch = topo.edge_switch_of(attacker)
    targetable = [h for h in topo.host_names() if h != attacker]

    hr_frac = float(exp["runtime_traffic"].get("hit_and_run_fraction", 0.0))
    hr_life = exp["runtime_traffic"].get("hit_and_run_lifetime_s", {"min": 0.3, "max": 2.6})

    per_vec = _split_counts(n_flows, _shares())
    out: List[RawFlowStats] = []
    idx = 0
    for vec, cnt in per_vec.items():
        if cnt <= 0:
            continue
        feats = sample_attack(rng, vec, cnt)
        proto = _VECTOR_PROTO[vec]
        fam = "volumetric" if vec in _VOLUMETRIC else "low_rate"
        life = float(lifetimes[fam])
        for j in range(cnt):
            dst = targetable[int(rng.integers(len(targetable)))]
            # hit-and-run: a fraction of flows (any vector) finish inside one
            # 3 s telemetry window and so cannot be caught by 3 s polling
            # (the paper's own latency-bound argument, Sec IV.E).
            if rng.random() < hr_frac:
                flow_life = float(rng.uniform(hr_life["min"], hr_life["max"]))
            else:
                flow_life = max(polling, life * (0.6 + 0.8 * rng.random()))
            pps = float(feats["pps"][j]); bps = float(feats["bps"][j])
            dur = float(feats["duration"][j])
            pkt, byt = pps * polling, bps * polling
            tcp_r = float(feats["tcp_ratio"][j]); udp_r = float(feats["udp_ratio"][j]); icmp_r = float(feats["icmp_ratio"][j])
            out.append(RawFlowStats(
                flow_id=f"a-{vec[:3]}-{poll_time_s:.0f}-{idx}",
                src_ip=a_ip, dst_ip=topo.hosts[dst].ip,
                src_port=int(40000 + rng.integers(0, 20000)),
                dst_port=int(_VECTOR_DPORT[vec]), protocol=proto,
                packet_count=pkt, byte_count=byt, duration_s=dur,
                tcp_packets=pkt * tcp_r, udp_packets=pkt * udp_r, icmp_packets=pkt * icmp_r,
                pps=pps, bps=bps,
                meta={
                    "label": "attack", "scenario": vec, "family": fam,
                    "src_host": attacker, "dst_host": dst, "switch": a_switch,
                    "init_time_s": poll_time_s - float(rng.random()) * polling,
                    "lifetime_s": flow_life,
                    "hit_and_run": bool(flow_life < polling),
                    "distinct_dst": 1, "failed_auth": 0,
                },
            ))
            idx += 1
    return out


def generate_horizontal_probe_flows(
    rng: np.random.Generator,
    topo: TopologyModel,
    poll_time_s: float,
    n_probe_flows: int = 24,
) -> List[RawFlowStats]:
    """h4 sweeps the internal subnet, concentrating on HR (h2) and DB (h5).

    Sec IV.C.2: "From the compromised Host (h4) a subnet on the internal subnet
    is probed, hitting the HR server (h2) and DB (h5) server."
    """
    exp = config.experiment()
    polling = float(exp["telemetry"]["polling_interval_s"])
    life = float(exp["runtime_traffic"]["flow_lifetime_s"]["horizontal_probe"])
    attacker = topo.attacker
    a_ip = topo.hosts[attacker].ip
    a_switch = topo.edge_switch_of(attacker)
    prio_targets = [t for t in config.experiment()["attack_vectors"]["horizontal_probe"]["targets"]]
    all_targets = [h for h in topo.host_names() if h != attacker]

    # low-rate TCP probe features (close to benign) -> hard to catch, like Sec IV.C.2
    feats = sample_attack(rng, "slowloris", n_probe_flows)
    out: List[RawFlowStats] = []
    distinct = set()
    for i in range(n_probe_flows):
        if i < len(prio_targets) or rng.random() < 0.45:
            dst = prio_targets[i % len(prio_targets)]
        else:
            dst = all_targets[int(rng.integers(len(all_targets)))]
        distinct.add(dst)
        pps = float(feats["pps"][i]) * 0.6
        bps = float(feats["bps"][i]) * 0.6
        dur = float(feats["duration"][i]) * 0.3
        pkt, byt = pps * polling, bps * polling
        dport = int([22, 445, 3389, 3306, 1433][int(rng.integers(5))])
        out.append(RawFlowStats(
            flow_id=f"a-hpr-{poll_time_s:.0f}-{i}",
            src_ip=a_ip, dst_ip=topo.hosts[dst].ip,
            src_port=int(50000 + rng.integers(0, 10000)), dst_port=dport, protocol="tcp",
            packet_count=pkt, byte_count=byt, duration_s=dur,
            tcp_packets=pkt, udp_packets=0.0, icmp_packets=0.0, pps=pps, bps=bps,
            meta={
                "label": "attack", "scenario": "horizontal_probe", "family": "horizontal_probe",
                "src_host": attacker, "dst_host": dst, "switch": a_switch,
                "init_time_s": poll_time_s - float(rng.random()) * polling,
                "lifetime_s": max(polling, life * (0.6 + 0.8 * rng.random())),
                "distinct_dst": len(distinct),
                "failed_auth": int(1 + rng.integers(0, 5)) if dst in prio_targets else 0,
            },
        ))
    # back-fill the running distinct-destination count onto every probe flow
    for r in out:
        r.meta["distinct_dst"] = len(distinct)
    return out
