"""Unit tests for topology, features, dataset, risk engine, policy engine, metrics."""
import numpy as np
import pytest

from common import config
from common.features import RawFlowStats, extract_vector
from common.openflow_rules import Action, severity_tier_rule, FlowMatch
from common.risk_engine import host_risk_score, host_state, RiskSignals
from topology.topology_model import load_topology


# --- topology -------------------------------------------------------------
def test_topology_matches_fig2():
    t = load_topology()
    assert len(t.hosts) == 13
    assert t.n_directed_paths() == 156
    assert t.attacker == "h4"
    assert t.hosts["h2"].role == "hr_server" and t.hosts["h2"].server
    assert t.hosts["h5"].role == "database_server" and t.hosts["h5"].server
    # S3 segment = h9..h13
    s3 = [h for h in t.host_names() if t.edge_switch_of(h) == "s3"]
    assert s3 == ["h9", "h10", "h11", "h12", "h13"]


# --- features ----------------------------------------------------------
def test_feature_vector_order_and_shape():
    s = RawFlowStats(flow_id="f", src_ip="10.0.0.1", dst_ip="10.0.0.5",
                     src_port=1234, dst_port=80, protocol="tcp",
                     packet_count=30, byte_count=3000, duration_s=1.0,
                     tcp_packets=30, pps=0.2, bps=0.1)
    v = extract_vector(s)
    assert v.shape == (6,)
    assert v[0] == pytest.approx(0.2) and v[1] == pytest.approx(0.1)
    assert v[3] == pytest.approx(1.0)  # tcp_ratio


# --- dataset ---------------------------------------------------------
def test_dataset_balance_and_table_vii_shares():
    from ml.dataset_builder import build_dataset, summarize
    df = build_dataset()
    s = summarize(df)
    assert s.n_total == 50000 and s.n_benign == 25000 and s.n_malicious == 25000
    # Table VII shares of the 25,000 malicious samples
    assert s.per_scenario["syn_flood"] == 8750
    assert s.per_scenario["udp_flood"] == 6250
    assert s.per_scenario["icmp_flood"] == 3750
    assert s.per_scenario["mixed_ddos"] == 3000
    assert s.per_scenario["slowloris"] == 2000
    assert s.per_scenario["http_flood"] == 1250


def test_dataset_is_deterministic():
    from ml.dataset_builder import build_dataset
    a = build_dataset().to_numpy()
    b = build_dataset().to_numpy()
    assert np.array_equal(a[:, :6].astype(float), b[:, :6].astype(float))


# --- risk engine (Eq 2 / Eq 4) --------------------------------------
def test_risk_score_bounds_and_states():
    lo = host_risk_score(0.0, RiskSignals())
    hi = host_risk_score(1.0, RiskSignals(1, 1, 1))
    assert 0.0 <= lo < hi <= 100.0
    assert host_state(0.0) == 0
    assert host_state(40.0) == 1        # suspected (default thresholds 35/60)
    assert host_state(90.0) == 2        # compromised


# --- severity tiers (Sec V.A.4) ----------------------------------
@pytest.mark.parametrize("sev,expect", [
    (0.30, Action.MONITOR), (0.50, Action.RATE_LIMIT),
    (0.70, Action.QUARANTINE), (0.95, Action.BLOCK)])
def test_severity_tiers(sev, expect):
    m = FlowMatch("10.0.0.4", "10.0.0.2", 5000, 9999, "tcp")
    r = severity_tier_rule(m, sev, meter_id=1)
    assert r.action == expect
    if expect == Action.BLOCK:
        assert r.priority == 200
    if expect == Action.RATE_LIMIT:
        assert r.meter_rate_kbps == 100
    if expect == Action.QUARANTINE:
        assert r.set_vlan == 99


# --- DMCA / Algorithm 1 --------------------------------------
def test_dmca_contains_attacker_flows_and_spares_benign():
    from common.policy_engine import run_dmca
    topo = load_topology()
    benign = [RawFlowStats(flow_id=f"b{i}", src_ip=topo.hosts['h7'].ip,
                           dst_ip=topo.hosts['h6'].ip, src_port=3000 + i, dst_port=80,
                           protocol="tcp", packet_count=6, byte_count=600, duration_s=1.0,
                           tcp_packets=6, pps=0.2, bps=0.1,
                           meta={"label": "benign", "distinct_dst": 1}) for i in range(20)]
    attack = [RawFlowStats(flow_id=f"a{i}", src_ip=topo.hosts['h4'].ip,
                           dst_ip=topo.hosts['h2'].ip, src_port=40000 + i, dst_port=80,
                           protocol="tcp", packet_count=90, byte_count=45000, duration_s=0.2,
                           tcp_packets=90, pps=3.0, bps=1.5,
                           meta={"label": "attack", "distinct_dst": 6, "failed_auth": 3})
              for i in range(30)]

    # a deterministic stand-in classifier: attack rows -> high prob
    def pp(X):
        return np.where(X[:, 0] > 1.0, 0.97, 0.02)

    res = run_dmca(benign + attack, pp)
    acts = {d.flow_id: d.action for d in res.decisions}
    assert all(acts[f"a{i}"] != Action.MONITOR for i in range(30))       # attacker contained
    assert sum(acts[f"b{i}"] == Action.MONITOR for i in range(20)) >= 18  # benign mostly spared


# --- metrics ---------------------------------------------------
def test_metric_functions_on_synthetic_outcomes():
    from metrics.records import FlowOutcome, PathAvailabilitySample
    from metrics.containment import containment_rate
    from metrics.false_positive import false_positive_rate
    from metrics.availability import network_availability

    flows = [
        FlowOutcome("a1", "attack", "syn_flood", "h4", "h2", True, 0.99, 80, True,
                    "BLOCK", True, 0.0, 40.0, 1.4, 1.4, True),
        FlowOutcome("a2", "attack", "syn_flood", "h4", "h2", False, 0.1, 5, False,
                    "MONITOR", False, 0.0, 1.0, None, None, False),
        FlowOutcome("b1", "benign", "benign", "h7", "h6", True, 0.7, 40, False,
                    "MONITOR", False, 0.0, 5.0, None, None, False),
    ]
    assert containment_rate(flows) == pytest.approx(50.0)
    assert false_positive_rate(flows) == pytest.approx(100.0)  # 1/1 benign flagged
    av = [PathAvailabilitySample(0, 150, 156, False), PathAvailabilitySample(3, 156, 156, True)]
    assert 90 < network_availability(av) < 100
