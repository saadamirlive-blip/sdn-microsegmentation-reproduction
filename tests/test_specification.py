"""Assert the [PAPER] specification values are wired through unchanged."""
import math

import pytest

from common import config


def test_environment_versions_match_paper():
    e = config.experiment()["environment"]
    assert e["operating_system"] == "Ubuntu 22.04 LTS"
    assert e["linux_kernel"] == "5.15"
    assert e["python"] == "3.10"
    assert e["mininet"] == "2.3.0"
    assert e["open_vswitch"] == "2.17.0"
    assert e["openflow"] == "1.3"
    assert e["scikit_learn"] == "1.2.2"
    assert e["numpy"] == "1.24.3"
    assert e["pandas"] == "2.0.1"
    assert e["scapy"] == "2.5.0"


def test_telemetry_interval_is_exactly_3s():
    assert config.experiment()["telemetry"]["polling_interval_s"] == 3.0


def test_dataset_sizes():
    d = config.experiment()["dataset"]
    assert d["total_samples"] == 50000
    assert d["benign_samples"] == 25000
    assert d["malicious_samples"] == 25000
    assert d["train_fraction"] == 0.70 and d["test_fraction"] == 0.30
    assert d["train_samples"] == 35000 and d["test_samples"] == 15000


def test_rf_hyperparameters():
    hp = config.ml()["model"]["hyperparameters"]
    assert hp["n_estimators"] == 100
    assert hp["max_depth"] == 12
    assert hp["min_samples_split"] == 5
    assert hp["class_weight"] == "balanced"
    assert hp["random_state"] == 42


def test_attack_vector_shares_sum_to_one():
    av = config.experiment()["attack_vectors"]
    shares = [v["traffic_share"] for k, v in av.items()
              if isinstance(v, dict) and "traffic_share" in v and v["traffic_share"] > 0]
    assert len(shares) == 6
    assert math.isclose(sum(shares), 1.0, abs_tol=1e-9)


def test_containment_constants():
    from common.openflow_rules import CONSTANTS
    assert CONSTANTS["meter_rate_kbps"] == 100
    assert CONSTANTS["quarantine_vlan"] == 99
    assert CONSTANTS["drop_priority"] == 200


def test_baseline_latencies_are_paper_values():
    b = config.experiment()["baselines"]
    assert b["traditional_firewall"]["response_latency_s"] == 45.0
    assert b["ids_ips"]["response_latency_s"] == 30.0
    assert b["static_sdn"]["response_latency_s"] == 15.0
    assert b["proposed_dynamic_sdn"]["response_latency_s"] is None  # measured


def test_monte_carlo_trials():
    assert config.experiment()["monte_carlo"]["trials"] == 10


def test_constraints_paper_coefficients():
    c = config.experiment()["constraints"]
    assert c["lctrl_intercept"] == 0.246
    assert c["lctrl_slope"] == 0.00454
    assert c["containment_latency_max_s"] == 5.0
    assert c["controller_cpu_load_max"] == 0.80


def test_moop_weights_sum_to_one():
    m = config.experiment()["moop"]
    assert math.isclose(m["alpha"] + m["beta"] + m["gamma"] + m["delta"], 1.0, abs_tol=1e-9)
