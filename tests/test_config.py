"""Internal-consistency checks on the configuration."""
import math


from common import config


def test_environment_versions():
    e = config.experiment()["environment"]
    assert e["python"] == "3.10"
    assert e["scikit_learn"] == "1.2.2"
    assert e["numpy"] == "1.24.3"
    assert e["pandas"] == "2.0.1"
    assert e["openflow"] == "1.3"


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


def test_monte_carlo_trials():
    assert config.experiment()["monte_carlo"]["trials"] == 10


def test_constraint_coefficients():
    c = config.experiment()["constraints"]
    assert c["lctrl_intercept"] == 0.246
    assert c["lctrl_slope"] == 0.00454
    assert c["containment_latency_max_s"] == 5.0
    assert c["controller_cpu_load_max"] == 0.80


def test_moop_weights_sum_to_one():
    m = config.experiment()["moop"]
    assert math.isclose(m["alpha"] + m["beta"] + m["gamma"] + m["delta"], 1.0, abs_tol=1e-9)
