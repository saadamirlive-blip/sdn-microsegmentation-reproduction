"""End-to-end smoke test: dataset -> train -> 1 proposed trial -> metrics finite."""
import math

import pytest


@pytest.mark.slow
def test_full_pipeline_one_trial(tmp_path):
    from ml.train_rf import train
    from ml.evaluate_rf import evaluate
    from simulation.system_sim import run_proposed_trial
    from experiments.metrics_bundle import compute_trial_metrics

    clf, split, _ = train(save=True)
    off = evaluate()
    assert off["accuracy"] > 0.95
    assert off["confusion"]["false_positive"] >= 0

    rec = run_proposed_trial(0)
    m = compute_trial_metrics(rec)
    for v in (m.cr_pct, m.tresp_s, m.fpr_pct, m.fcr_pct, m.na_pct):
        assert math.isfinite(v)
    assert 80.0 <= m.cr_pct <= 100.0
    assert 0.0 < m.tresp_s < 5.0           # containment-latency constraint
    assert 90.0 <= m.na_pct <= 100.0
    assert m.controller_load_final <= 0.80  # controller-CPU constraint


def test_seeding_is_reproducible():
    from simulation.system_sim import run_proposed_trial
    from experiments.metrics_bundle import compute_trial_metrics
    a = compute_trial_metrics(run_proposed_trial(0))
    b = compute_trial_metrics(run_proposed_trial(0))
    assert a.cr_pct == b.cr_pct
    assert a.tresp_s == b.tresp_s
