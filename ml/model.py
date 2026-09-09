"""Random Forest factory  (Sec III.D Phase 2, Sec IV.D).

Hyper-parameters -- ALL , read from ``config/ml_config.yaml``:
    n_estimators      = 100
    max_depth         = 12
    min_samples_split = 5
    class_weight      = "balanced"
    random_state      = 42

No other knob is set (scikit-learn 1.2.2 defaults otherwise).  No search.
"""
from __future__ import annotations

from typing import Any, Dict

from sklearn.ensemble import RandomForestClassifier

from common import config


def rf_hyperparameters() -> Dict[str, Any]:
    hp = dict(config.ml()["model"]["hyperparameters"])
    return hp


def build_random_forest() -> RandomForestClassifier:
    hp = rf_hyperparameters()
    return RandomForestClassifier(
        n_estimators=int(hp["n_estimators"]),          # 100
        max_depth=int(hp["max_depth"]),                # 12
        min_samples_split=int(hp["min_samples_split"]),  # 5
        class_weight=hp["class_weight"],               # "balanced"
        random_state=int(hp["random_state"]),          # 42
        n_jobs=int(hp.get("n_jobs", -1)),              # runtime-only
    )
