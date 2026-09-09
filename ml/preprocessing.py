"""Phase 2 preprocessing -- leakage-safe StandardScaler  (Sec III.D, task Sec 11).

Paper: features "standardized using StandardScaler (z = (x - mu)/sigma)" and the
fitted scaler "saved to scaler.pkl".

Leakage guards (task Sec 11):
  1. split BEFORE fitting anything
  2. StandardScaler.fit on TRAIN ONLY
  3. transform TEST with the train-fitted scaler
  4. the label column is never part of X
  5. the 'scenario' column is metadata, never a feature
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from common import config

FEATURES = list(config.ml()["features"]["order"])


@dataclass
class SplitData:
    X_train_raw: np.ndarray
    X_test_raw: np.ndarray
    y_train: np.ndarray
    y_test: np.ndarray
    scen_train: np.ndarray
    scen_test: np.ndarray
    scaler: StandardScaler
    X_train: np.ndarray            # scaled
    X_test: np.ndarray             # scaled (with TRAIN-fitted scaler)


def split_and_scale(df: pd.DataFrame) -> SplitData:
    exp = config.experiment()
    ds = exp["dataset"]
    test_size = float(ds["test_fraction"])                 # 0.30
    stratify_flag = bool(ds["test_split_stratified"])      # True
    random_state = int(exp["seeds"]["random_state"])       # 42

    X = df[FEATURES].to_numpy(dtype=float)
    y = df["label"].to_numpy(dtype=int)
    scen = df["scenario"].to_numpy()

    strat = y if stratify_flag else None
    (X_tr, X_te, y_tr, y_te, s_tr, s_te) = train_test_split(
        X, y, scen, test_size=test_size, random_state=random_state,
        shuffle=True, stratify=strat,
    )

    # --- fit ONLY on train ------------------------------------------------
    scaler = StandardScaler()
    scaler.fit(X_tr)
    X_tr_s = scaler.transform(X_tr)
    X_te_s = scaler.transform(X_te)          # train-fitted params applied to test

    return SplitData(
        X_train_raw=X_tr, X_test_raw=X_te, y_train=y_tr, y_test=y_te,
        scen_train=s_tr, scen_test=s_te, scaler=scaler,
        X_train=X_tr_s, X_test=X_te_s,
    )


def zscore_manual_check(scaler: StandardScaler, X_raw: np.ndarray) -> np.ndarray:
    """Explicit z = (x - mu)/sigma using the fitted scaler, for a sanity assert."""
    return (X_raw - scaler.mean_) / np.sqrt(scaler.var_)
