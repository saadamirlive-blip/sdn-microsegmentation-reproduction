"""Phase 2 -- train the 100-tree Random Forest and serialise model.pkl/scaler.pkl.

Run:  python -m ml.train_rf
"""
from __future__ import annotations

import json
from dataclasses import asdict

import joblib
import numpy as np

from common import config
from common.seeding import global_seed
from ml.dataset_builder import build_dataset, summarize
from ml.model import build_random_forest, rf_hyperparameters
from ml.preprocessing import split_and_scale, zscore_manual_check


def train(save: bool = True):
    exp = config.experiment()
    global_seed(int(exp["seeds"]["numpy_seed"]))          # 42

    df = build_dataset()
    dsum = summarize(df)

    split = split_and_scale(df)

    # sanity: sklearn StandardScaler == explicit z=(x-mu)/sigma
    manual = zscore_manual_check(split.scaler, split.X_test_raw)
    assert np.allclose(manual, split.X_test, atol=1e-9), "StandardScaler mismatch"

    # sanity: split sizes match the paper
    assert split.X_train.shape[0] == int(exp["dataset"]["train_samples"]), split.X_train.shape
    assert split.X_test.shape[0] == int(exp["dataset"]["test_samples"]), split.X_test.shape

    clf = build_random_forest()
    clf.fit(split.X_train, split.y_train)

    if save:
        mdir = config.model_dir()
        joblib.dump(clf, mdir / "model.pkl")             # model.pkl
        joblib.dump(split.scaler, mdir / "scaler.pkl")   # scaler.pkl
        meta = {
            "hyperparameters": rf_hyperparameters(),
            "dataset": asdict(dsum),
            "train_samples": int(split.X_train.shape[0]),
            "test_samples": int(split.X_test.shape[0]),
            "feature_order": list(config.ml()["features"]["order"]),
            "scaler_mean": split.scaler.mean_.tolist(),
            "scaler_scale": split.scaler.scale_.tolist(),
        }
        with open(mdir / "training_meta.json", "w", encoding="utf-8") as fh:
            json.dump(meta, fh, indent=2)
        # persist the exact test split so evaluate_rf uses identical data
        np.savez(
            mdir / "test_split.npz",
            X_test=split.X_test, y_test=split.y_test, scen_test=split.scen_test,
            X_test_raw=split.X_test_raw,
        )
        print(f"[train_rf] saved model.pkl, scaler.pkl, test_split.npz -> {mdir}")

    return clf, split, dsum


if __name__ == "__main__":
    train(save=True)
