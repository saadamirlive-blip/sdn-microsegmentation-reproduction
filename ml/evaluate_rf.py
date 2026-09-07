"""Phase 2 evaluation -- OFFLINE Random Forest results (Table V + Table VI).

Emits:
  results/classification_report.txt
  results/confusion_matrix.csv
  results/rf_offline_metrics.json
  results/feature_importance.csv

These are the OFFLINE numbers.  They are intentionally kept separate from the
system-level (online) metrics (task Sec 22): the paper's offline FPR is 0.20%
whereas its system-level FPR is 1.2%.

Run:  python -m ml.evaluate_rf
"""
from __future__ import annotations

import json

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, precision_score, recall_score,
                             roc_auc_score)

from common import config


def _load():
    mdir = config.model_dir()
    clf = joblib.load(mdir / "model.pkl")
    npz = np.load(mdir / "test_split.npz", allow_pickle=True)
    return clf, npz["X_test"], npz["y_test"], npz["scen_test"]


def evaluate() -> dict:
    rdir = config.results_dir()
    clf, X_test, y_test, scen_test = _load()

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec_attack = precision_score(y_test, y_pred, pos_label=1)
    rec_attack = recall_score(y_test, y_pred, pos_label=1)
    auc = roc_auc_score(y_test, y_proba)
    cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    n_norm = int((y_test == 0).sum())
    n_att = int((y_test == 1).sum())
    fpr_offline = fp / n_norm if n_norm else float("nan")
    fnr_offline = fn / n_att if n_att else float("nan")

    # --- Table V ------------------------------------------------------------
    metrics = {
        "test_samples": int(len(y_test)),
        "test_normal": n_norm,
        "test_attack": n_att,
        "accuracy": float(acc),
        "attack_precision": float(prec_attack),
        "recall": float(rec_attack),
        "roc_auc": float(auc),
        "confusion": {"true_normal": int(tn), "false_positive": int(fp),
                      "false_negative": int(fn), "true_attack": int(tp)},
        "fpr_offline": float(fpr_offline),
        "fnr_offline": float(fnr_offline),
    }

    with open(rdir / "classification_report.txt", "w", encoding="utf-8") as fh:
        fh.write("Random Forest -- OFFLINE classification performance (Table V)\n")
        fh.write("=" * 64 + "\n\n")
        fh.write(classification_report(y_test, y_pred, target_names=["normal", "attack"], digits=4))
        fh.write("\n\nConfusion matrix [rows=true, cols=pred], labels [normal, attack]:\n")
        fh.write(f"  TN={tn}  FP={fp}\n  FN={fn}  TP={tp}\n")
        fh.write(f"\nAccuracy      : {acc*100:.2f}%\n")
        fh.write(f"Attack Prec.  : {prec_attack*100:.2f}%\n")
        fh.write(f"Recall (TPR)  : {rec_attack*100:.2f}%\n")
        fh.write(f"ROC-AUC       : {auc:.4f}\n")
        fh.write(f"Offline FPR   : {fpr_offline*100:.2f}%  ({fp} / {n_norm})\n")

    pd.DataFrame(cm, index=["true_normal", "true_attack"],
                 columns=["pred_normal", "pred_attack"]).to_csv(rdir / "confusion_matrix.csv")

    # --- Table VI : feature importance -----------------------------------
    feats = list(config.ml()["features"]["order"])
    imp = clf.feature_importances_
    paper_imp = config.ml()["features"]["paper_importance"]
    fi = pd.DataFrame({
        "feature": feats,
        "importance_reproduced": imp,
        "importance_paper": [paper_imp[f] for f in feats],
    })
    fi["abs_diff"] = (fi.importance_reproduced - fi.importance_paper).abs()
    fi.to_csv(rdir / "feature_importance.csv", index=False)

    # --- per-scenario recall (diagnostic; not in paper tables) -----------
    per_scn = {}
    for s in np.unique(scen_test):
        m = scen_test == s
        if s == "benign":
            per_scn[s] = {"n": int(m.sum()),
                          "flagged_malicious_pct": float((y_pred[m] == 1).mean() * 100)}
        else:
            per_scn[s] = {"n": int(m.sum()),
                          "detected_pct": float((y_pred[m] == 1).mean() * 100)}
    metrics["per_scenario"] = per_scn
    metrics["feature_importance_reproduced"] = {f: float(v) for f, v in zip(feats, imp)}

    with open(rdir / "rf_offline_metrics.json", "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)

    print("[evaluate_rf] OFFLINE Random Forest results")
    print(f"  accuracy={acc*100:.2f}%  precision={prec_attack*100:.2f}%  "
          f"recall={rec_attack*100:.2f}%  AUC={auc:.4f}")
    print(f"  confusion  TN={tn} FP={fp} FN={fn} TP={tp}   offline FPR={fpr_offline*100:.2f}%")
    return metrics


if __name__ == "__main__":
    evaluate()
