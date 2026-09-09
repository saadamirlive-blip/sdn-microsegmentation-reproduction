"""Figures for the proposed Dynamic SDN experiment.

Every figure is built only from this experiment's own ``results/*.csv`` /
``results/*.json``.  No external reference values are plotted.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from common import config

_BLUE = "#3b7dd8"
_GREEN = "#8bbf5b"
_VEC_ORDER = ["syn_flood", "udp_flood", "icmp_flood", "mixed_ddos", "slowloris", "http_flood"]
_ACTIONS = ["BLOCK", "QUARANTINE", "RATE_LIMIT", "MONITOR"]


def _fig_dir() -> Path:
    return config.figures_dir()


def _res(name: str) -> pd.DataFrame:
    return pd.read_csv(config.results_dir() / name)


def fig_headline_metrics():
    """The five headline metrics: mean +/- std over trials."""
    agg = _res("aggregate_results.csv").iloc[0]
    keys = [("cr_pct", "Containment\nRate (%)"), ("tresp_s", "Response\nLatency (s)"),
            ("fpr_pct", "False Positive\nRate (%)"), ("fcr_pct", "False Contain.\nRate (%)"),
            ("na_pct", "Network\nAvailability (%)")]
    vals = [agg[f"{k}_mean"] for k, _ in keys]
    errs = [agg[f"{k}_std"] for k, _ in keys]
    fig, ax = plt.subplots(figsize=(7.6, 4.4))
    x = np.arange(len(keys))
    ax.bar(x, vals, yerr=errs, capsize=4, color=_BLUE, width=0.55)
    for xi, v in zip(x, vals):
        ax.text(xi, v, f" {v:.2f}", ha="center", va="bottom", fontsize=9)
    ax.set_xticks(x); ax.set_xticklabels([lbl for _, lbl in keys], fontsize=9)
    ax.set_title(f"Proposed Dynamic SDN -- headline metrics (mean +/- std, {int(agg['n_trials'])} trials)")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(_fig_dir() / "headline_metrics.png", dpi=130); plt.close(fig)


def fig_cr_by_vector():
    cv = _res("containment_by_vector.csv").set_index("attack_vector")
    order = [v for v in _VEC_ORDER if v in cv.index]
    means = [cv.loc[v, "cr_mean"] for v in order]
    stds = [cv.loc[v, "cr_std"] for v in order]
    fig, ax = plt.subplots(figsize=(7.6, 4.2))
    x = np.arange(len(order))
    ax.bar(x, means, yerr=stds, capsize=4, color=_BLUE, width=0.55)
    for xi, v in zip(x, means):
        ax.text(xi, v, f" {v:.1f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels([v.replace("_", "\n") for v in order], fontsize=8)
    ax.set_ylabel("Containment Rate (%)"); ax.set_ylim(80, 102)
    ax.set_title("Containment Rate by Attack Vector")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(_fig_dir() / "cr_by_vector.png", dpi=130); plt.close(fig)


def fig_response_time_by_action():
    lat = _res("latency_results.csv")
    cols = [f"tresp_{a}" for a in _ACTIONS if f"tresp_{a}" in lat.columns]
    if not cols:
        return
    means = [lat[c].mean() for c in cols]
    stds = [lat[c].std(ddof=0) for c in cols]
    labels = [c.replace("tresp_", "") for c in cols]
    fig, ax = plt.subplots(figsize=(6.6, 4.2))
    x = np.arange(len(cols))
    ax.bar(x, means, yerr=stds, capsize=4, color=_GREEN, width=0.5)
    for xi, v in zip(x, means):
        ax.text(xi, v, f" {v:.2f}s", ha="center", va="bottom", fontsize=9)
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylabel("Mean response latency (s)")
    ax.set_title("Containment Response Latency by Enforcement Strategy")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(_fig_dir() / "response_time_by_action.png", dpi=130); plt.close(fig)


def fig_fpr_fcr_over_trials():
    raw = _res("raw_trial_results.csv").sort_values("trial")
    fig, ax = plt.subplots(figsize=(7.6, 4.2))
    x = raw["trial"].to_numpy()
    ax.plot(x, raw["fpr_pct"], "o-", color=_BLUE, label="False Positive Rate")
    ax.plot(x, raw["fcr_pct"], "s-", color=_GREEN, label="False Containment Rate")
    ax.set_xlabel("Monte Carlo trial"); ax.set_ylabel("Rate (%)")
    ax.set_title("Collateral-damage rates across trials")
    ax.legend(fontsize=9); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(_fig_dir() / "fpr_fcr_over_trials.png", dpi=130); plt.close(fig)


def fig_availability_timeline():
    try:
        tl = _res("availability_timeline.csv")
    except FileNotFoundError:
        return
    fig, ax = plt.subplots(figsize=(8, 4.4))
    ax.plot(tl.t_s, tl.availability_pct_mean, color=_BLUE, label="Network availability")
    ax.axhline(config.experiment()["operational_window"]["sla_threshold_pct"],
               ls="--", c="#d1495b", label="SLA threshold")
    for t in config.experiment()["operational_window"]["attack_start_times_s"]:
        ax.axvline(t, ls=":", c="#888", lw=1)
    ax.set_xlabel("Time (s)"); ax.set_ylabel("Availability (%)")
    ax.set_title("Network Service Availability over the 300 s window")
    ax.legend(fontsize=9); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(_fig_dir() / "availability_timeline.png", dpi=130); plt.close(fig)


def fig_feature_importance():
    fi = _res("feature_importance.csv")
    fig, ax = plt.subplots(figsize=(7.0, 4.0))
    x = np.arange(len(fi))
    ax.bar(x, fi.importance * 100, color=_BLUE, width=0.55)
    for xi, v in zip(x, fi.importance * 100):
        ax.text(xi, v, f" {v:.1f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels(fi.feature, fontsize=9)
    ax.set_ylabel("Importance (%)"); ax.set_title("Random Forest Feature Importance")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(_fig_dir() / "feature_importance.png", dpi=130); plt.close(fig)


def fig_confusion():
    m = json.loads((config.results_dir() / "rf_offline_metrics.json").read_text())
    c = m["confusion"]
    cm = np.array([[c["true_normal"], c["false_positive"]],
                   [c["false_negative"], c["true_attack"]]])
    fig, ax = plt.subplots(figsize=(4.6, 4.0))
    im = ax.imshow(cm, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{cm[i, j]}", ha="center", va="center",
                    color="white" if cm[i, j] > cm.max() / 2 else "black", fontsize=12)
    ax.set_xticks([0, 1]); ax.set_xticklabels(["pred normal", "pred attack"])
    ax.set_yticks([0, 1]); ax.set_yticklabels(["true normal", "true attack"])
    ax.set_title(f"RF offline confusion (acc={m['accuracy']*100:.2f}%)")
    fig.colorbar(im, fraction=0.046)
    fig.tight_layout(); fig.savefig(_fig_dir() / "confusion_matrix.png", dpi=130); plt.close(fig)


ALL = [
    fig_headline_metrics, fig_cr_by_vector, fig_response_time_by_action,
    fig_fpr_fcr_over_trials, fig_availability_timeline,
    fig_feature_importance, fig_confusion,
]


def make_all():
    made = []
    for fn in ALL:
        try:
            fn()
            made.append(fn.__name__)
        except Exception as e:  # pragma: no cover
            print(f"  [plots] {fn.__name__} skipped: {e}")
    print(f"[plots] wrote {len(made)} figures -> {_fig_dir()}")
    return made


if __name__ == "__main__":
    make_all()
