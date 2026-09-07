"""All figure functions.  Each reads results/*.csv and writes figures/<name>.png.

Paper reference values are overlaid as hollow markers / dashed lines and are
NEVER the plotted series.
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

_SYS_ORDER = ["traditional_firewall", "ids_ips", "static_sdn", "proposed_dynamic_sdn"]
_SYS_LABEL = {
    "traditional_firewall": "Traditional\nFirewall",
    "ids_ips": "IDS/IPS",
    "static_sdn": "Static SDN",
    "proposed_dynamic_sdn": "Proposed SDN\n(ML + Dynamic)",
}
_PAPER = {  # Table VIII / Fig 10-14  (reference overlays only)
    "cr":    {"traditional_firewall": 72.0, "ids_ips": 78.5, "static_sdn": 85.0, "proposed_dynamic_sdn": 96.8},
    "tresp": {"traditional_firewall": 45.0, "ids_ips": 30.0, "static_sdn": 15.0, "proposed_dynamic_sdn": 2.30},
    "fpr":   {"traditional_firewall": 12.0, "ids_ips": 8.5,  "static_sdn": 5.0,  "proposed_dynamic_sdn": 1.2},
    "fcr":   {"traditional_firewall": 10.0, "ids_ips": 6.5,  "static_sdn": 4.0,  "proposed_dynamic_sdn": 1.5},
    "na":    {"traditional_firewall": 88.0, "ids_ips": 91.0, "static_sdn": 94.0, "proposed_dynamic_sdn": 98.5},
}
_PAPER_VEC_CR = {"icmp_flood": 99.0, "syn_flood": 98.0, "udp_flood": 97.0,
                 "mixed_ddos": 94.0, "slowloris": 92.0, "http_flood": 90.0}


def _fig_dir() -> Path:
    return config.figures_dir()


def _res(name: str) -> pd.DataFrame:
    return pd.read_csv(config.results_dir() / name)


def _agg():
    return _res("aggregate_results.csv").set_index("system")


def _bar(metric_key: str, col: str, title: str, ylabel: str, fname: str, paper_key: str):
    agg = _agg()
    xs = [s for s in _SYS_ORDER if s in agg.index]
    vals = [agg.loc[s, f"{col}_mean"] for s in xs]
    errs = [agg.loc[s, f"{col}_std"] for s in xs]
    paper = [_PAPER[paper_key][s] for s in xs]

    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    x = np.arange(len(xs))
    bars = ax.bar(x, vals, yerr=errs, capsize=4, color="#3b7dd8", width=0.55,
                  label="Reproduced (mean +/- std, 10 trials)")
    ax.plot(x, paper, "D", ms=9, mfc="none", mec="#d1495b", mew=2, label="Paper (Table VIII)")
    for xi, v in zip(x, vals):
        ax.text(xi, v, f" {v:.2f}", ha="center", va="bottom", fontsize=9)
    ax.set_xticks(x); ax.set_xticklabels([_SYS_LABEL[s] for s in xs], fontsize=9)
    ax.set_ylabel(ylabel); ax.set_title(title)
    ax.legend(fontsize=8, loc="best"); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(_fig_dir() / fname, dpi=130); plt.close(fig)


def fig_containment_rate():
    _bar("cr", "cr_pct", "Threat Containment Rate (CR) -- reproduced vs paper",
         "Containment Rate (%)", "fig13_containment_rate.png", "cr")


def fig_response_time():
    _bar("tresp", "tresp_s", "Average Response Time (T_resp) -- reproduced vs paper",
         "Response Time (s)", "fig10_response_time.png", "tresp")


def fig_collateral_damage():
    """FPR + FCR grouped bar (Fig 11)."""
    agg = _agg()
    xs = [s for s in _SYS_ORDER if s in agg.index]
    fpr = [agg.loc[s, "fpr_pct_mean"] for s in xs]
    fcr = [agg.loc[s, "fcr_pct_mean"] for s in xs]
    fig, ax = plt.subplots(figsize=(7.6, 4.4))
    x = np.arange(len(xs)); w = 0.35
    ax.bar(x - w / 2, fpr, w, label="FPR (reproduced)", color="#3b7dd8")
    ax.bar(x + w / 2, fcr, w, label="FCR (reproduced)", color="#8bbf5b")
    ax.plot(x - w / 2, [_PAPER["fpr"][s] for s in xs], "D", ms=8, mfc="none", mec="#d1495b", mew=2, label="FPR (paper)")
    ax.plot(x + w / 2, [_PAPER["fcr"][s] for s in xs], "s", ms=8, mfc="none", mec="#8a5a00", mew=2, label="FCR (paper)")
    ax.set_xticks(x); ax.set_xticklabels([_SYS_LABEL[s] for s in xs], fontsize=9)
    ax.set_ylabel("Rate (%)"); ax.set_title("False Positive Rate & False Containment Rate (Fig 11)")
    ax.legend(fontsize=8); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(_fig_dir() / "fig11_fpr_fcr.png", dpi=130); plt.close(fig)


def fig_availability_bar():
    _bar("na", "na_pct", "Network Service Availability under attack (Fig 12)",
         "Availability (%)", "fig12_availability.png", "na")


def fig_availability_timeline():
    """Fig 7 -- NA over the 300 s window."""
    try:
        tl = _res("availability_timeline.csv")
    except FileNotFoundError:
        return
    fig, ax = plt.subplots(figsize=(8, 4.4))
    for s in _SYS_ORDER:
        d = tl[tl.system == s]
        if d.empty:
            continue
        ax.plot(d.t_s, d.availability_pct_mean, label=_SYS_LABEL[s].replace("\n", " "))
    ax.axhline(95.0, ls="--", c="#d1495b", label="95% SLA")
    for t in config.experiment()["operational_window"]["attack_start_times_s"]:
        ax.axvline(t, ls=":", c="#888", lw=1)
    ax.set_xlabel("Time (s)"); ax.set_ylabel("Availability (%)")
    ax.set_title("Network Availability Timeline (5-min window) -- Fig 7")
    ax.legend(fontsize=8); ax.grid(alpha=0.3)
    fig.tight_layout(); fig.savefig(_fig_dir() / "fig07_availability_timeline.png", dpi=130); plt.close(fig)


def fig_cr_by_vector():
    """Fig 8 -- CR by attack vector, proposed system."""
    cv = _res("containment_by_vector.csv")
    d = cv[cv.system == "proposed_dynamic_sdn"]
    d = d[d.attack_vector.isin(_PAPER_VEC_CR)]
    order = list(_PAPER_VEC_CR)
    d = d.set_index("attack_vector").reindex(order).reset_index()
    fig, ax = plt.subplots(figsize=(7.6, 4.2))
    x = np.arange(len(order))
    ax.bar(x, d.cr_mean, yerr=d.cr_std, capsize=4, color="#3b7dd8", width=0.55, label="Reproduced")
    ax.plot(x, [_PAPER_VEC_CR[v] for v in order], "D", ms=9, mfc="none", mec="#d1495b", mew=2, label="Paper (Table VII)")
    for xi, v in zip(x, d.cr_mean):
        ax.text(xi, v, f" {v:.1f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels([v.replace("_", "\n") for v in order], fontsize=8)
    ax.set_ylabel("Containment Rate (%)"); ax.set_ylim(80, 102)
    ax.set_title("Containment Rate by Attack Vector (Fig 8 / Table VII)")
    ax.legend(fontsize=8); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(_fig_dir() / "fig08_cr_by_vector.png", dpi=130); plt.close(fig)


def fig_radar():
    """Fig 14 -- multi-metric radar."""
    agg = _agg()
    axes_lbl = ["Containment\nRate", "Response\nSpeed", "Low FP\nRate", "Low FC\nRate", "Availability"]

    def norm(s):
        cr = agg.loc[s, "cr_pct_mean"]
        speed = 100.0 * (1 - min(agg.loc[s, "tresp_s_mean"], 45.0) / 45.0)
        lowfp = 100.0 - min(agg.loc[s, "fpr_pct_mean"], 100.0)
        lowfc = 100.0 - min(agg.loc[s, "fcr_pct_mean"], 100.0)
        na = agg.loc[s, "na_pct_mean"]
        return [cr, speed, lowfp, lowfc, na]

    ang = np.linspace(0, 2 * np.pi, len(axes_lbl), endpoint=False).tolist()
    ang += ang[:1]
    fig, ax = plt.subplots(figsize=(6.2, 6.2), subplot_kw=dict(polar=True))
    for s in _SYS_ORDER:
        if s not in agg.index:
            continue
        vals = norm(s); vals += vals[:1]
        ax.plot(ang, vals, label=_SYS_LABEL[s].replace("\n", " "))
        ax.fill(ang, vals, alpha=0.08)
    ax.set_xticks(ang[:-1]); ax.set_xticklabels(axes_lbl, fontsize=8)
    ax.set_ylim(0, 100)
    ax.set_title("Multi-Metric Performance Radar (Fig 14)")
    ax.legend(loc="lower right", bbox_to_anchor=(1.25, -0.1), fontsize=8)
    fig.tight_layout(); fig.savefig(_fig_dir() / "fig14_radar.png", dpi=130); plt.close(fig)


def fig_feature_importance():
    fi = _res("feature_importance.csv")
    fig, ax = plt.subplots(figsize=(7.2, 4.2))
    x = np.arange(len(fi)); w = 0.38
    ax.bar(x - w / 2, fi.importance_reproduced * 100, w, label="Reproduced", color="#3b7dd8")
    ax.bar(x + w / 2, fi.importance_paper * 100, w, label="Paper (Table VI)", color="#c9c9c9")
    ax.set_xticks(x); ax.set_xticklabels(fi.feature, fontsize=9)
    ax.set_ylabel("Importance (%)"); ax.set_title("Random Forest Feature Importance (Table VI)")
    ax.legend(fontsize=8); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(_fig_dir() / "fig_feature_importance.png", dpi=130); plt.close(fig)


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
    fig.tight_layout(); fig.savefig(_fig_dir() / "fig05_confusion_matrix.png", dpi=130); plt.close(fig)


def fig_reproduction_gap():
    """Reproduced vs paper for the 5 headline proposed-system metrics."""
    try:
        cmp = _res("reproduction_comparison.csv")
    except FileNotFoundError:
        return
    keys = ["Proposed CR", "Proposed T_resp", "Proposed FPR (system-level)",
            "Proposed FCR", "Proposed NA"]
    d = cmp[cmp.metric.isin(keys)].set_index("metric").reindex(keys).reset_index()
    fig, ax = plt.subplots(figsize=(8, 4.2))
    x = np.arange(len(d)); w = 0.38
    ax.bar(x - w / 2, d.paper_result, w, label="Paper", color="#c9c9c9")
    ax.bar(x + w / 2, d.reproduced_result, w, label="Reproduced", color="#3b7dd8")
    for xi, p, r in zip(x, d.paper_result, d.reproduced_result):
        ax.text(xi - w / 2, p, f"{p:g}", ha="center", va="bottom", fontsize=8)
        ax.text(xi + w / 2, r, f"{r:.2f}", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels([k.replace("Proposed ", "") for k in keys], fontsize=9)
    ax.set_title("Proposed Dynamic SDN -- reproduced vs paper (Table VIII)")
    ax.legend(fontsize=8); ax.grid(axis="y", alpha=0.3)
    fig.tight_layout(); fig.savefig(_fig_dir() / "fig_reproduction_gap.png", dpi=130); plt.close(fig)


ALL = [
    fig_containment_rate, fig_response_time, fig_collateral_damage,
    fig_availability_bar, fig_availability_timeline, fig_cr_by_vector,
    fig_radar, fig_feature_importance, fig_confusion, fig_reproduction_gap,
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
