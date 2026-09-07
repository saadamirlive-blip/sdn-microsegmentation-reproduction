"""Build ``results/reproduction_comparison.csv``  (task Sec 32).

Compares the MEASURED reproduction results against the values reported in the
paper, for:
  * the offline Random Forest classifier   (Table V, Table VI)
  * the proposed system's five metrics      (Table VIII)
  * every baseline's five metrics            (Table VIII)
  * the per-attack-vector containment rate  (Table VII)

Status rule (documented, not tuned):
  PASS         if |relative diff| <= 10%  AND  |absolute diff| <= abs_tol
  INVESTIGATE  otherwise
abs_tol: 1.5 percentage points for rate metrics, 0.6 s for T_resp.
"""
from __future__ import annotations

import json
from typing import List

import pandas as pd

from common import config

_ABS_TOL_PP = 1.5
_ABS_TOL_TRESP = 0.6
_REL_TOL = 0.10


def _status(paper: float, repro: float, is_latency: bool = False) -> str:
    if paper is None or repro != repro:  # nan
        return "N/A"
    adiff = abs(repro - paper)
    rdiff = adiff / abs(paper) if paper else float("inf")
    tol = _ABS_TOL_TRESP if is_latency else _ABS_TOL_PP
    return "PASS" if (rdiff <= _REL_TOL and adiff <= tol) else "INVESTIGATE"


def _row(metric, paper, repro, unit="%", is_latency=False, note=""):
    if paper is None:
        return None
    adiff = repro - paper
    rdiff = (adiff / paper * 100.0) if paper else float("nan")
    return {
        "metric": metric, "unit": unit,
        "paper_result": round(paper, 4), "reproduced_result": round(repro, 4),
        "absolute_difference": round(adiff, 4),
        "relative_difference_pct": round(rdiff, 2),
        "status": _status(paper, repro, is_latency),
        "explanation": note,
    }


def build_comparison() -> pd.DataFrame:
    rdir = config.results_dir()
    exp = config.experiment()
    mlc = config.ml()

    agg = pd.read_csv(rdir / "aggregate_results.csv").set_index("system")
    rf = json.loads((rdir / "rf_offline_metrics.json").read_text())
    try:
        cv = pd.read_csv(rdir / "containment_by_vector.csv")
    except FileNotFoundError:
        cv = None

    rows: List[dict] = []

    # ---- offline Random Forest (Table V / VI) ----------------------------
    po = mlc["paper_offline_results"]
    rows += [r for r in [
        _row("RF offline accuracy", po["accuracy"] * 100, rf["accuracy"] * 100,
             note="Table V; paper text also states 99.82% (Sec III.D) -- ASSUMPTIONS.md #14"),
        _row("RF offline attack precision", po["attack_precision"] * 100, rf["attack_precision"] * 100, note="Table V"),
        _row("RF offline recall", po["recall"] * 100, rf["recall"] * 100, note="Table V"),
        _row("RF offline ROC-AUC", po["roc_auc"], rf["roc_auc"], unit="", note="Table V"),
        _row("RF offline FPR", 0.20, rf["fpr_offline"] * 100,
             note="Table V (15/7500). Distinct from system-level FPR (Sec VI.B.7)"),
        _row("RF offline false positives (count)", po["confusion"]["false_positive"],
             rf["confusion"]["false_positive"], unit="flows", note="Table V"),
        _row("RF offline false negatives (count)", po["confusion"]["false_negative"],
             rf["confusion"]["false_negative"], unit="flows", note="Table V"),
    ] if r]

    # ---- proposed system five metrics (Table VIII) ---------------------
    pdd = exp["baselines"]["proposed_dynamic_sdn"]
    P = agg.loc["proposed_dynamic_sdn"]
    rows += [r for r in [
        _row("Proposed CR", pdd["paper_cr"] * 100, P["cr_pct_mean"],
             note="Table VIII / abstract (96.8%)"),
        _row("Proposed T_resp", pdd["paper_response_latency_s"], P["tresp_s_mean"],
             unit="s", is_latency=True,
             note="Table VIII (2.30s) -- MEASURED from per-flow timestamps, not hard-coded"),
        _row("Proposed FPR (system-level)", pdd["paper_fpr"] * 100, P["fpr_pct_mean"],
             note="Table VIII (1.2%) -- system-level, != 0.20% offline (Sec VI.B.7)"),
        _row("Proposed FCR", pdd["paper_fcr"] * 100, P["fcr_pct_mean"],
             note="Table VIII (1.5%)"),
        _row("Proposed NA", pdd["paper_na"] * 100, P["na_pct_mean"],
             note="Table VIII (98.5%)"),
    ] if r]

    # ---- baselines five metrics (Table VIII) -------------------------
    for sysname, key in [("traditional_firewall", "Traditional Firewall"),
                         ("ids_ips", "IDS/IPS"), ("static_sdn", "Static SDN")]:
        b = exp["baselines"][sysname]
        if sysname not in agg.index:
            continue
        B = agg.loc[sysname]
        rows += [r for r in [
            _row(f"{key} CR", b["paper_cr"] * 100, B["cr_pct_mean"],
                 note="Table VIII -- baseline mechanism model (ASSUMPTIONS.md #17)"),
            _row(f"{key} T_resp", b["response_latency_s"], B["tresp_s_mean"], unit="s", is_latency=True,
                 note="Table IV/VIII -- latency is a [PAPER] modelling assumption"),
            _row(f"{key} FPR", b["paper_fpr"] * 100, B["fpr_pct_mean"],
                 note="Table VIII -- baseline mechanism model"),
            _row(f"{key} FCR", b["paper_fcr"] * 100, B["fcr_pct_mean"],
                 note="Table VIII -- baseline mechanism model"),
            _row(f"{key} NA", b["paper_na"] * 100, B["na_pct_mean"],
                 note="Table VIII -- baseline mechanism model"),
        ] if r]

    # ---- per-vector CR (Table VII) ----------------------------------
    if cv is not None:
        av = exp["attack_vectors"]
        prop = cv[cv.system == "proposed_dynamic_sdn"]
        for _, cr_row in prop.iterrows():
            vec = cr_row["attack_vector"]
            if vec in av and isinstance(av[vec], dict) and "target_cr" in av[vec]:
                r = _row(f"CR[{vec}]", av[vec]["target_cr"] * 100, cr_row["cr_mean"],
                         note="Table VII")
                if r:
                    rows.append(r)

    df = pd.DataFrame(rows)
    df.to_csv(rdir / "reproduction_comparison.csv", index=False)
    return df


def main() -> None:
    df = build_comparison()
    with pd.option_context("display.max_rows", None, "display.width", 160,
                           "display.max_colwidth", 40):
        print(df.to_string(index=False))
    n_pass = int((df.status == "PASS").sum())
    n_inv = int((df.status == "INVESTIGATE").sum())
    print(f"\n{n_pass} PASS / {n_inv} INVESTIGATE / {len(df)} rows")
    print(f"written -> {config.results_dir() / 'reproduction_comparison.csv'}")


if __name__ == "__main__":
    main()
