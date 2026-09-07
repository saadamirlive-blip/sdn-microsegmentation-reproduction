"""Phase 1 -- Dataset Generation & 6-D Feature Engineering  (Sec III.D, Sec IV.D).

Produces the 50,000-row offline telemetry dataset:
    25,000 benign  +  25,000 malicious
    malicious split across the 6 attack vectors by their Table VII traffic shares
    columns: pps, bps, duration, tcp_ratio, udp_ratio, icmp_ratio, label, scenario

What is [PAPER]:
    * 50,000 total / 25,000 / 25,000 balance          (Sec IV.D, Eq 3)
    * benign  pps ~ N(0.2, 0.05),  bps ~ N(0.1, 0.02) (Sec IV.C.1)
    * attack  pps ~ N(3.0, 0.5),   bps ~ N(1.5, 0.3)  (Sec IV.C.2)
    * 6-D feature order                                (Eq 3)
    * per-vector traffic shares                        (Table VII)
    * random_state = 42                               (Sec IV.D)

What is [ASSUMPTION]  (ASSUMPTIONS.md #6) -- FROZEN in config/ml_config.yaml,
NOT tuned:  the duration / protocol-ratio distributions, the benign burst
mixture (Sec VI.B.7 mechanism), the low-rate stealth fraction (Sec VI.B.4),
and a ~1% telemetry jitter.

The per-class feature distributions live in ``traffic/flow_sampler.py`` and are
shared with the online simulation traffic so the Random Forest always sees
in-distribution data at runtime.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

import numpy as np
import pandas as pd

from common import config
from common.seeding import dataset_seed
from traffic.flow_sampler import FEATURES, sample_attack, sample_benign

_SHARES: Dict[str, float] = config.ml()["malicious_sample_shares"]


def _block(sample: Dict[str, np.ndarray], label: int, scenario: str) -> pd.DataFrame:
    df = pd.DataFrame({k: sample[k] for k in FEATURES})
    df["label"] = label
    df["scenario"] = scenario
    return df


def _split_counts(total: int, shares: Dict[str, float]) -> Dict[str, int]:
    """Largest-remainder apportionment so per-vector counts sum EXACTLY to total."""
    raw = {k: total * v for k, v in shares.items()}
    base = {k: int(np.floor(x)) for k, x in raw.items()}
    rem = total - sum(base.values())
    order = sorted(shares, key=lambda k: raw[k] - base[k], reverse=True)
    for i in range(rem):
        base[order[i % len(order)]] += 1
    return base


def build_dataset() -> pd.DataFrame:
    """Return the deterministic 50,000-row dataframe (seed 42)."""
    exp = config.experiment()["dataset"]
    total = int(exp["total_samples"])            # [PAPER] 50000
    n_benign = int(exp["benign_samples"])        # [PAPER] 25000
    n_mal = int(exp["malicious_samples"])        # [PAPER] 25000
    assert n_benign + n_mal == total

    bundle = dataset_seed()                       # seed 42
    rng = np.random.default_rng(bundle.master)

    blocks: List[pd.DataFrame] = [_block(sample_benign(rng, n_benign), 0, "benign")]
    for vec, cnt in _split_counts(n_mal, _SHARES).items():
        blocks.append(_block(sample_attack(rng, vec, cnt), 1, vec))

    df = pd.concat(blocks, ignore_index=True)
    df = df.sample(frac=1.0, random_state=bundle.master).reset_index(drop=True)
    df = df[FEATURES + ["label", "scenario"]]

    assert len(df) == total, (len(df), total)
    assert int((df.label == 0).sum()) == n_benign
    assert int((df.label == 1).sum()) == n_mal
    return df


@dataclass
class DatasetSummary:
    n_total: int
    n_benign: int
    n_malicious: int
    per_scenario: Dict[str, int]


def summarize(df: pd.DataFrame) -> DatasetSummary:
    return DatasetSummary(
        n_total=len(df),
        n_benign=int((df.label == 0).sum()),
        n_malicious=int((df.label == 1).sum()),
        per_scenario={k: int(v) for k, v in df.scenario.value_counts().sort_index().items()},
    )


def main() -> None:
    df = build_dataset()
    out = config.results_dir() / "dataset_50k.csv"
    df.to_csv(out, index=False)
    s = summarize(df)
    print(f"[dataset_builder] wrote {out}")
    print(f"  total={s.n_total}  benign={s.n_benign}  malicious={s.n_malicious}")
    for k, v in s.per_scenario.items():
        print(f"  {k:18s} {v}")


if __name__ == "__main__":
    main()
