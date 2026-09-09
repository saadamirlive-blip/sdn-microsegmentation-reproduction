"""Deterministic seeding.

Paper (Sec IV.D, Sec IV.G):
  * ``random_state=42`` is enforced for the Random Forest and the train/test split.
  * "All software scripts ... were version-controlled under fixed random seeds
     to ensure full experimental reproducibility."

The paper names only ``random_state=42``.  It does NOT state a per-trial seed
policy for the 10 Monte Carlo runs.  :
  trial t (t = 0 .. 9)  ->  seed = trial_seed_base + t   (i.e. 42, 43, ... 51).

Every stochastic component (numpy, Python ``random``, and any per-trial RNG)
is seeded from this single integer so a trial is byte-for-byte reproducible.
"""
from __future__ import annotations

import os
import random
from dataclasses import dataclass

import numpy as np

from common import config


@dataclass(frozen=True)
class SeedBundle:
    """All seeds derived for one execution context."""
    master: int          # the integer everything is derived from
    numpy: int
    python: int
    sklearn_random_state: int   # always 42 (paper-fixed) unless explicitly overridden

    def make_rng(self) -> np.random.Generator:
        return np.random.default_rng(self.master)


def global_seed(master: int) -> SeedBundle:
    """Seed the process-global RNGs (numpy legacy + Python ``random``)."""
    exp = config.experiment()
    fixed_rs = int(exp["seeds"]["random_state"])          # 42
    random.seed(master)
    np.random.seed(master & 0xFFFFFFFF)
    os.environ["PYTHONHASHSEED"] = str(master)
    return SeedBundle(
        master=master,
        numpy=master & 0xFFFFFFFF,
        python=master,
        sklearn_random_state=fixed_rs,
    )


def dataset_seed() -> SeedBundle:
    """Seed for the one-off 50,000-sample dataset build (Phase 1)."""
    exp = config.experiment()
    return global_seed(int(exp["seeds"]["numpy_seed"]))   # == 42


def trial_seed(trial_index: int) -> SeedBundle:
    """Seed for Monte Carlo trial ``trial_index`` (0-based)."""
    exp = config.experiment()
    policy = exp["seeds"]["trial_seed_policy"]
    base = int(exp["seeds"]["trial_seed_base"])
    if policy == "base_plus_index":
        master = base + int(trial_index)                  # MODELING_NOTES.md #12
    else:  # pragma: no cover - only one policy defined
        raise ValueError(f"unknown trial_seed_policy: {policy!r}")
    return global_seed(master)
