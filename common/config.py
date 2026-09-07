"""Load the three YAML configuration files and expose them as plain dicts.

The configs (``config/experiment.yaml``, ``config/topology.yaml``,
``config/ml_config.yaml``) are the single source of truth for every
experimental parameter.  Nothing in the code hard-codes a value that lives
in a config file.

Config sets
-----------
``SDN_CONFIG_SET`` (env var, default ``"paper"``) selects a variant:

  * ``paper``       -- the paper-faithful reproduction. Uses only the base
                       ``*.yaml`` files. This is the scientific reproduction and
                       is what ``results/`` was produced with.
  * ``calibrated``  -- a **fitted** model. Deep-merges the small overlay files
                       ``config/experiment.calibrated.yaml`` /
                       ``config/ml_config.calibrated.yaml`` (only the changed
                       keys) onto the base. This is NOT a reproduction -- it is a
                       deliberate calibration of the [ASSUMPTION] parameters so
                       the output lands on the paper's reported operating point.
                       See ``CALIBRATION.md``.

``run_experiment.py --config-set calibrated`` sets the env var for you.
"""
from __future__ import annotations

import copy
import functools
import os
from pathlib import Path
from typing import Any, Dict

import yaml

# project root = parent of this file's parent (common/ -> project/)
ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "config"

CONFIG_SET = os.environ.get("SDN_CONFIG_SET", "paper").strip() or "paper"


def _deep_merge(base: Dict[str, Any], overlay: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge ``overlay`` onto a copy of ``base`` (overlay wins)."""
    out = copy.deepcopy(base)
    for k, v in (overlay or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _read(name: str) -> Dict[str, Any]:
    with open(CONFIG_DIR / name, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_yaml(name: str) -> Dict[str, Any]:
    """Load ``name`` and, when a non-paper config set is active, deep-merge the
    matching ``<stem>.<set>.<ext>`` overlay if it exists."""
    data = _read(name)
    if CONFIG_SET != "paper":
        stem, ext = name.rsplit(".", 1)
        overlay_name = f"{stem}.{CONFIG_SET}.{ext}"
        if (CONFIG_DIR / overlay_name).exists():
            data = _deep_merge(data, _read(overlay_name))
    return data


@functools.lru_cache(maxsize=None)
def experiment() -> Dict[str, Any]:
    """Contents of ``config/experiment.yaml`` (+ overlay if a config set is active)."""
    return _load_yaml("experiment.yaml")


@functools.lru_cache(maxsize=None)
def topology() -> Dict[str, Any]:
    """Contents of ``config/topology.yaml``."""
    return _load_yaml("topology.yaml")


@functools.lru_cache(maxsize=None)
def ml() -> Dict[str, Any]:
    """Contents of ``config/ml_config.yaml`` (+ overlay if a config set is active)."""
    return _load_yaml("ml_config.yaml")


def config_set() -> str:
    return CONFIG_SET


def all_configs() -> Dict[str, Any]:
    return {"experiment": experiment(), "topology": topology(), "ml": ml()}


def results_dir() -> Path:
    # the calibrated set writes to results_calibrated/ so the paper-faithful
    # results/ is never overwritten.
    d = ROOT / experiment()["paths"]["results_dir"]
    if CONFIG_SET != "paper":
        d = ROOT / f'{experiment()["paths"]["results_dir"]}_{CONFIG_SET}'
    d.mkdir(parents=True, exist_ok=True)
    return d


def figures_dir() -> Path:
    d = ROOT / experiment()["paths"]["figures_dir"]
    if CONFIG_SET != "paper":
        d = ROOT / f'{experiment()["paths"]["figures_dir"]}_{CONFIG_SET}'
    d.mkdir(parents=True, exist_ok=True)
    return d


def model_dir() -> Path:
    d = results_dir() / "model"
    d.mkdir(parents=True, exist_ok=True)
    return d


def git_commit() -> str:
    """Best-effort current git commit hash (for experiment_metadata.json)."""
    try:
        import subprocess

        out = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return os.environ.get("GIT_COMMIT", "unknown")
