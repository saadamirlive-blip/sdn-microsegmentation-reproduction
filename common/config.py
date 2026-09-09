"""Load the YAML configuration files and expose them as plain dicts.

``config/experiment.yaml``, ``config/topology.yaml`` and ``config/ml_config.yaml``
are the single source of truth for every experimental parameter. Nothing in the
code hard-codes a value that belongs in a config file, and nothing outside these
files is loaded at runtime.
"""
from __future__ import annotations

import functools
import os
from pathlib import Path
from typing import Any, Dict

import yaml

# project root = parent of this file's parent (common/ -> project/)
ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT / "config"


def _load_yaml(name: str) -> Dict[str, Any]:
    with open(CONFIG_DIR / name, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


@functools.lru_cache(maxsize=None)
def experiment() -> Dict[str, Any]:
    return _load_yaml("experiment.yaml")


@functools.lru_cache(maxsize=None)
def topology() -> Dict[str, Any]:
    return _load_yaml("topology.yaml")


@functools.lru_cache(maxsize=None)
def ml() -> Dict[str, Any]:
    return _load_yaml("ml_config.yaml")


def all_configs() -> Dict[str, Any]:
    return {"experiment": experiment(), "topology": topology(), "ml": ml()}


def results_dir() -> Path:
    d = ROOT / experiment()["paths"]["results_dir"]
    d.mkdir(parents=True, exist_ok=True)
    return d


def figures_dir() -> Path:
    d = ROOT / experiment()["paths"]["figures_dir"]
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
