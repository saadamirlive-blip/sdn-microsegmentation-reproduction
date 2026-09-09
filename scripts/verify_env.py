"""Environment verification (step 1 of run_experiment.py).

Checks the Python packages used by the experiment against the versions declared
in config/experiment.yaml. A mismatch WARNS (does not fail) so the pipeline can
still run on a newer stack; the delta is recorded in experiment_metadata.json.

The Mininet / OVS / Ryu / hping3 data-plane stack is not checked here -- that
belongs to the Ubuntu testbed (scripts/run_testbed.sh, Dockerfile).
"""
from __future__ import annotations

import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from common import config  # noqa: E402

# module import name -> key in config experiment.environment (None = not pinned)
_KEYS = {
    "numpy": "numpy",
    "pandas": "pandas",
    "sklearn": "scikit_learn",
    "scipy": None,
    "matplotlib": None,
    "joblib": None,
    "yaml": None,
}


def main() -> int:
    env = config.experiment()["environment"]
    print("Environment check")
    print("=" * 50)
    print(f"python running : {sys.version.split()[0]}   (target: {env['python']})")

    mismatch = 0
    for mod, key in _KEYS.items():
        pin = env.get(key) if key else None
        try:
            m = importlib.import_module(mod)
            ver = getattr(m, "__version__", "?")
        except Exception:
            print(f"  {mod:12s} MISSING")
            mismatch += 1
            continue
        if pin and ver != pin:
            print(f"  {mod:12s} {ver:12s} MISMATCH (target {pin})")
            mismatch += 1
        elif pin:
            print(f"  {mod:12s} {ver:12s} == target")
        else:
            print(f"  {mod:12s} {ver:12s} ok")

    print("-" * 50)
    if mismatch:
        print(f"{mismatch} package(s) differ from the target versions.")
        print("This is acceptable; the delta is recorded in experiment_metadata.json.")
        print("For an exact match, use requirements.txt / environment.yml on Python 3.10.")
    else:
        print("All checked packages match the target versions.")
    return 0  # never hard-fail


if __name__ == "__main__":
    raise SystemExit(main())
