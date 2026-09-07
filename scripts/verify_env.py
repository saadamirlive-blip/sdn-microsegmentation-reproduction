"""Environment verification (task Sec 28 step 1-2).

Checks the Python packages needed by the REFERENCE SIMULATION against the
paper's pinned versions.  Warns (does not fail) on a mismatch so the pipeline
can still run on a newer stack, but records the delta for the metadata.

The Mininet / OVS / Ryu / hping3 stack is NOT checked here -- that belongs to
the Ubuntu testbed; see testbed/README and Dockerfile.
"""
from __future__ import annotations

import importlib
import sys

from common import config

PINS = {  # module -> paper-specified version
    "numpy": "1.24.3",
    "pandas": "2.0.1",
    "sklearn": "1.2.2",
    "scipy": None,          # not pinned by the paper
    "matplotlib": None,
    "joblib": None,
    "yaml": None,
}


def main() -> int:
    exp = config.experiment()
    print("Reproduction-host environment check")
    print("=" * 50)
    print(f"python running : {sys.version.split()[0]}   (paper: {exp['environment']['python']})")

    mismatch = 0
    for mod, pin in PINS.items():
        try:
            m = importlib.import_module(mod)
            ver = getattr(m, "__version__", "?")
        except Exception:
            print(f"  {mod:12s} MISSING")
            mismatch += 1
            continue
        tag = "ok"
        if pin and ver != pin:
            tag = f"MISMATCH (paper pins {pin})"
            mismatch += 1
        elif pin:
            tag = "== paper pin"
        print(f"  {mod:12s} {ver:12s} {tag}")

    print("-" * 50)
    if mismatch:
        print(f"{mismatch} package(s) differ from the paper pins.")
        print("This is acceptable for the pure-Python simulation but is recorded")
        print("in results/experiment_metadata.json. For an exact match use the")
        print("provided environment.yml / requirements.txt on Python 3.10.")
    else:
        print("All checked packages match the paper's specification.")
    # never hard-fail: return 0 so run_experiment.py can proceed
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
