"""Write results/experiment_metadata.json -- a complete record of the parameters
and environment this experiment ran with, so a run is reproducible."""
from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone

from common import config, constraints
from common.openflow_rules import CONSTANTS as OF_CONSTANTS
from common.policy_engine import POLICY_CONSTANTS
from common.risk_engine import PARAMS as RISK_PARAMS


def _pkg_versions() -> dict:
    out = {}
    for mod in ["numpy", "pandas", "sklearn", "scipy", "matplotlib", "joblib", "yaml"]:
        try:
            m = __import__(mod)
            out[mod] = getattr(m, "__version__", "unknown")
        except Exception:
            out[mod] = "not installed"
    return out


def build() -> dict:
    exp = config.experiment()
    ml = config.ml()
    env = exp["environment"]
    used = _pkg_versions()

    return {
        "project": exp["meta"]["project"],
        "pipeline": exp["meta"]["pipeline"],
        "experiment_date_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": config.git_commit(),

        "environment_target": env,
        "environment_actual": {
            "os": platform.platform(),
            "python": sys.version.split()[0],
            "packages": used,
            "matches_target_pins": all([
                used.get("numpy") == env["numpy"],
                used.get("pandas") == env["pandas"],
                used.get("sklearn") == env["scikit_learn"],
            ]),
        },

        "seeds": exp["seeds"],
        "telemetry_polling_interval_s": exp["telemetry"]["polling_interval_s"],
        "dataset": exp["dataset"],
        "ml_hyperparameters": ml["model"]["hyperparameters"],
        "monte_carlo": exp["monte_carlo"],
        "benign_traffic": exp["benign_traffic"],
        "attack_traffic": exp["attack_traffic"],
        "attack_vectors": exp["attack_vectors"],
        "operational_window": exp["operational_window"],
        "runtime_traffic": exp["runtime_traffic"],
        "availability_model": exp["availability"],

        "risk_engine_params": RISK_PARAMS,
        "policy_constants": POLICY_CONSTANTS,
        "openflow_constants": OF_CONSTANTS,
        "constraint_params": constraints.PARAMS,
        "moop_weights": exp["moop"],
    }


def main() -> None:
    meta = build()
    out = config.results_dir() / "experiment_metadata.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    print(f"[make_metadata] wrote {out}")


if __name__ == "__main__":
    main()
