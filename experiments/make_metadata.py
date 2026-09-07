"""Write results/experiment_metadata.json  (task Sec 29) and
results/reproducibility_environment.json (paper-specified vs actually-used)."""
from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone

from common import config, constraints
from common.policy_engine import POLICY_CONSTANTS
from common.openflow_rules import CONSTANTS as OF_CONSTANTS
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

    meta = {
        "paper": {
            "title": exp["meta"]["paper_title"],
            "author": exp["meta"]["paper_author"],
            "file": exp["meta"]["paper_file"],
        },
        "experiment_date_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": config.git_commit(),
        "config_set": config.config_set(),
        "reproduction_task": ("reproduction (not a redesign)" if config.config_set() == "paper"
                              else "CALIBRATED FIT -- not a reproduction (see CALIBRATION.md)"),

        "environment_paper_specified": {
            "operating_system": env["operating_system"],
            "linux_kernel": env["linux_kernel"],
            "python": env["python"],
            "mininet": env["mininet"],
            "open_vswitch": env["open_vswitch"],
            "ryu": f'{env["ryu"]}  [ASSUMPTION -- paper says only "Ryu SDN Framework (Python 3.10)"]',
            "openflow": env["openflow"],
            "scikit_learn": env["scikit_learn"],
            "numpy": env["numpy"],
            "pandas": env["pandas"],
            "scapy": env["scapy"],
            "traffic_tools": env["traffic_tools"],
        },
        "environment_actually_used_on_repro_host": {
            "note": "The Mininet/OVS/Ryu/Scapy/hping3 data-plane stack runs ONLY "
                    "on the Ubuntu 22.04 testbed (testbed/). The pure-Python "
                    "reference simulation that produced results/ ran here:",
            "os": platform.platform(),
            "python": sys.version.split()[0],
            "packages": used,
            "matches_paper_pins": all([
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

        "risk_engine_params": RISK_PARAMS,
        "policy_constants": POLICY_CONSTANTS,
        "openflow_constants": OF_CONSTANTS,
        "constraint_params": constraints.PARAMS,
        "moop_weights": exp["moop"],

        "baseline_latencies_s_paper": {
            k: v["response_latency_s"] for k, v in exp["baselines"].items()
            if v.get("response_latency_s") is not None
        },
    }
    return meta


def main() -> None:
    meta = build()
    out = config.results_dir() / "experiment_metadata.json"
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)
    print(f"[make_metadata] wrote {out}")


if __name__ == "__main__":
    main()
