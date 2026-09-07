"""Per-flow and per-path outcome records shared by the simulation and metrics."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FlowOutcome:
    """The measured fate of one flow across the operational window."""
    flow_id: str
    label: str                     # "benign" | "attack"
    scenario: str                  # "benign" | "syn_flood" | ... | "horizontal_probe"
    src_host: str
    dst_host: str

    predicted_malicious: bool      # Random Forest prediction (P_attack >= 0.5)
    p_attack: float
    risk_score: float              # R_i(t)  (Eq 4), 0..100
    compromised: bool              # R_i(t) >= risk

    action: str                    # "MONITOR" | "RATE_LIMIT" | "QUARANTINE" | "BLOCK"
    contained: bool                # action != MONITOR

    init_time_s: float
    lifetime_s: float
    rule_installed_time_s: Optional[float] = None   # absolute sim time
    resp_latency_s: Optional[float] = None          # rule_installed - init  (measured)
    mitigated: bool = False        # contained AND installed within lifetime AND enforcing

    is_service_call: bool = False
    is_critical: bool = False
    is_lateral: bool = False
    collateral: bool = False       # benign flow that was contained
    trial: int = -1
    system: str = "proposed_dynamic_sdn"


@dataclass
class PathAvailabilitySample:
    """Operational-path count at one telemetry tick (for the NA metric)."""
    t_s: float
    operational_paths: int
    total_paths: int               # N(N-1) = 156
    under_attack: bool


@dataclass
class TrialRecords:
    trial: int
    system: str
    flows: List[FlowOutcome] = field(default_factory=list)
    availability: List[PathAvailabilitySample] = field(default_factory=list)
    n_rules_total: int = 0                 # cumulative rules installed over the window (TCAM / logging)
    peak_concurrent_rules: int = 0         # max rules active in a single 3.0 s poll -> Eq 9 N_rules(t)
    mean_concurrent_rules: float = 0.0
    rules_per_switch: dict = field(default_factory=dict)
    seed: int = -1
