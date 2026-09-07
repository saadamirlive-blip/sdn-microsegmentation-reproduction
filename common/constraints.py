"""Operational constraints (Sec III.F) and the MOOP utility (Sec III.E).

Constraints (Eq 10-14):
    C1  TCAM capacity     : sum_k I(f_k on s_m) <= M_max      for all s_m
    C2  Containment lat.   : T_contain(h_i) <= 5.0 s
    C3  Controller CPU     : L_ctrl(t) <= 0.80
    C4  Critical SLA path  : C_k(t) = 3  for  f_k in F_critical   (see note)
    C5  Action domain      : C_k(t) in {0,1,2,3}

Controller load model (Eq 9):
    L_ctrl(t) = ( 0.246 + 0.00454 * N_rules(t) ) / L_max

MOOP (Eq 5-8):
    max Phi(C) = alpha*tau(C) - beta*fcr(C) + gamma*avail(C) - delta*lambda(C)
    with alpha+beta+gamma+delta = 1
      tau(C)   = |{f_k in F_malicious  : C_k >= 1}| / |F_malicious|  * 100     (Eq 6)
      fcr(C)   = |{f_k in F_legitimate : C_k >= 1}| / |F_legitimate| * 100     (Eq 7)
      avail(C) = sum_{u!=v} I(Path(u,v) operational) / (N(N-1))       * 100     (Eq 8)
      lambda   = L_ctrl(t)                                                     (Eq 9)

Note on C4 [ASSUMPTION -- ASSUMPTIONS.md #11]: the paper's Constraint 4 literally
reads C_k = 3 (BLOCK) for critical flows, which contradicts Algorithm 1 line 9
(critical flows -> meter rule, i.e. C_k = 1).  We follow Algorithm 1 (the
"complete operational execution") and read C4 as "critical flows always receive
a *definite* containment decision" rather than specifically a hard drop, so the
meter rule satisfies it.  ``check_c4`` is parameterised by ``critical_action``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable

from common import config

_C = config.experiment()["constraints"]
_MOOP = config.experiment()["moop"]

M_MAX = int(_C["tcam_capacity_Mmax"])                 # [PAPER-RANGE] 4000
T_CONTAIN_MAX = float(_C["containment_latency_max_s"])  # [PAPER] 5.0
L_CTRL_MAX = float(_C["controller_cpu_load_max"])     # [PAPER] 0.80
L_INTERCEPT = float(_C["lctrl_intercept"])            # [PAPER] 0.246
L_SLOPE = float(_C["lctrl_slope"])                    # [PAPER] 0.00454
L_MAX = float(_C["lctrl_Lmax"])                       # [ASSUMPTION] 1.0

ALPHA = float(_MOOP["alpha"]); BETA = float(_MOOP["beta"])
GAMMA = float(_MOOP["gamma"]); DELTA = float(_MOOP["delta"])
assert abs((ALPHA + BETA + GAMMA + DELTA) - 1.0) < 1e-9, "MOOP weights must sum to 1 (Eq 5)"


def controller_load(n_rules: int) -> float:
    """Eq 9 : L_ctrl(t) = (0.246 + 0.00454 * N_rules) / L_max."""
    return (L_INTERCEPT + L_SLOPE * max(0, int(n_rules))) / L_MAX


# --- constraint checks -------------------------------------------------------

def check_c1_tcam(rules_per_switch: Dict[str, int]) -> bool:
    return all(v <= M_MAX for v in rules_per_switch.values())


def check_c2_latency(contain_times_s: Iterable[float]) -> bool:
    return all(t <= T_CONTAIN_MAX for t in contain_times_s)


def check_c3_cpu(n_rules: int) -> bool:
    return controller_load(n_rules) <= L_CTRL_MAX


def check_c4_critical(critical_flow_actions: Iterable[int]) -> bool:
    # Algorithm-1 reading: every critical flow gets a definite (>=1) action.
    return all(int(a) >= 1 for a in critical_flow_actions)


def check_c5_domain(actions: Iterable[int]) -> bool:
    return all(int(a) in (0, 1, 2, 3) for a in actions)


# --- MOOP utility ----------------------------------------------------------

@dataclass
class MOOPTerms:
    tau: float        # containment rate  (%)   Eq 6
    fcr: float        # false containment (%)   Eq 7
    avail: float      # availability      (%)   Eq 8
    lam: float        # controller load   [0,1] Eq 9

    def utility(self) -> float:
        """Eq 5 (percent terms scaled to [0,1] before weighting)."""
        return (ALPHA * (self.tau / 100.0)
                - BETA * (self.fcr / 100.0)
                + GAMMA * (self.avail / 100.0)
                - DELTA * self.lam)


def moop_utility(tau_pct: float, fcr_pct: float, avail_pct: float, n_rules: int) -> MOOPTerms:
    return MOOPTerms(tau=tau_pct, fcr=fcr_pct, avail=avail_pct, lam=controller_load(n_rules))


PARAMS = {
    "M_max": M_MAX, "T_contain_max_s": T_CONTAIN_MAX, "L_ctrl_max": L_CTRL_MAX,
    "L_ctrl_intercept": L_INTERCEPT, "L_ctrl_slope": L_SLOPE, "L_max": L_MAX,
    "moop_alpha": ALPHA, "moop_beta": BETA, "moop_gamma": GAMMA, "moop_delta": DELTA,
}
