"""Discrete-event system-level simulation of the closed-loop pipeline (Fig 5).

The simulation reproduces Phase 3 (runtime) of the paper's pipeline WITHOUT a
kernel data plane, so it runs on any OS:

    3.0 s telemetry poll  ->  6-D feature extraction  ->  Random Forest inference
      ->  host risk score R_i(t) (Eq 4)  ->  DMCA / Algorithm 1  ->  OpenFlow
      rule install (timed)  ->  containment outcome  ->  metric collection.

It applies the SAME ``common.policy_engine`` / ``common.risk_engine`` logic that
the real Ryu controller (``controller/ryu_controller.py``) applies on the
Mininet testbed -- only the data plane differs.

  system_sim.py    -- proposed Dynamic SDN trial
  baseline_sim.py  -- Traditional Firewall / IDS-IPS / Static SDN trials
"""
