"""Discrete-event system-level model of the closed-loop pipeline.

Runs Phase 3 (runtime) without a kernel data plane, so it works on any OS:

    3.0 s telemetry poll  ->  6-D feature extraction  ->  Random Forest inference
      ->  host risk score R_i(t)  ->  DMCA / Algorithm 1  ->  OpenFlow rule
      install (timed)  ->  containment outcome  ->  metric collection.

It applies the SAME ``common.policy_engine`` / ``common.risk_engine`` logic the
real Ryu controller (``controller/ryu_controller.py``) applies on the Mininet
testbed -- only the data plane differs.

  system_sim.py  -- one proposed-system Monte Carlo trial
"""
