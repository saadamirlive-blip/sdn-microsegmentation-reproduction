"""Ryu SDN controller package (Ubuntu 22.04 testbed).

  ryu_controller.py     -- the Ryu app (OF 1.3): L2 learning + 3.0 s telemetry
                           polling + DME closed loop
  telemetry.py          -- flow-stats polling / parsing
  feature_extraction.py -- raw stats -> 6-D vector  (re-exports common.features)
  risk_engine.py        -- Eq 4          (re-exports common.risk_engine)
  policy_engine.py      -- Algorithm 1   (re-exports common.policy_engine)
  openflow_rules.py     -- rule structs -> real OFPFlowMod / OFPMeterMod

The risk / policy logic is IDENTICAL to the pure-Python simulation because it is
the same `common/` code; only the data plane is real here.
"""
