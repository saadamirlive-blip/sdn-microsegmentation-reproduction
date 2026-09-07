"""The five performance-evaluation metrics (Sec IV.F).

  containment.py       -> Threat Containment Rate  (CR %)   -- Eq/def IV.F.1
  latency.py           -> Containment Response Latency (T_resp s) -- IV.F.2
  false_positive.py    -> False Positive Rate  (FPR %)      -- IV.F.3
  false_containment.py -> False Containment Rate (FCR %)    -- IV.F.4
  availability.py      -> Network Service Availability (NA %) -- IV.F.5

Each takes measured per-flow / per-path simulation records and returns a number.
None of them takes a paper result as an input.
"""
