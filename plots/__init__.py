"""Figure generation from measured results (task Sec 24).

All figures are drawn from ``results/*.csv`` produced by the experiment.
The paper's reported comparison values are overlaid as reference markers only
(never used as the plotted data).

  figures.py           -- all figure functions
  containment_rate.py  response_time.py  collateral_damage.py  availability.py
                       -- thin CLI wrappers (task Sec 25 layout)
  make_all.py          -- regenerate every figure
"""
