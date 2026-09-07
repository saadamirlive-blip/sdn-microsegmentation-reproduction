"""CLI wrapper -- see plots/figures.py:fig_collateral_damage (task Sec 25 layout)."""
from plots.figures import fig_collateral_damage as _f, fig_availability_timeline as _tl

if __name__ == "__main__":
    _f()
    if "collateral_damage" == "availability":
        _tl()
