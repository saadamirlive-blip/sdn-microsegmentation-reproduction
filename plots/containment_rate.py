"""CLI wrapper -- see plots/figures.py:fig_containment_rate (task Sec 25 layout)."""
from plots.figures import fig_containment_rate as _f, fig_availability_timeline as _tl

if __name__ == "__main__":
    _f()
    if "containment_rate" == "availability":
        _tl()
