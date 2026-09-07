"""CLI wrapper -- see plots/figures.py:fig_response_time (task Sec 25 layout)."""
from plots.figures import fig_response_time as _f, fig_availability_timeline as _tl

if __name__ == "__main__":
    _f()
    if "response_time" == "availability":
        _tl()
