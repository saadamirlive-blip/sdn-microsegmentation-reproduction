"""CLI wrapper for the CR bar chart (Fig 13). See plots/figures.py."""
from common import config
from plots.figures import fig_containment_rate

if __name__ == "__main__":
    fig_containment_rate()
    print(f"wrote {config.figures_dir() / 'fig13_containment_rate.png'}")
