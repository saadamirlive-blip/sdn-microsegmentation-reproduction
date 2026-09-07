"""CLI wrapper for the availability bar chart (Fig 12) + timeline (Fig 7). See plots/figures.py."""
from common import config
from plots.figures import fig_availability_bar, fig_availability_timeline

if __name__ == "__main__":
    fig_availability_bar()
    fig_availability_timeline()
    print(f"wrote {config.figures_dir() / 'fig12_availability.png'} and fig07_availability_timeline.png")
