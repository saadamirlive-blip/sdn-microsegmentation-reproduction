"""CLI wrapper for the response-time bar chart (Fig 10). See plots/figures.py."""
from common import config
from plots.figures import fig_response_time

if __name__ == "__main__":
    fig_response_time()
    print(f"wrote {config.figures_dir() / 'fig10_response_time.png'}")
