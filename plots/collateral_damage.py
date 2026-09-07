"""CLI wrapper for the FPR/FCR collateral-damage chart (Fig 11). See plots/figures.py."""
from common import config
from plots.figures import fig_collateral_damage

if __name__ == "__main__":
    fig_collateral_damage()
    print(f"wrote {config.figures_dir() / 'fig11_fpr_fcr.png'}")
