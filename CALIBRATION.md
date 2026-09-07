# CALIBRATION.md — the `calibrated` config set

> **This is not a reproduction. It is a fit.**
>
> The `paper` config set (default, `results/`) is the scientific reconstruction:
> every unspecified value is a documented `[ASSUMPTION]` set once from the paper's
> qualitative text and **never adjusted toward the reported numbers**
> (`ASSUMPTIONS.md`, `RESULTS.md`).
>
> The `calibrated` config set (`results_calibrated/`) deliberately **tunes those
> same `[ASSUMPTION]` parameters** until the system-level output sits on the
> paper's reported operating point (Table VII / VIII). It answers the question
> *"what would the free parameters have to be for this model to match the
> paper?"* — it does **not** add evidence that the paper's numbers are correct.

## How to run it

```bash
python run_experiment.py --config-set calibrated       # -> results_calibrated/ + figures_calibrated/
# or
SDN_CONFIG_SET=calibrated python -m experiments.run_all_trials
```

The two sets never overwrite each other. `results_calibrated/reproduction_comparison.csv`
still compares against the **paper's** values (the `paper_*` reference keys are
inherited unchanged).

## Mechanism

`common/config.py` deep-merges two small overlay files onto the base config when
`SDN_CONFIG_SET != "paper"`:

| Overlay | Merged onto |
|---|---|
| `config/experiment.calibrated.yaml` | `config/experiment.yaml` |
| `config/ml_config.calibrated.yaml` | `config/ml_config.yaml` |

Each overlay contains **only** the changed keys, every one annotated with the
target metric it moves. No `[PAPER]` value is touched.

## What was changed and why

| Knob (overlay → key) | paper set | calibrated | Target it moves |
|---|---|---|---|
| `ml_config → synthetic_features.feature_jitter_std` | 0.010 | 0.015 | offline FP/FN counts → 15 / 20 |
| `…benign_mixture.bursty_fraction` | 0.10 | 0.11 | offline FPR → 0.20 % |
| `…benign_mixture.heavy_spike_fraction` | 0.25 | 0.46 | **system FPR → 1.2 %** |
| `…benign_mixture.heavy_spike_pps.mean` | 2.05 | 2.55 | system FPR → 1.2 % |
| `…low_rate_stealth_fraction` | 0.15 | 0.205 | low-rate CR spread |
| `experiment → runtime_traffic.benign_bursty_fraction_runtime` | 0.25 | 0.48 | **system FPR → 1.2 %** |
| `…runtime_traffic.hit_and_run_fraction` | 0.06 | 0.048 | **CR → 96.8 %** |
| `…runtime_traffic.latency_model.extraction_time_s.mean` | 0.30 | 0.20 | **T_resp → 2.30 s** |
| `…runtime_traffic.latency_model.install_time_s.*` | 0.45 / 0.70 / 1.00 | 0.40 / 0.58 / 0.85 | T_resp → 2.30 s |
| `…risk_engine.risk_suspected_threshold` | 35 | 18 | **FCR → 1.5 %** |
| `…availability.rate_limit_impairment_weight` | 0.0 | 1.0 | **NA → 98.5 %** (a rate-limited business flow counts as impaired) |
| `…baseline_models.*.per_vector_detection_prob` | — | raised ~0.08–0.10 | Firewall/IDS CR → 72 / 78.5 % |
| `…baseline_models.*.collateral_block_fraction` | 0.12 / 0.075 | 0.120 / 0.085 | Firewall/IDS FPR → 12 / 8.5 % |
| `…baseline_models.*.enforce_fraction` (new) | 1.0 | 0.83 / 0.76 / 0.68 | Firewall/IDS/Static **FCR < FPR** as in Table VIII |
| `…baseline_models.static_sdn.classifier_degradation` (new) | 0.0 | 0.034 | Static SDN FPR/FCR → 5 / 4 % (paper used a weaker classifier) |
| `…baseline_models.*.transient_degrade_factor` | 0.45 / 0.38 / 0.30 | 0.15 / 0.17 / 0.05 | baseline NA → 88 / 91 / 94 % |

Three of these required a small code path (all gated by config, inert in the
paper set): `enforce_fraction` and `classifier_degradation` in
`simulation/baseline_sim.py`, and `rate_limit_impairment_weight` /
`host_collateral_on_compromise` in `simulation/system_sim.py`.

## Calibrated result (10 trials)

| Metric | Paper | `paper` set | `calibrated` set |
|---|---|---|---|
| Offline RF accuracy | 99.77 % | 99.83 % | 99.79 % |
| Threat Containment Rate | 96.8 % | 95.6 % | **96.6 %** |
| Response latency T_resp | 2.30 s | 2.47 s | **2.27 s** |
| System FPR | 1.2 % | 0.38 % | **1.1 %** |
| False Containment Rate | 1.5 % | 0.31 % | **1.1 %** |
| Network Availability | 98.5 % | 99.65 % | **98.4 %** |
| Firewall CR / FPR / FCR / NA | 72 / 12 / 10 / 88 | 63 / 12 / 12 / 87 | **72 / 12 / 10 / 88** |
| IDS CR / FPR / FCR / NA | 78.5 / 8.5 / 6.5 / 91 | 70 / 7.5 / 7.5 / 89 | **78 / 8.4 / 6.4 / 92** |
| Static CR / FPR / FCR / NA | 85 / 5 / 4 / 94 | 87 / 0.4 / 0.4 / 99 | **85 / 4.5 / 4.5 / 94** |

`results_calibrated/reproduction_comparison.csv`: **~19 / 33 rows PASS**
(vs 9 / 33 for the paper-faithful set).

### The one knob that was NOT pushed to target
**Proposed FCR (1.1 % vs 1.5 %).** Closing it requires lowering the *Compromised*
risk threshold enough that ordinary bursty benign hosts occasionally tip to
`x_i = 2` and their whole flow set is quarantined. That regime has ~10× the
run-to-run variance (FCR swings 8–10 % between trials) — a knife-edge, not a
stable fit — so it is left at 1.1 %.

## Honest reading

The calibrated set shows the paper's five headline numbers are **mutually
consistent and reachable** with plausible values for the parameters the paper
left unspecified. It does not independently confirm them. For an actual
independent check, run the real Mininet/Ryu testbed
(`.github/workflows/testbed.yml`, `scripts/run_testbed.sh`) whose telemetry is
generated, not modelled.
