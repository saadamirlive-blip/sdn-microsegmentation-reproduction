# Reproducibility

## Determinism

| Source of randomness | How it is fixed |
|---|---|
| Random Forest training | `random_state=42` |
| Train/test split | `train_test_split(random_state=42, stratify=y)` (70/30) |
| Dataset generation | `numpy.random.default_rng(42)` (`common/seeding.py:dataset_seed`) |
| Monte Carlo trial *t* | `seed = 42 + t`, t = 0..9 (`common/seeding.py:trial_seed`) |
| Python `random`, `numpy` legacy, `PYTHONHASHSEED` | seeded from the same master int per context (`common/seeding.py:global_seed`) |
| scikit-learn RF `n_jobs` | `-1` — parallelism does **not** change the fitted trees given `random_state` |

`test_seeding_is_reproducible` asserts two runs of trial 0 give identical
CR / T_resp. `test_dataset_is_deterministic` asserts the 50k dataset is
byte-identical across builds.

## Environment recorded at run time

`run_experiment.py` writes `results/experiment_metadata.json`: UTC timestamp,
git commit, target vs actual package versions (and whether they match), all
seeds, the telemetry interval, dataset sizes, RF hyper-parameters, traffic /
attack parameters, and the risk-engine / MOOP / constraint parameters.

## Reference environment

* CPython **3.10** with `numpy 1.24.3`, `pandas 2.0.1`, `scikit-learn 1.2.2`,
  `scipy 1.10.1`, `matplotlib 3.7.1`, `joblib 1.2.0`, `pyyaml 6.0`
  (`requirements.txt`). `scripts/verify_env.py` reports any drift; a newer stack
  still runs.
* The Mininet 2.3.0 / OVS 2.17.0 / Ryu / Scapy / hping3 data-plane stack is
  Linux-only; `topology/topology.py`, `controller/`, `attacks/` and
  `scripts/run_testbed.sh` are for an Ubuntu 22.04 run (`Dockerfile`,
  `Vagrantfile`).

## Rebuild from scratch

```bash
python3.10 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt pytest
python run_experiment.py                              # -> results/ + figures/
pytest -q
```

Headline output (10 trials, seeds 42–51) is written to `results/run_summary.json`.
The mean over the 10 trials is stable; per-trial values drift slightly because
the seeds differ.

## What changes the numbers

Any value in `config/*.yaml` — most sensitively
`ml_config.yaml: synthetic_features` (drives FPR / FCR) and
`experiment.yaml: runtime_traffic` (drives CR / T_resp). See `MODELING_NOTES.md`
for what each parameter represents.
