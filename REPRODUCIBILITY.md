# Reproducibility

## Determinism

| Source of randomness | How it is fixed | Reference |
|---|---|---|
| Random Forest training | `random_state=42` | [PAPER] Sec IV.D |
| Train/test split | `train_test_split(random_state=42, stratify=y)` | [PAPER] 70/30; stratify = ASSUMPTIONS §7 |
| Dataset generation | `numpy.random.default_rng(42)` (`common/seeding.py:dataset_seed`) | ASSUMPTIONS §12 |
| Monte Carlo trial *t* | `seed = 42 + t`, t = 0..9 (`common/seeding.py:trial_seed`) | ASSUMPTIONS §12 |
| Python `random`, `numpy` legacy, `PYTHONHASHSEED` | seeded from the same master int per context | `common/seeding.py:global_seed` |
| scikit-learn RF `n_jobs` | `-1` — parallelism does **not** change the fitted trees given `random_state` | ASSUMPTIONS §13 |

`test_seeding_is_reproducible` asserts two runs of trial 0 give identical
CR / T_resp. `test_dataset_is_deterministic` asserts the 50 k dataset is
byte-identical across builds.

## Environment recorded at run time

`run_experiment.py` step 9 writes `results/experiment_metadata.json` containing:
paper title/author/file, UTC timestamp, git commit, **paper-specified** vs
**actually-used** package versions (and whether they match), all seeds, the
telemetry interval, dataset sizes, RF hyper-parameters, traffic/attack
parameters, risk-engine/MOOP/constraint parameters, and baseline latencies.

## The environment used to produce `results/`

* **Reproduction host:** Windows 10, CPython **3.10.20** (installed via `uv`).
* **Packages:** the exact paper pins — `numpy 1.24.3`, `pandas 2.0.1`,
  `scikit-learn 1.2.2`, `scipy 1.10.1`, `matplotlib 3.7.1`, `joblib 1.2.0`,
  `pyyaml 6.0` (see `requirements.txt`). `scripts/verify_env.py` confirms the
  match.
* **Not exercised on this host:** Mininet 2.3.0, OVS 2.17.0, Ryu, Scapy, hping3
  (Linux-only). The `topology/topology.py` + `controller/` + `attacks/` code is
  provided for an Ubuntu 22.04 run (`Dockerfile`, `Vagrantfile`,
  `scripts/run_testbed.sh`); its telemetry can be fed back through
  `experiments/run_all_trials.py`.

## Rebuilding from scratch

```bash
python3.10 -m venv .venv && . .venv/bin/activate      # (Windows: .venv\Scripts\activate)
pip install -r requirements.txt
python run_experiment.py                              # ~90 s -> results/ + figures/
pytest -q                                             # 23 tests
```

Expected headline output (10 trials, seeds 42–51) — see `RESULTS.md` for the full
table and the discrepancy analysis:

| Metric | Paper | Reproduced |
|---|---|---|
| Offline RF accuracy | 99.77 % | ~99.83 % |
| Containment Rate | 96.8 % | ~95.6 % |
| Response latency | 2.30 s | ~2.47 s |
| System FPR | 1.2 % | ~0.38 % *(INVESTIGATE — ASSUMPTIONS §6)* |
| False Containment Rate | 1.5 % | ~0.31 % *(INVESTIGATE)* |
| Network Availability | 98.5 % | ~99.65 % |

Small run-to-run drift (< 0.3 pp on CR/NA) is expected because the per-trial
seeds differ across the 10 runs; the **mean over 10 trials is stable**.

## What would change the numbers

Editing any `[ASSUMPTION]` value in `config/*.yaml` (see `ASSUMPTIONS.md`) — most
sensitively `ml_config.yaml: synthetic_features` (FPR/FCR) and
`experiment.yaml: runtime_traffic` (CR / T_resp). Editing a `[PAPER]` value is
outside the scope of a reproduction.
