# SDN Dynamic Microsegmentation & Automated Threat Containment — Reproduction

A **reproduction / reconstruction** of the experiment in:

> **"SDN-Based Prevention: Dynamic Microsegmentation and Automated Containment
> Policies"**, Muhammad Saad Amir, Department of Computer Science, Bahria
> University. *(local source: `Research_paper (18).pdf`)*

The paper is the **primary specification**. This repository does not propose a new
method, does not tune the experiment toward the paper's numbers, and does not
hard-code any reported result. It implements the paper's pipeline, runs it, and
compares the **measured** output against the paper (`results/reproduction_comparison.csv`,
`RESULTS.md`).

```
Traffic Generation → SDN/Mininet → OVS → Ryu Controller → Flow Telemetry (3.0s)
 → 6-D Feature Extraction → Random Forest → Host Risk Score (Eq 4)
 → Dynamic Microsegmentation (Algorithm 1) → FlowMod / MeterMod
 → Containment → Metric Collection → Tables / Figures / Statistical Summary
```

---

## 1. What runs where

| Component | Runs on | Purpose |
|---|---|---|
| **Pure-Python reference pipeline** (`ml/`, `simulation/`, `metrics/`, `experiments/`, `plots/`) | **any OS** (Win/macOS/Linux), Python 3.10 | builds the 50 k dataset, trains the RF, runs the 10-trial closed-loop simulation, produces every table/figure/comparison. **This is what generated `results/`.** |
| **Real Mininet/Ryu testbed** (`topology/topology.py`, `controller/`, `traffic/iperf_generator.py`, `traffic/socket_generator.py`, `attacks/`) | **Ubuntu 22.04 LTS only** (Mininet 2.3.0, OVS 2.17.0, Ryu, hping3) | the paper's actual data-plane emulation; shares the *identical* risk/policy logic (`common/`) with the simulation |

The two paths apply the **same** `common/risk_engine.py` (Eq 4),
`common/policy_engine.py` (Algorithm 1) and `common/openflow_rules.py`
(meter 100 Kbps / VLAN 99 / drop priority 200) — only the data plane differs.

---

## 2. System requirements

### Paper's specified environment (Table III, Sec IV.A) — used by the testbed
| | Version |
|---|---|
| OS | Ubuntu 22.04 LTS |
| Linux kernel | 5.15 |
| Python | 3.10 |
| Mininet | 2.3.0 |
| Open vSwitch | 2.17.0 |
| Ryu SDN Framework | *(paper unspecified)* → **4.34** *(assumption, see `ASSUMPTIONS.md` #1)* |
| OpenFlow | 1.3 (with meter tables) |
| scikit-learn | 1.2.2 |
| NumPy | 1.24.3 |
| Pandas | 2.0.1 |
| Scapy | 2.5.0 |
| also | iPerf3, hping3 |

### Minimum to reproduce the results (no Mininet needed)
* Python **3.10**
* `pip install -r requirements.txt` (installs the exact paper pins above)

---

## 3. Install

### Option A — pip + venv (reproduction pipeline, any OS)
```bash
python3.10 -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

pip install -r requirements.txt
python scripts/verify_env.py          # checks versions against the paper pins
```

### Option B — conda
```bash
conda env create -f environment.yml
conda activate sdn-microseg-repro
```

### Option C — Docker (Ubuntu 22.04 image, both paths)
```bash
docker build -t sdn-microseg-repro .
docker run --rm -v "$PWD/results:/app/results" -v "$PWD/figures:/app/figures" \
           sdn-microseg-repro python3.10 run_experiment.py
```

### Option D — Vagrant VM (exact testbed: Ubuntu 22.04 / kernel 5.15 / Mininet 2.3.0)
```bash
vagrant up
vagrant ssh
cd /vagrant
```

---

## 3b. Two config sets: `paper` (reproduction) vs `calibrated` (fit)

| Set | Command | Output | What it is |
|---|---|---|---|
| **`paper`** (default) | `python run_experiment.py` | `results/`, `figures/` | the **scientific reproduction** — every unspecified value is a documented `[ASSUMPTION]` never adjusted toward the paper's numbers |
| **`calibrated`** | `python run_experiment.py --config-set calibrated` | `results_calibrated/`, `figures_calibrated/` | a **deliberate fit** — the same `[ASSUMPTION]` parameters tuned until the output matches Table VII/VIII. **Not** a reproduction. See **`CALIBRATION.md`**. |

The calibrated set deep-merges the tiny overlays `config/experiment.calibrated.yaml`
+ `config/ml_config.calibrated.yaml` (only the changed keys, each annotated with
the metric it moves). It never overwrites `results/`.

## 4. Run the whole experiment (one command)

```bash
python run_experiment.py                       # paper-faithful reproduction
python run_experiment.py --config-set calibrated   # the fitted variant
```

This executes, in order (task brief §28):

1. verify environment (`scripts/verify_env.py`)
2. build the **50,000-sample** dataset — 25 k benign / 25 k malicious (`ml/dataset_builder.py`)
3. train the **100-tree Random Forest** + StandardScaler → `results/model/{model,scaler}.pkl` (`ml/train_rf.py`)
4. evaluate the **offline** classifier → Table V / VI (`ml/evaluate_rf.py`)
5. run **10 Monte Carlo trials** × {proposed + 3 baselines} (`experiments/run_all_trials.py`)
6. aggregate → `results/*.csv`
7. build `results/reproduction_comparison.csv` (measured vs paper) (`experiments/compare_baselines.py`)
8. generate every figure → `figures/` (`plots/figures.py`)
9. write `results/experiment_metadata.json` (`experiments/make_metadata.py`)

Runtime: ~90 s on a laptop. Quick smoke run: `python run_experiment.py --trials 3`.

---

## 5. Run individual stages

```bash
# dataset
python -m ml.dataset_builder

# train + offline evaluation
python -m ml.train_rf
python -m ml.evaluate_rf

# one trial of one system
python -m experiments.run_trial --system proposed_dynamic_sdn --trial 0
python -m experiments.run_trial --system static_sdn --trial 3

# all 10 trials, all systems
python -m experiments.run_all_trials
python -m experiments.run_all_trials --trials 10 --systems proposed_dynamic_sdn

# comparison table
python -m experiments.compare_baselines

# figures (after a run)
python -m plots.make_all
python -m plots.containment_rate      # individual figure scripts (task Sec 25 layout)
python -m plots.response_time
python -m plots.collateral_damage
python -m plots.availability
```

---

## 6. Run the REAL Mininet/Ryu testbed (Ubuntu 22.04 only)

```bash
# terminal 1 — controller
ryu-manager controller/ryu_controller.py

# terminal 2 — topology + traffic + attacks (needs sudo for Mininet)
sudo python3 topology/topology.py            # builds Fig-2 topology, drops to CLI
#   mininet> source scripts/run_testbed.sh   # or run the orchestrator directly:
sudo ./scripts/run_testbed.sh                # topology + benign iperf3/socket + 6 attack vectors + probe
```

`scripts/run_testbed.sh` starts the Ryu controller, builds the topology, launches
iPerf3 servers/clients and the Python socket generators for benign traffic, then
runs each attack vector from **h4** (Scapy 2.5.0 / hping3), collecting the same
telemetry CSV the simulation consumes. Feed its `results/testbed/telemetry_*.csv`
back through `experiments/run_all_trials.py --from-telemetry` for a testbed-backed
metric set. *(The results in `results/` were produced by the pure-Python path;
the testbed path requires a Linux host and was not executed on the Windows
reproduction machine — see `RESULTS.md`.)*

---

## 7. Reading the results

| File | Content |
|---|---|
| `results/reproduction_comparison.csv` | **measured vs paper**, per metric, with abs/rel diff and PASS/INVESTIGATE |
| `results/aggregate_results.csv` | mean ± std over 10 trials, per system |
| `results/raw_trial_results.csv` | every trial's raw metrics |
| `results/classification_report.txt`, `confusion_matrix.csv` | offline RF (Table V) |
| `results/feature_importance.csv` | Table VI |
| `results/containment_by_vector.csv` | Table VII |
| `results/latency_results.csv` | T_resp incl. per-strategy (Fig 9) |
| `results/network_availability.csv`, `availability_timeline.csv` | Fig 7 / Fig 12 |
| `results/false_containment.csv` | FCR breakdown |
| `results/experiment_metadata.json` | full reproducibility record (task Sec 29) |
| `results/logs/flows_<system>_trial<k>.csv` | structured per-flow log (task Sec 27) |
| `figures/*.png` | Fig 5, 7, 8, 10–14 + feature importance + reproduction gap |
| `RESULTS.md` | narrative comparison + discrepancy analysis |
| `ASSUMPTIONS.md` | every value **not** in the paper, why, and how to replace it |
| `PAPER_TO_CODE_MAPPING.md` | paper section → file/function → config → validation |

---

## 8. Headline reproduced numbers (10 trials, seeds 42–51)

| Metric | Paper | Reproduced | Status |
|---|---|---|---|
| Offline RF accuracy | 99.77 % | 99.83 % | PASS |
| Threat Containment Rate | 96.8 % | 95.6 % ± 0.15 | PASS |
| Response latency T_resp | 2.30 s | 2.47 s ± 0.01 | PASS |
| System-level FPR | 1.2 % | 0.38 % | INVESTIGATE (see `RESULTS.md §3`) |
| False Containment Rate | 1.5 % | 0.31 % | INVESTIGATE |
| Network Availability | 98.5 % | 99.65 % | PASS |

The FPR/FCR gap is a **documented, untuned** consequence of the paper specifying
generative distributions for only 2 of the 6 flow features (`ASSUMPTIONS.md #6`).

---

## 9. Tests

```bash
pip install pytest
pytest -q
```

## 9b. Running it on GitHub (CI)

Two workflows under `.github/workflows/`:

| Workflow | Runner | What it does |
|---|---|---|
| **`reproduce.yml`** | `ubuntu-latest`, Python 3.10 + paper pins | full pure-Python pipeline for **both** config sets + `pytest`; prints both comparison tables to the run summary; uploads `results*/` + `figures*/` as artifacts. Runs on every push / PR. |
| **`testbed.yml`** | `ubuntu-22.04` | best-effort **real Mininet + OVS + Ryu (OF 1.3) + Scapy + hping3** run of `scripts/run_testbed.sh`; uploads the live telemetry. `continue-on-error` (Ryu on 3.10 is fragile in CI). Manual / path-triggered. |

To run it in your own GitHub repo:

```bash
git remote add origin git@github.com:<you>/sdn-microseg-reproduction.git
git push -u origin main
# GitHub Actions -> "reproduce" runs automatically;
# trigger "testbed (Mininet + Ryu)" manually from the Actions tab.
```

---

## 10. Project layout

```
config/            experiment.yaml · topology.yaml · ml_config.yaml   (every parameter, tagged [PAPER]/[DERIVED]/[ASSUMPTION])
common/            config · seeding · features · risk_engine (Eq 4) · policy_engine (Algorithm 1) · openflow_rules · constraints (Eq 5-14)
topology/          topology.py (Mininet, Fig 2) · topology_model.py (graph model for the sim)
controller/        ryu_controller.py · telemetry.py · feature_extraction.py · risk_engine.py · policy_engine.py · openflow_rules.py
traffic/           flow_sampler.py · benign_traffic.py · attack_traffic.py · iperf_generator.py · socket_generator.py
attacks/           syn_flood · udp_flood · icmp_flood · mixed_ddos · slowloris · http_flood · horizontal_probe
ml/                dataset_builder.py · preprocessing.py · model.py · train_rf.py · evaluate_rf.py
simulation/        system_sim.py (proposed) · baseline_sim.py (firewall / IDS / static SDN)
metrics/           containment · latency · false_positive · false_containment · availability
experiments/       run_trial.py · run_all_trials.py · compare_baselines.py · metrics_bundle.py · make_metadata.py
plots/             figures.py · make_all.py · containment_rate.py · response_time.py · collateral_damage.py · availability.py
scripts/           verify_env.py · run_testbed.sh
results/  figures/  tests/
run_experiment.py  ← one-command pipeline
```
