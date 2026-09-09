# SDN Dynamic Microsegmentation & Automated Threat Containment

An SDN security experiment: real-time flow telemetry is classified by a Random
Forest, hosts are risk-scored, and a Dynamic Microsegmentation Engine installs
graded OpenFlow containment (monitor / rate-limit / quarantine / block). The
pipeline runs end to end and reports its own measured metrics.

```
traffic → attack → telemetry (3.0 s) → 6-D feature extraction → Random Forest
  → host risk score → dynamic microsegmentation → FlowMod / MeterMod
  → containment → metrics → results
```

It is fully self-contained: **`python run_experiment.py`** needs only the code,
the config in `config/`, and the dataset it generates. No external document is
read, parsed, or compared at runtime; the project runs unchanged with nothing
but this repository present.

---

## 1. What runs where

| Component | Runs on | Purpose |
|---|---|---|
| **Experiment pipeline** (`ml/`, `simulation/`, `metrics/`, `experiments/`, `plots/`) | any OS, Python 3.10 | builds the 50k dataset, trains the RF, runs the 10-trial closed-loop experiment, produces the CSVs and figures. **This produces `results/`.** |
| **Mininet/Ryu data-plane testbed** (`topology/topology.py`, `controller/`, `traffic/iperf_generator.py`, `traffic/socket_generator.py`, `attacks/`) | Ubuntu 22.04 only | optional: the same experiment on a real OVS data plane, sharing the identical risk/policy logic (`common/`) |

Both paths apply the same `common/risk_engine.py`, `common/policy_engine.py`
(DMCA / Algorithm 1) and `common/openflow_rules.py` (meter 100 Kbps / VLAN 99 /
drop priority 200) — only the data plane differs.

---

## 2. Requirements

| | Version |
|---|---|
| Python | 3.10 |
| scikit-learn | 1.2.2 |
| NumPy | 1.24.3 |
| Pandas | 2.0.1 |
| matplotlib, joblib, pyyaml, scipy | see `requirements.txt` |
| *(testbed only)* Ubuntu 22.04, Mininet 2.3.0, Open vSwitch 2.17.0, Ryu (or os-ken), OpenFlow 1.3, Scapy 2.5.0, iperf3, hping3 | |

Newer package versions run fine (a mismatch only warns); the delta is recorded
in `results/experiment_metadata.json`.

---

## 3. Install

```bash
python3.10 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python scripts/verify_env.py
```

Conda: `conda env create -f environment.yml && conda activate sdn-microseg`.
Docker (Ubuntu 22.04, both paths): `docker build -t sdn-microseg . && docker run --rm -v "$PWD/results:/app/results" sdn-microseg python3 run_experiment.py`.

---

## 4. Run the experiment

```bash
python run_experiment.py            # full run: 10 Monte Carlo trials
python run_experiment.py --trials 3 # quick run
python run_experiment.py --skip-train   # reuse results/model/model.pkl
```

Steps: verify env → build 50,000-sample dataset (25k benign / 25k malicious) →
train the 100-tree Random Forest + StandardScaler → evaluate the offline
classifier → run N closed-loop trials of the proposed system → figures →
metadata. Runtime ~20 s (3 trials) / ~90 s (10 trials).

---

## 5. Run individual stages

```bash
python -m ml.dataset_builder                 # dataset -> results/dataset_50k.csv
python -m ml.train_rf                        # -> results/model/{model,scaler}.pkl
python -m ml.evaluate_rf                     # offline classifier metrics
python -m experiments.run_trial --trial 0    # one Monte Carlo trial
python -m experiments.run_all_trials         # all trials + aggregation
python -m plots.make_all                     # (re)generate figures from results/*.csv
```

---

## 6. Real-packet run: the Mininet/Ryu testbed (Ubuntu 22.04)

This path sends **real packets** through an emulated OVS network — synthetic
scenarios, real traffic — the same way the reference methodology does.
Ubuntu 22.04 (a VM, WSL2, or a cloud box), with `sudo`.

```bash
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch iperf3 hping3 python3.10 python3.10-venv
sudo service openvswitch-switch start
```

```bash
python3.10 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r requirements-testbed.txt   # os-ken + scapy
```

```bash
python -m ml.train_rf                         # the controller loads results/model/model.pkl
sudo env "PATH=$PATH" ./scripts/run_testbed.sh 300
```

`run_testbed.sh` does the whole run: starts the SDN controller
(`ryu-manager`, or `osken-manager` when Ryu can't be installed), builds the
1-core / 3-edge / 13-host topology, drives benign iperf3 + socket traffic and
the six attack vectors + horizontal probe from **h4**, logs a telemetry +
decision row every 3 s to `results/testbed/telemetry_<ts>.csv`, and finally runs:

```bash
python -m experiments.metrics_from_testbed    # -> results/testbed/metrics_summary.json
```

which turns that telemetry into the same five metrics (CR / T_resp / FPR / FCR /
NA). On the **first** run, open `results/testbed/telemetry_*.csv` and check the
`pps` column: benign rows should be near `0.2`, attack rows near `3.0`. If
they're off by a constant factor, adjust `testbed.pps_scale` / `testbed.bps_scale`
in `config/experiment.yaml`.

> Note: this path is Linux-only and has not been executed from the Windows
> machine these results were produced on. The code is complete; the unit-scale
> defaults may need one adjustment on a real box.

---

## 7. Outputs

| File | Content |
|---|---|
| `results/run_summary.json` | headline: CR, T_resp, FPR, FCR, NA (mean ± std over trials) |
| `results/aggregate_results.csv` | the same, plus MOOP utility and rule counts |
| `results/raw_trial_results.csv` | every trial's raw metrics |
| `results/latency_results.csv` | response latency, overall and per enforcement action |
| `results/containment_by_vector.csv` | containment rate per attack vector |
| `results/network_availability.csv`, `availability_timeline.csv` | NA per trial and vs time |
| `results/false_containment.csv` | FCR and its block/quarantine/rate-limit breakdown |
| `results/classification_report.txt`, `confusion_matrix.csv`, `feature_importance.csv` | offline Random Forest |
| `results/logs/flows_t<k>.csv` | per-flow structured log (classification, risk, action, latency) |
| `results/experiment_metadata.json` | full parameter + environment record |
| `figures/*.png` | headline metrics, CR by vector, latency by strategy, FPR/FCR over trials, availability timeline, feature importance, confusion matrix |

The five metrics (Threat Containment Rate, Containment Response Latency, False
Positive Rate, False Containment Rate, Network Service Availability) are all
**measured** from the per-flow / per-path records of each run.

---

## 8. Configuration

Everything is in `config/` — nothing is hard-coded in the source:

* `config/experiment.yaml` — telemetry interval, dataset sizes, seeds, trial
  count, traffic/attack distributions, runtime traffic model, risk-engine
  weights and thresholds, containment constants, constraints, MOOP weights
* `config/topology.yaml` — the 1-core + 3-edge / 13-host topology, IPs, VLANs,
  critical hosts, attacker placement
* `config/ml_config.yaml` — RF hyper-parameters, StandardScaler, the synthetic
  flow-feature generative model

`MODELING_NOTES.md` explains the engineering choices behind the parameters the
methodology does not pin down. `REPRODUCIBILITY.md` covers seeds and determinism.

---

## 9. Tests

```bash
pip install pytest
pytest -q
```
