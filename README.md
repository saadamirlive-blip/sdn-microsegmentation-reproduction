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
| **Experiment pipeline** (`ml/`, `simulation/`, `metrics/`, `experiments/`, `plots/`) | any OS, Python 3.10 (§3–5) | builds the 50k dataset, trains the RF, runs the 10-trial closed-loop experiment, produces the CSVs and figures. **This produces `results/`.** |
| **Mininet topology + `ping`** (`topology/topology.py --standalone`) | any Linux incl. a Codespace (§6) | builds the real 13-host topology, checks connectivity |
| **Full DME testbed** (`controller/`, `traffic/iperf_generator.py`, `attacks/`, `scripts/run_testbed.sh`) | real Ubuntu VM / WSL2 (§6b) | the same experiment on a real OVS data plane with the Ryu/os-ken controller |

Both paths apply the same `common/risk_engine.py`, `common/policy_engine.py`
(DMCA / Algorithm 1) and `common/openflow_rules.py` (meter 100 Kbps / VLAN 99 /
drop priority 200) — only the data plane differs.

---

## 2. Requirements

| | Version |
|---|---|
| Python | **3.10** (the pinned packages don't build on 3.12+) |
| scikit-learn | 1.2.2 |
| NumPy | 1.24.3 |
| Pandas | 2.0.1 |
| matplotlib, joblib, pyyaml, scipy | see `requirements.txt` |
| *(Mininet demo)* Mininet + `bridge-utils` + `iputils-ping` | any Linux, incl. a GitHub Codespace |
| *(full testbed)* real Ubuntu (VM / WSL2), Open vSwitch kernel module, Ryu or os-ken, Scapy, hping3 | not a container |

---

## 3. Install (any OS / GitHub Codespace)

Use [`uv`](https://docs.astral.sh/uv/) — it fetches a standalone Python 3.10 and
prebuilt wheels, so nothing compiles and the system Python (3.12/3.14) is not
used. **Paste this as one block:**

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh && export PATH="$HOME/.local/bin:$PATH" && uv venv --python 3.10 .venv && source .venv/bin/activate && uv pip install -r requirements.txt pytest
```

In every **new** terminal, re-activate:

```bash
source .venv/bin/activate
```

> On Ubuntu 24.04 / GitHub Codespaces, `apt install python3.10-venv` does **not**
> exist and `pip install -r requirements.txt` under Python 3.12+ fails to build
> numpy — use the `uv` line above.

Conda alternative: `conda env create -f environment.yml && conda activate sdn-microseg`.

---

## 4. Run the experiment

Full run (10 Monte Carlo trials):

```bash
python run_experiment.py
```

Quick run (3 trials):

```bash
python run_experiment.py --trials 3
```

Reuse an already-trained model:

```bash
python run_experiment.py --skip-train
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

## 6. Mininet topology + `ping` between nodes

Builds the real 1-core / 3-edge / 13-host topology in Mininet using **Linux
bridge** switches (no OpenFlow controller, no OVS kernel module) — this works
inside a GitHub Codespace.

**One-time setup** (uses the *system* `python3`, not the `.venv` — Mininet's
bindings live in `/usr/lib/python3/dist-packages`):

```bash
sudo apt-get update && sudo apt-get install -y mininet bridge-utils iputils-ping
```

**Open the Mininet CLI:**

```bash
sudo /usr/bin/python3 topology/topology.py --standalone --switch lxbr
```

You land at `mininet>`. Useful commands:

```
nodes             # h1..h13, s_core, s1..s3
dump              # every node's IP (h1=10.0.0.1 ... h13=10.0.0.13)
net               # all links
pingall           # full 13x13 reachability -> "0% dropped (156/156 received)"
pingallfull       # same, with RTT min/avg/max
h4 ping -c 4 h2   # attacker h4 -> HR server h2
h1 ifconfig
exit              # quit and tear down
```

**One-shot connectivity test** (build → `pingall` → tear down):

```bash
sudo bash scripts/ping_demo.sh
```

**If `pingall` shows `X` everywhere** (100% dropped) inside a container, the
Linux bridge is being filtered by iptables. The topology script disables the
`net.bridge.bridge-nf-call-*` sysctls automatically; if it still fails, also run:

```bash
sudo iptables -P FORWARD ACCEPT
```

then re-run `pingall`.

### 6b. Full real-packet DME testbed (real Ubuntu, not a container)

Sends real packets through OVS with the Ryu/os-ken controller, ML inference and
live OpenFlow containment. Needs the **`openvswitch` kernel module**, so it
requires a real Ubuntu host (VM or WSL2), not a Codespace.

```bash
sudo apt-get install -y mininet openvswitch-switch iperf3 hping3
sudo systemctl start openvswitch-switch || sudo /usr/share/openvswitch/scripts/ovs-ctl start
pip install -r requirements-testbed.txt          # os-ken + scapy (inside the .venv)
python -m ml.train_rf
sudo env "PATH=$PATH" bash scripts/run_testbed.sh 300
```

`run_testbed.sh` starts the controller, builds the topology, drives benign
iperf3/socket traffic + the six attack vectors + horizontal probe from **h4**,
logs `results/testbed/telemetry_<ts>.csv` every 3 s, then runs
`python -m experiments.metrics_from_testbed` → `results/testbed/metrics_summary.json`
(the same CR / T_resp / FPR / FCR / NA, measured from real packets).

On the first run, check the `pps` column of the telemetry CSV: benign rows
should sit near `0.2`, attack rows near `3.0`; if off by a constant factor,
adjust `testbed.pps_scale` / `testbed.bps_scale` in `config/experiment.yaml`.

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
pytest -q
```

(22 tests; `pytest` is installed by the §3 `uv pip install` line.)
