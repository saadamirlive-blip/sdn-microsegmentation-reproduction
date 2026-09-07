# Paper → Code Traceability

Paper: *"SDN-Based Prevention: Dynamic Microsegmentation and Automated Containment
Policies"* (`Research_paper (18).pdf`).

For each methodology component: **paper location → paper statement → implementation
file/symbol → config parameter → how it is validated.**

---

## A. Hardware & Software Testbed

| Field | Value |
|---|---|
| Paper | Sec IV.A, **Table III** |
| Statement | Ubuntu 22.04 LTS / kernel 5.15; Mininet 2.3.0; OVS 2.17.0; Ryu (Python 3.10); OpenFlow 1.3 + meter tables; scikit-learn 1.2.2; NumPy 1.24.3; Pandas 2.0.1; Scapy 2.5.0; iPerf3; hping3; telemetry 3.0 s; 100 Mbps / 1.0 ms links |
| Code | `config/experiment.yaml: environment`, `telemetry`; `environment.yml`; `requirements.txt`; `Dockerfile`; `Vagrantfile` |
| Config | `environment.*`, `telemetry.polling_interval_s` |
| Validation | `scripts/verify_env.py`; `results/experiment_metadata.json` records paper-pinned vs actually-used versions; Ryu version is `[ASSUMPTION]` (ASSUMPTIONS §1) |

## B. Enterprise Network Topology

| Field | Value |
|---|---|
| Paper | Sec III.B, Sec IV.B, **Fig 2** |
| Statement | G=(V,E,W); 1 core + 3 edge OF switches; h1–h13; S1={h1 Finance, h2 HR, h3 App, h4 Attacker}; S2={h5 DB, h6 Web, h7 EMP1, h8 EMP2}; S3={h9–h13 = DEV/MKT/SALES/GUEST/ADMIN} |
| Code | `topology/topology.py` (Mininet build, Ubuntu); `topology/topology_model.py` (graph model for the simulation) |
| Config | `config/topology.yaml` (`switches`, `hosts`, `switch_links`, roles) |
| Validation | `topology/topology_model.py::load_topology` asserts 13 hosts and 156 directed paths; `tests/test_topology.py`. IP/MAC/base-VLAN are `[ASSUMPTION]` (ASSUMPTIONS §2–3) |

## C. Five-Layer Architecture & 4-Stage / 6-Stage Workflow

| Field | Value |
|---|---|
| Paper | Sec III.A, III.C, **Fig 1/3/5**; Sec V |
| Statement | Infrastructure → Monitoring (3 s poll) → Controller (Ryu/OF1.3) → Policy Engine → Containment; closed-loop 6 stages |
| Code | `controller/ryu_controller.py` (orchestration); `simulation/system_sim.py` (closed-loop simulation of the same stages) |
| Validation | `simulation/system_sim.py` runs poll → feature → RF → risk → DMCA → rule-install → metric each 3.0 s tick |

## D. Telemetry Collection

| Field | Value |
|---|---|
| Paper | Sec IV.A/IV.D, Sec V.A.1, Fig 5 |
| Statement | `OFPT_MULTIPART_REQUEST` every **3.0 s**; port counters, flow-hit counters, byte volumes; raw 5-tuple headers |
| Code | `controller/telemetry.py` (Ryu `EventOFPFlowStatsReply`); `common/features.py::RawFlowStats` |
| Config | `telemetry.polling_interval_s = 3.0`, `telemetry.collected_counters` |
| Validation | interval asserted in `simulation/system_sim.py`; never overridden |

## E. 6-D Feature Extraction & Preprocessing

| Field | Value |
|---|---|
| Paper | Eq 3; Sec III.D Phase 1; Sec V.A.2; Sec IV.D |
| Statement | φ_k = [pps, bps, duration, tcp_ratio, udp_ratio, icmp_ratio]; StandardScaler `z=(x−μ)/σ` → `scaler.pkl` |
| Code | `common/features.py::extract_vector`; `ml/preprocessing.py::split_and_scale` (fit on **train only**) |
| Config | `ml_config.yaml: features.order`, `preprocessing` |
| Validation | `ml/train_rf.py` asserts sklearn `StandardScaler` == explicit `z=(x−μ)/σ`; leakage guard = split-before-fit |

## F. Dataset Generation & ML Training Protocol

| Field | Value |
|---|---|
| Paper | Sec III.D Phase 1–2, **Sec IV.D**, Table VII |
| Statement | 50 000 samples (25 k benign / 25 k attack); benign `pps~N(0.2,0.05)`,`bps~N(0.1,0.02)`; attack `pps~N(3.0,0.5)`,`bps~N(1.5,0.3)`; 70/30 split (35 k/15 k); RF `n_estimators=100, max_depth=12, min_samples_split=5, class_weight=balanced, random_state=42` |
| Code | `ml/dataset_builder.py`, `traffic/flow_sampler.py`, `ml/model.py::build_random_forest`, `ml/train_rf.py` |
| Config | `experiment.yaml: dataset`, `ml_config.yaml: model.hyperparameters`, `synthetic_features` |
| Validation | `ml/dataset_builder.py` asserts 50 000 / 25 k / 25 k and Table VII per-vector counts; `ml/evaluate_rf.py` → `results/classification_report.txt`, `confusion_matrix.csv`. Feature distributions for 4/6 features are `[ASSUMPTION]` (ASSUMPTIONS §6) |

## G. Host Threat Risk Score (Eq 4) & host states (Eq 2)

| Field | Value |
|---|---|
| Paper | Eq 2, **Eq 4**, Sec III.D Phase 3, Sec V.A.3 |
| Statement | `R_i(t) = [w_rf·P_attack + w1·δ1 + w2·δ2 + w3·δ3]·100 ∈ [0,100]`; `x_i ∈ {0,1,2}`; `R_i ≥ risk ⇒ x_i=2` |
| Code | `common/risk_engine.py::host_risk_score`, `host_state`; `common/policy_engine.py` (host-level aggregation) |
| Config | `experiment.yaml: risk_engine` (weights, thresholds) — **all `[ASSUMPTION]`, ASSUMPTIONS §9** |
| Validation | weights asserted to sum to 1; `tests/test_risk_engine.py` |

## H. Dynamic Microsegmentation Algorithm (Algorithm 1 / DMCA)

| Field | Value |
|---|---|
| Paper | **Algorithm 1**, Sec III.G; Sec V.A.4 severity tiers |
| Statement | per flow: extract → RF → `R_i` → if compromised: critical→meter(100K) / lateral→VLAN 99 / else→drop(prio 200); else→monitor; push FlowMod to all switches |
| Code | `common/policy_engine.py::run_dmca`; `common/openflow_rules.py` (`create_meter_rule`, `create_vlan_rule`, `create_drop_rule`, `create_monitor_rule`, `severity_tier_rule`) |
| Config | `experiment.yaml: policy.mode` (`hybrid` default — reconciliation is `[ASSUMPTION]`, ASSUMPTIONS §11) |
| Validation | `tests/test_policy_engine.py` checks each Algorithm-1 branch; rule constants (`100 Kbps`, `VLAN 99`, `priority 200`) are `[PAPER]` |

## I. Containment Policy Tiers

| Field | Value |
|---|---|
| Paper | Sec III.D, **Sec V.A.4** |
| Statement | `S_k ≤ 0.4` MONITOR; `≤ 0.6` RATE_LIMIT (meter 100 Kbps); `≤ 0.8` QUARANTINE (VLAN 99); `> 0.8` BLOCK (drop, priority 200) |
| Code | `common/openflow_rules.py::severity_tier_rule` |
| Config | thresholds hard-coded from the paper in `severity_tier_rule`; `S_k := P_attack` is `[ASSUMPTION]` (ASSUMPTIONS §6) |
| Validation | `tests/test_policy_engine.py::test_severity_tiers` |

## J. MOOP Utility & Constraints (Eq 5–14)

| Field | Value |
|---|---|
| Paper | Sec III.E, **Sec III.F**, Eq 5–14 |
| Statement | `max Φ = α·τ − β·fcr + γ·avail − δ·λ`, Σweights=1; `L_ctrl = (0.246 + 0.00454·N_rules)/L_max`; C1 TCAM ≤ M_max; C2 T_contain ≤ 5.0 s; C3 L_ctrl ≤ 0.80; C5 C_k ∈ {0,1,2,3} |
| Code | `common/constraints.py` (`moop_utility`, `controller_load`, `check_c1..c5`) |
| Config | `experiment.yaml: moop`, `constraints` (`α,β,γ,δ`, `L_max` are `[ASSUMPTION]`, ASSUMPTIONS §9–10; `0.246`, `0.00454`, `5.0`, `0.80` are `[PAPER]`) |
| Validation | `experiments/metrics_bundle.py` reports Φ and L_ctrl per trial; `RESULTS.md §4` |

## K. Legitimate Background Traffic

| Field | Value |
|---|---|
| Paper | Sec IV.C.1 |
| Statement | iPerf3 + custom Python sockets; HTTP/HTTPS/SQL/file-transfer; `pps~N(0.2,0.05)`, `bps~N(0.1,0.02)` |
| Code | testbed: `traffic/iperf_generator.py`, `traffic/socket_generator.py`; simulation: `traffic/benign_traffic.py`, `traffic/flow_sampler.py::sample_benign` |
| Config | `experiment.yaml: benign_traffic` |
| Validation | distributions asserted against config in `traffic/flow_sampler.py` |

## L. Attack Traffic & Scenarios

| Field | Value |
|---|---|
| Paper | Sec IV.C.2, **Table VII** |
| Statement | Scapy 2.5.0 + hping3 from **h4**; `pps~N(3.0,0.5)`, `bps~N(1.5,0.3)`; six vectors SYN/UDP/ICMP/Mixed-DDoS/Slowloris/HTTP-flood (shares 35/25/15/12/8/5 %); horizontal probe h4→{h2,h5} |
| Code | testbed: `attacks/{syn_flood,udp_flood,icmp_flood,mixed_ddos,slowloris,http_flood,horizontal_probe}.py`; simulation: `traffic/attack_traffic.py`, `traffic/flow_sampler.py::sample_attack` |
| Config | `experiment.yaml: attack_traffic`, `attack_vectors` |
| Validation | per-vector counts asserted in `ml/dataset_builder.py`; `results/containment_by_vector.csv` vs Table VII |

## M. Baseline Defense Paradigms

| Field | Value |
|---|---|
| Paper | Sec IV.E, **Table IV**, Table VIII |
| Statement | Traditional Firewall 45 s; IDS/IPS 30 s; Static SDN 15 s; Proposed = measured |
| Code | `simulation/baseline_sim.py` |
| Config | `experiment.yaml: baselines` (latencies `[PAPER]`), `baseline_models` (CR/FPR/FCR/NA mechanism = `[ASSUMPTION]`, ASSUMPTIONS §17) |
| Validation | `experiments/compare_baselines.py` → `results/reproduction_comparison.csv` |

## N. Evaluation Metrics

| Field | Value |
|---|---|
| Paper | **Sec IV.F** |
| Statement | CR %, T_resp s, FPR %, FCR %, NA % (five definitions) |
| Code | `metrics/containment.py`, `metrics/latency.py`, `metrics/false_positive.py`, `metrics/false_containment.py`, `metrics/availability.py` |
| Validation | each function's docstring quotes the paper definition; `experiments/metrics_bundle.py` assembles them; no paper result is an input |

## O. Experimental Protocol / Monte Carlo

| Field | Value |
|---|---|
| Paper | **Sec IV.G** |
| Statement | 10 independent Monte Carlo trials; report the mean; fixed seeds |
| Code | `experiments/run_all_trials.py`, `common/seeding.py` |
| Config | `experiment.yaml: monte_carlo.trials = 10`, `seeds` (per-trial policy `[ASSUMPTION]`, ASSUMPTIONS §12) |
| Validation | `results/raw_trial_results.csv` (10 rows/system), `results/aggregate_results.csv` (mean ± std) |

## P. Results, Tables & Figures

| Paper artefact | Reproduced by | Output |
|---|---|---|
| Table V (RF perf) | `ml/evaluate_rf.py` | `results/classification_report.txt`, `rf_offline_metrics.json`, `figures/fig05_confusion_matrix.png` |
| Table VI (feature importance) | `ml/evaluate_rf.py` | `results/feature_importance.csv`, `figures/fig_feature_importance.png` |
| Table VII (CR by vector) | `experiments/run_all_trials.py` | `results/containment_by_vector.csv`, `figures/fig08_cr_by_vector.png` |
| Table VIII (system benchmark) | `experiments/run_all_trials.py` + `compare_baselines.py` | `results/aggregate_results.csv`, `reproduction_comparison.csv` |
| Fig 6 (traffic timeline) | `simulation/system_sim.py` availability/rule counters | `results/availability_timeline.csv` |
| Fig 7 (NA timeline) | `plots/figures.py::fig_availability_timeline` | `figures/fig07_availability_timeline.png` |
| Fig 9 (severity vs response) | `metrics/latency.py::response_latency_by_action` | `results/latency_results.csv` |
| Fig 10 / 11 / 12 / 13 / 14 | `plots/figures.py` | `figures/fig10..14_*.png` |
| Reproduction gap | `plots/figures.py::fig_reproduction_gap` | `figures/fig_reproduction_gap.png` |
