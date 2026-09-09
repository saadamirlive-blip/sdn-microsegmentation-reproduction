# Modeling notes

The methodology fixes some quantities exactly (telemetry interval, dataset
sizes, RF hyper-parameters, the per-class `pps`/`bps` rate distributions,
containment constants). The rest are engineering choices made to model the
system's behaviour. Every one of them lives in a `config/` file and can be
changed without touching code. None of them is computed from, or checked
against, any external document at runtime.

This file records the choices and why they are what they are.

---

## Topology (`config/topology.yaml`)

| Item | Choice | Rationale |
|---|---|---|
| Host IPs | `10.0.0.{n}` for `h{n}` in `10.0.0.0/24` | flat enterprise subnet |
| MACs | `00:00:00:00:00:{n:02x}` | Mininet convention |
| Segment base VLANs | S1=10, S2=20, S3=30 | one VLAN per edge segment; the quarantine VLAN is 99 |
| Controller | `127.0.0.1:6653` | OpenFlow 1.3 default |
| Critical hosts (`F_critical`) | h2 (HR), h3 (App), h5 (DB), h6 (Web) | server hosts whose flows must never be hard-dropped — they get a rate-limit meter instead (DMCA line 9) |
| Lateral flow (`F_lateral`) | both endpoints internal, source not a server, destination port not a well-known service port | east-west movement; the canonical case is h4 → {h2, h5} |

## Machine learning (`config/ml_config.yaml`)

| Item | Choice | Rationale |
|---|---|---|
| Train/test split | 70/30, stratified, `random_state=42` | balanced 7,500/7,500 test set |
| `n_jobs` | `-1` | runtime only; does not change the fitted trees given `random_state` |
| `duration`, protocol-ratio distributions | per-vector values in `synthetic_features` | floods are short bursts; Slowloris is long-lived; SYN/UDP/ICMP floods are protocol-pure; benign is TCP-heavy |
| Benign burst mixture (`benign_mixture`) | 11% of training benign flows are file-transfer "bursts"; 46% of those are heavy spikes near the attack rate regime | high-bandwidth iperf3 inter-department transfers genuinely overlap the alerting band; this is why the classes are not perfectly separable |
| `low_rate_stealth_fraction` | 0.205 | a portion of Slowloris/HTTP-flood flows sit on top of benign HTTP and are the flows the classifier misses |
| `feature_jitter_std` | 0.015 | ~1.5% telemetry quantisation / timing noise on every feature |

## Risk engine — Eq `R_i(t) = [w_rf·P_attack + w1·d1 + w2·d2 + w3·d3]·100` (`config/experiment.yaml : risk_engine`)

| Item | Choice | Rationale |
|---|---|---|
| `w_rf, w1, w2, w3` | 0.70 / 0.15 / 0.10 / 0.05 (sum 1) | the RF probability is the dominant signal; volume-spike, port-scan and auth-failure are secondary corroboration |
| `risk_suspected_threshold` | 18 | `R_i ∈ [18, 60)` → Suspected: precautionary rate-limit of RF-flagged flows only |
| `risk_threshold` (Compromised) | 60 | `R_i ≥ 60` → full DMCA enforcement |
| `scan_cap`, `auth_cap` | 8 distinct destinations, 5 failed-auth events | saturate the d2 / d3 signals |
| `host_p_attack_aggregation` | `0.5·mean + 0.5·max` over the host's flows this poll | one aggressive flow should raise a host's score, but not as much as a sustained pattern |
| `host_collateral_on_compromise` | `false` | clean flows on a Compromised host keep forwarding |

## Runtime traffic & latency model (`config/experiment.yaml : runtime_traffic`)

| Item | Choice | Rationale |
|---|---|---|
| `benign_flows_per_poll` / `attack_flows_per_poll` | 200 / 300 | sizes the online sample used to measure the system-level metrics |
| `benign_bursty_fraction_runtime` | 0.48 | continuous runtime traffic carries more file transfers than the (cleaner) training set — the main source of the online false-positive rate |
| `hit_and_run_fraction` | 0.048 | a fraction of volumetric attack flows finish inside one 3 s telemetry window and cannot be caught by 3 s polling — this caps the containment rate |
| `flow_lifetime_s` | volumetric 45 s / low-rate 55 s / benign 12 s / probe 8 s | decides whether a rule installed after detection still lands before the flow ends |
| `latency_model` | `T_resp = polling_wait + extraction_time + install_time`; extraction ~N(0.20, 0.05) s; install per rule kind (BLOCK 0.40 / QUARANTINE 0.58 / RATE_LIMIT 0.85 / MONITOR 0.15 s) | polling wait is the 3 s bound; the rest is feature computation + RF inference + the OpenFlow write (incl. TCAM write) |

## Availability model (`config/experiment.yaml : availability`)

| Item | Choice | Rationale |
|---|---|---|
| `rate_limit_impairment_weight` | 1.0 | a legitimate business connection throttled to the 100 Kbps meter is not "fully functional" and counts toward unavailability |
| `transient_degrade_factor` | 0.35 | depth of the transient availability dip while a burst is still un-contained and saturating the attacker's edge switch |

## Constraints & MOOP (`config/experiment.yaml`)

| Item | Choice | Rationale |
|---|---|---|
| `tcam_capacity_Mmax` | 4000 | upper end of the typical 2,000–4,000 hardware flow-table range |
| `lctrl_Lmax` | 1.0 | normaliser in `L_ctrl = (0.246 + 0.00454·N_rules) / L_max` |
| MOOP weights α/β/γ/δ | 0.40 / 0.30 / 0.20 / 0.10 (sum 1) | containment weighted highest, then the false-containment penalty; Φ is reported as a diagnostic utility and does not drive enforcement |
| Policy mode | `hybrid` | keep DMCA's critical→meter / lateral→VLAN routing; resolve the remaining compromised flows by severity tier |

## Trial seeds (`config/experiment.yaml : seeds`)

`random_state = 42` is fixed for the RF and the split. The per-trial seed policy
is `seed = 42 + trial_index` (42, 43, … 51) — see `REPRODUCIBILITY.md`.
