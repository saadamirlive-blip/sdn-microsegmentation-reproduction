# ASSUMPTIONS

This is a **reproduction** of the experiment in
*"SDN-Based Prevention: Dynamic Microsegmentation and Automated Containment
Policies"* (M. Saad Amir, Bahria University — local file `Research_paper (18).pdf`).

Every value the code uses is one of:

| Category | Meaning | Where |
|---|---|---|
| **A — [PAPER]** | Explicitly stated in the paper | config `*.yaml`, tagged `[PAPER]` |
| **B — [DERIVED]** | Computed from category-A values | tagged `[DERIVED]` |
| **C — [ASSUMPTION]** | **Not** in the paper; chosen for reproducibility | tagged `[ASSUMPTION]`, **and listed below** |

**No category-C value is ever presented as if it came from the paper.**
Every assumption is isolated in a config file so it can be replaced without
touching code. None of them were tuned to make the output match the paper's
numbers (see `RESULTS.md` and §33 of the task brief).

---

## Index of assumptions

| # | Topic | Config key |
|---|---|---|
| 1 | Ryu version | `experiment.yaml: environment.ryu` |
| 2 | Host IP addressing | `topology.yaml: ip_plan` |
| 3 | Host MAC addressing | `topology.yaml: ip_plan.mac_format` |
| 4 | Controller listen IP/port | `topology.yaml: controller` |
| 5 | Link queue size | `topology.yaml: links.max_queue_size` |
| 6 | Feature distributions for `duration`/protocol ratios; class-overlap model; severity `S_k` definition; risk signals δ | `ml_config.yaml: synthetic_features`, `experiment.yaml: risk_engine` |
| 7 | Train/test split is stratified | `experiment.yaml: dataset.test_split_stratified` |
| 8 | `F_critical` / `F_lateral` membership rules | `topology.yaml: critical_hosts`, `lateral_definition` |
| 9 | Eq 4 weights, risk thresholds; MOOP weights α,β,γ,δ; MOOP role | `experiment.yaml: risk_engine`, `experiment.yaml: moop` |
| 10 | `L_max` in Eq 9 | `experiment.yaml: constraints.lctrl_Lmax` |
| 11 | Reconciliation of Algorithm 1 vs severity tiers; 3-state model | `experiment.yaml: policy.mode`, `risk_engine.risk_suspected_threshold` |
| 12 | Per-trial seed policy | `experiment.yaml: seeds.trial_seed_policy` |
| 13 | `n_jobs` for the Random Forest | `ml_config.yaml: model.hyperparameters.n_jobs` |
| 14 | Which reported offline accuracy is the reference (99.77 vs 99.82) | `ml_config.yaml: paper_offline_results.accuracy` |
| 15 | MONITOR / meter / quarantine rule priorities | `common/openflow_rules.py` |
| 16 | TCAM `M_max` point value from the 2000–4000 range | `experiment.yaml: constraints.tcam_capacity_Mmax` |
| 17 | Baseline mechanism models (detection probabilities, collateral fractions, CR semantics) | `experiment.yaml: baseline_models` |
| 18 | System-level runtime traffic volume, flow lifetimes, latency decomposition | `experiment.yaml: runtime_traffic` |

---

### 1. Ryu SDN Framework version
* **Missing:** Table III lists only *"Ryu SDN Framework (Python 3.10)"* — no version.
* **Needed:** to pin the controller dependency and the OpenFlow 1.3 parser API.
* **Choice:** `ryu==4.34` (the final Ryu release; the last that installs and runs
  under a Python 3.10 runtime with `eventlet`).
* **Repro impact:** low. The controller uses only stable OF 1.3 constructs
  (`OFPFlowMod`, `OFPMeterMod`, `OFPMultipartRequest`) present since Ryu 4.x.
* **Replace:** set `environment.ryu` and the `controller` extra in `requirements.txt`.

### 2. Host IP addressing
* **Missing:** the paper gives roles for h1–h13 but no addresses.
* **Needed:** Mininet host config, 5-tuple flow matches, `F_critical`/`F_lateral` tests.
* **Choice:** flat `10.0.0.0/24`, `h{n} -> 10.0.0.{n}`.
* **Repro impact:** none on any metric (addresses are opaque identifiers).
* **Replace:** `topology.yaml: ip_plan`.

### 3. Host MAC addressing
* **Choice:** `00:00:00:00:00:{n:02x}` for `h{n}` (Mininet default style).
* **Repro impact:** none.

### 4. Controller listen IP / port
* **Choice:** `127.0.0.1:6653` (Ryu / OpenFlow 1.3 default).
* **Repro impact:** none.

### 5. Link queue size
* **Missing:** the paper gives 100 Mbps / 1.0 ms / 0 % loss but no queue length.
* **Choice:** `max_queue_size: 1000` (Mininet `TCLink` typical).
* **Repro impact:** affects only the depth of the *transient* availability dip
  during an un-contained burst (Fig 7); no effect on CR/FPR/FCR or steady-state NA.
* **Replace:** `topology.yaml: links.max_queue_size`.

### 6. Feature distributions, class overlap, severity, risk signals  *(largest assumption)*
* **Missing:** the paper fixes **only** `pps ~ N(0.2,0.05)/N(3.0,0.5)` and
  `bps ~ N(0.1,0.02)/N(1.5,0.3)` (Sec IV.C). It gives **no** distribution for
  `duration`, `tcp_ratio`, `udp_ratio`, `icmp_ratio`, no generative model for the
  benign/attack **overlap** that yields a non-perfect classifier, no definition of
  the severity score `S_k`, and no formula for the three risk signals δ_{i,1..3}.
* **Needed:** to build the 50,000-sample dataset (Phase 1) and to run the online
  classifier and risk engine.
* **Choices (all in `ml_config.yaml: synthetic_features` and
  `experiment.yaml: risk_engine`), set once from the paper's *qualitative* text
  and then FROZEN:**
  * `duration`: benign `N(1.0,0.35)`; per-vector attack durations from the paper's
    descriptions ("Slowloris = low-rate/long-lived", "floods = short bursts").
  * protocol ratios: per-class Dirichlet concentrations reflecting Table VI
    ("`tcp_ratio` identifies SYN floods", "`udp_ratio` identifies UDP amplification", …).
  * **class-overlap** = the paper's own stated mechanisms:
    * Sec VI.B.7 — benign iPerf3 **file-transfer bursts** transiently raise the rate
      features → modelled as a 2-component benign mixture (`benign_mixture`), with a
      heavier runtime burst fraction than the training set (Sec VI.B.7 says the FPR
      rises from 0.20 % offline to 1.2 % system *because of* these runtime bursts).
    * Sec VI.B.4 — Slowloris/HTTP-flood traffic "closely resemble legitimate web
      connections" → a `low_rate_stealth_fraction` of those flows is drawn from the
      benign regime (these become the classifier's false negatives, i.e. the reason
      Table VII gives Slowloris/HTTP the lowest CR).
  * `S_k := P_attack(f_k)` — the per-flow Random-Forest attack probability
    (the most direct reading of Sec V.A.3 "generating an instantaneous attack
    probability P_attack … resolves severity scores into … actions").
  * δ_{i,1} volume spike `= min(1, pps / attack_pps_mean)`;
    δ_{i,2} port-scan `= min(1, distinct_dst / scan_cap)`;
    δ_{i,3} auth-failure `= min(1, failed_auth / auth_cap)`;
    `scan_cap=8`, `auth_cap=5`.
* **Repro impact:** **material** for FPR/FCR (see `RESULTS.md`): the frozen
  distributions produce classes slightly *more* separable than the paper's live
  emulation, so reproduced FPR/FCR come out **below** the paper's. CR, T_resp and
  NA are largely insensitive to it.
* **Replace:** `ml_config.yaml: synthetic_features`, `experiment.yaml: risk_engine`.

### 7. Stratified train/test split
* **Missing:** the paper says "70 % / 30 %" and reports a 7,500 / 7,500 balanced test
  set (Table V) — implying stratification but not stating it.
* **Choice:** `train_test_split(..., stratify=y, random_state=42)`.
* **Repro impact:** negligible (dataset is already exactly 50 / 50).

### 8. `F_critical` and `F_lateral` membership
* **Missing:** Algorithm 1 branches on `f_k ∈ F_critical` and `f_k ∈ F_lateral`
  but the paper never enumerates either set.
* **Choices:**
  * `F_critical` = any flow touching a business-critical **server** host
    (HR h2, App h3, DB h5, Web h6) — from Sec I "database services or active
    authentication servers". These are the flows Constraint 4 protects from a
    hard drop (they get a meter rule instead).
  * `F_lateral` = both endpoints internal, source is **not** a server, destination
    port is **not** a well-known service port. The canonical case is the
    h4 → {h2, h5} horizontal probe (Sec IV.C.2).
* **Repro impact:** moderate on *which* enforcement tier a contained flow lands in
  (meter vs VLAN vs drop); little on CR/FPR/NA aggregates.
* **Replace:** `topology.yaml: critical_hosts`, `lateral_definition`.

### 9. Eq 4 weights, risk thresholds, MOOP weights
* **Missing:** Eq 4 has weights `w_rf, w1, w2, w3` and a threshold `risk`; Eq 5 has
  `α, β, γ, δ`. **None are given numerically.**
* **Choices** (convex combinations, RF-dominant, matching the paper's emphasis that
  the ML prediction is the primary term and that containment rate is weighted highest):
  * `w_rf=0.70, w1=0.15, w2=0.10, w3=0.05`  (sum = 1)
  * `risk` (→ Compromised, x_i=2) `= 60` on the 0–100 scale;
    Suspected (x_i=1) `= 35` — see #11.
  * `α=0.40 (τ), β=0.30 (fcr), γ=0.20 (avail), δ=0.10 (λ)`  (sum = 1)
  * MOOP **role = diagnostic**: Φ(C) is computed and reported per trial, but
    enforcement follows Algorithm 1 + the severity tiers (the paper's operational
    path). The paper describes the MOOP as a formal model, not an online solver.
* **Repro impact:** the thresholds affect how readily a host is marked
  Suspected/Compromised and therefore FCR and (weakly) CR. Reproduced FCR is
  sensitive to `risk_suspected_threshold`; see `RESULTS.md`.
* **Replace:** `experiment.yaml: risk_engine`, `experiment.yaml: moop`.

### 10. `L_max` in Eq 9
* **Missing:** Eq 9 reads `L_ctrl(t) = (0.246 + 0.00454·N_rules(t)) / L_max`; `L_max`
  is never given. Constraint 3 is `L_ctrl(t) ≤ 0.80`.
* **Choice:** `L_max = 1.0` (so `L_ctrl` is the raw fraction and the 0.80 bound is a
  direct cap). `N_rules(t)` is interpreted as the number of **distinct** OpenFlow
  entries active in one 3.0 s poll, not the cumulative install count.
* **Repro impact:** only the numeric value of the reported controller-load
  diagnostic; the constraint check direction is unchanged.
* **Replace:** `experiment.yaml: constraints.lctrl_Lmax`.

### 11. Algorithm 1 ↔ severity tiers reconciliation; 3-state model
* **Ambiguity:** the paper describes **two** overlapping resolution schemes —
  Algorithm 1 (`critical → meter`, `lateral → VLAN 99`, `else → drop@200`,
  `no-risk → monitor`) **and** graded severity tiers keyed on `S_k`
  (`≤0.4 MONITOR`, `≤0.6 RATE_LIMIT`, `≤0.8 QUARANTINE`, `>0.8 BLOCK`).
  Constraint 4 (`C_k=3` for critical) also contradicts Algorithm 1 line 9
  (critical → meter, i.e. `C_k=1`).
* **Choice:** `policy.mode = "hybrid"` — keep Algorithm 1's `F_critical → meter` and
  `F_lateral → VLAN 99` routing (this honours Constraint 4 read as "critical flows
  always get a *definite* action", never a blanket blackout), and resolve the
  remaining compromised flows by the severity tiers rather than an unconditional
  drop. Modes `"algorithm1"` and `"severity_tiers"` are also implemented.
  Eq 2's **three host states** `x_i ∈ {0,1,2}` are honoured: `R_i ∈ [35,60)` →
  Suspected → precautionary rate-limit of RF-flagged flows only; `R_i ≥ 60` →
  Compromised → full DMCA.
* **Repro impact:** changes the tier mix (and therefore the T_resp-by-strategy
  breakdown, Fig 9) but has small effect on the headline CR/FPR/FCR/NA.
* **Replace:** `experiment.yaml: policy.mode`, `risk_engine.risk_suspected_threshold`.

### 12. Per-trial seed policy
* **Missing:** the paper enforces `random_state=42` and says scripts were
  "version-controlled under fixed random seeds", but gives no per-trial seed scheme
  for the 10 Monte Carlo runs.
* **Choice:** `seed(trial t) = 42 + t`, t = 0..9 (`trial_seed_policy: base_plus_index`).
  The Random Forest itself always uses `random_state=42` (paper-fixed).
* **Repro impact:** determines the exact per-trial numbers but not their mean;
  fully documented and deterministic.
* **Replace:** `experiment.yaml: seeds`.

### 13. Random Forest `n_jobs`
* **Choice:** `n_jobs=-1` (all cores). Runtime only — does **not** change the fitted
  model (scikit-learn RF training is deterministic given `random_state`).

### 14. Which offline accuracy is the reference
* **Ambiguity:** the paper states **99.82 %** (Sec III.D) and **99.77 %** (Table V,
  the detailed table with the confusion matrix).
* **Choice:** Table V (99.77 %, with TN=7485 / FP=15 / FN=20 / TP=7480) is the
  reference for the comparison, since it is the internally-consistent detailed table.

### 15. Rule priorities for non-drop tiers
* **Missing:** the paper fixes only the **drop** priority (200) and does not give
  priorities for monitor / meter / quarantine rules.
* **Choice:** `MONITOR=10 < METER=150 < QUARANTINE=175 < DROP=200`.
* **Repro impact:** none on metrics (all four tiers are mutually exclusive per flow).

### 16. TCAM `M_max`
* **Range given:** "typically 2,000 to 4,000 flow entries per switch" (Sec II).
* **Choice:** `M_max = 4000` (upper bound). Only used by the Constraint-1 check.
* **Replace:** `experiment.yaml: constraints.tcam_capacity_Mmax`.

### 17. Baseline mechanism models
* **Missing:** Table IV/VIII give baseline **response latencies** (45 / 30 / 15 s —
  these ARE `[PAPER]`) and baseline CR/FPR/FCR/NA **results**, but **no generative
  model** for those results. Several trace to cited literature (Table II:
  AlEroud 45 s / 12 % FP; Kennedy 30 s / 78.5 % CR; Wainwright 85 % CR / 15 s).
* **Choices** (`experiment.yaml: baseline_models`), set once from Sec II / Table I /
  Table IV descriptions:
  * **Traditional Firewall** — static ACLs, *zero* east-west visibility (Table I);
    detects volumetric / multi-vector headers only, with per-vector match
    probabilities; horizontal probe never detected; coarse subnet drop blocks a
    fixed 12 % of benign east-west flows; slowest transient recovery.
  * **IDS/IPS** — passive Snort signature match; higher per-vector detection than the
    firewall; async IP drop → 7.5 % benign collateral.
  * **Static SDN** — reuses the *same* 6-D Random Forest (per the Wainwright base
    paper) but only binary 5-tuple drop, no meter/VLAN tiers; a misclassified benign
    flow is fully dropped; 15 s idle-timeout latency lets short flows escape.
  * **CR semantics:** for the firewall / IDS, CR is governed by *detection
    capability* (their 45 s / 30 s slowness shows up in T_resp, not CR); for Static
    SDN and the proposed system, an attack flow counts as contained only if the rule
    lands before the flow ends.
* **Repro impact:** the baseline CR/FPR/FCR/NA are therefore approximate
  reconstructions; several land 2–9 points from the paper's numbers (which
  themselves have no derivation in the paper). See `results/reproduction_comparison.csv`.
* **Replace:** `experiment.yaml: baseline_models` and `baselines.*_latency_s`.

### 18. System-level runtime traffic
* **Missing:** the paper never states flow counts per poll, per-flow lifetimes, or
  the internal split of the 2.30 s response latency.
* **Choices** (`experiment.yaml: runtime_traffic`):
  * 200 benign + (during a burst) 300 attack flow-observations per 3.0 s poll
    → ~20 k benign / ~13 k attack observations per 300 s trial (enough to measure
    sub-1 % FPR).
  * Two attack bursts of 60 s each, initiated at t = 60 s and t = 120 s (Fig 6).
  * Flow lifetimes: volumetric 45 s, low-rate 55 s, benign 12 s, probe 8 s
    (× a per-flow 0.6–1.4 spread); a 6 % "hit-and-run" fraction of attack flows
    complete inside one 3 s poll and are therefore *uncatchable* by 3 s polling
    (the paper's own latency-bound argument, Sec IV.E).
  * `T_resp(flow) = (t_poll − t_flow_init)  +  extraction N(0.30,0.08)
                    +  install{BLOCK 0.45 / QUARANTINE 0.70 / RATE_LIMIT 1.00}` s.
    The polling wait is taken from real per-flow timestamps, not sampled.
* **Repro impact:** sets the measured T_resp (≈ 2.47 s here vs the paper's 2.30 s)
  and the CR shortfall from the hit-and-run fraction. All knobs are in one config
  block.
* **Replace:** `experiment.yaml: runtime_traffic`.

---

## What was NOT assumed / NOT changed

* All `[PAPER]` values in the three config files are used verbatim: OS/kernel/tool
  versions, OpenFlow 1.3, telemetry **3.0 s**, dataset **50 000 (25 k/25 k)**,
  **70/30** split, StandardScaler `z=(x−μ)/σ`, RF `n_estimators=100 /
  max_depth=12 / min_samples_split=5 / class_weight=balanced / random_state=42`,
  the six attack vectors + shares (Table VII), meter **100 Kbps**, VLAN **99**,
  drop priority **200**, baseline latencies **45/30/15 s**, **10** Monte Carlo
  trials, the five metric definitions, Eq 4 / Eq 5–9 functional forms, Algorithm 1
  control flow.
* No hyper-parameter search was run.
* The paper's reported results (96.8 / 2.30 / 1.2 / 1.5 / 98.5, Table VII CRs,
  Table VIII baseline rows) are used **only** in
  `results/reproduction_comparison.csv` and as reference overlays in the figures —
  never as inputs.
