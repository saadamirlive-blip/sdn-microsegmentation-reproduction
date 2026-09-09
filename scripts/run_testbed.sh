#!/usr/bin/env bash
# =============================================================================
# run_testbed.sh -- full Mininet/Ryu testbed run (Ubuntu 22.04 LTS ONLY)
# =============================================================================
# Reproduces the paper's Phase-3 runtime on the real data plane:
#   Ryu controller  ->  Mininet Fig-2 topology  ->  benign iperf3 + socket traffic
#   ->  6 attack vectors + horizontal probe from h4  ->  telemetry CSV
#
# Requires: mininet 2.3.0, openvswitch 2.17.0, ryu (4.34), scapy 2.5.0, hping3,
#           iperf3, a Python 3.10 venv with requirements.txt + requirements-testbed.txt
#
#   sudo ./scripts/run_testbed.sh [DURATION_SECONDS]
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

DURATION="${1:-300}"
ATTACK1_AT=60         # Fig 6 attack initiation
ATTACK2_AT=120        # 
PY="${PYTHON:-python3.10}"

command -v mn >/dev/null || { echo "Mininet not found -- Ubuntu 22.04 testbed only"; exit 1; }

# paper backend is ryu-manager; os-ken's osken-manager is the documented fallback
# (Ryu 4.34 no longer installs on modern toolchains -- see controller/__init__.py)
if command -v ryu-manager >/dev/null;  then MANAGER=ryu-manager
elif command -v osken-manager >/dev/null; then MANAGER=osken-manager
else echo "neither ryu-manager nor osken-manager found -- pip install -r requirements-testbed.txt"; exit 1
fi
echo "[0] SDN controller manager: $MANAGER"

echo "[1] ensure trained model exists"
[ -f results/model/model.pkl ] || $PY -m ml.train_rf

echo "[2] start SDN controller (OF1.3, 3.0s telemetry) via $MANAGER"
"$MANAGER" controller/ryu_controller.py >/tmp/ryu.log 2>&1 &
RYU_PID=$!
trap 'kill $RYU_PID 2>/dev/null || true; mn -c >/dev/null 2>&1 || true' EXIT
sleep 3

echo "[3] build topology + drive traffic for ${DURATION}s"
sudo "$PY" - "$DURATION" "$ATTACK1_AT" "$ATTACK2_AT" <<'PYEOF'
import sys, time, threading
from mininet.log import setLogLevel
from topology.topology import build_net
from traffic import iperf_generator
from attacks import (syn_flood, udp_flood, icmp_flood, mixed_ddos,
                     slowloris, http_flood, horizontal_probe)
from common import config

DUR, A1, A2 = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
setLogLevel("info")
net = build_net()
T = config.topology()["hosts"]
h4 = net.get("h4")

# benign background (iperf3 + socket services)
iperf_generator.start(net, duration_s=DUR)
for name, h in T.items():
    if h["server"]:
        for port in (80, 443, 3306, 8080):
            net.get(name).cmd(f"python3 traffic/socket_generator.py server --port {port} &")

def burst(t0):
    time.sleep(t0)
    victim_hr, victim_db = T["h2"]["ip"], T["h5"]["ip"]
    # six vectors (Table VII) launched from h4, then the horizontal probe
    for mod, tgt, dur in [
        (syn_flood, victim_hr, 30), (udp_flood, victim_db, 25), (icmp_flood, victim_hr, 20),
        (mixed_ddos, victim_db, 25), (slowloris, T["h6"]["ip"], 40), (http_flood, T["h6"]["ip"], 25),
    ]:
        threading.Thread(target=lambda m=mod, v=tgt, d=dur: h4.cmd(
            f"python3 -m attacks.{m.__name__.split('.')[-1]} {v} --duration {d} &")).start()
    h4.cmd("python3 -m attacks.horizontal_probe --duration 20 &")

threading.Thread(target=burst, args=(A1,), daemon=True).start()
threading.Thread(target=burst, args=(A2,), daemon=True).start()

time.sleep(DUR + 10)
net.stop()
PYEOF

echo "[4] telemetry written to results/testbed/telemetry_*.csv"
echo "    feed it to: python -m experiments.run_all_trials --from-telemetry <csv>"
