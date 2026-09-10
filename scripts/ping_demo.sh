#!/usr/bin/env bash
# =============================================================================
# ping_demo.sh -- show connectivity between all 13 hosts in the topology.
# Ubuntu 22.04/24.04 with Mininet + OVS. Starts the SDN controller, builds the
# topology, runs `pingall`, then tears everything down.
#
#   sudo ./scripts/ping_demo.sh
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

PY="${PYTHON:-python3}"

command -v mn >/dev/null || { echo "Mininet not found. Install: sudo apt-get install -y mininet"; exit 1; }

# start OVS if it isn't already up
sudo ovs-vsctl show >/dev/null 2>&1 || sudo /usr/share/openvswitch/scripts/ovs-ctl start || \
  sudo service openvswitch-switch start || true

# pick a controller manager
if   command -v ryu-manager   >/dev/null; then MANAGER=ryu-manager
elif command -v osken-manager >/dev/null; then MANAGER=osken-manager
else echo "no ryu-manager / osken-manager -- pip install -r requirements-testbed.txt"; exit 1
fi

[ -f results/model/model.pkl ] || $PY -m ml.train_rf

echo "[1] starting controller ($MANAGER) ..."
"$MANAGER" controller/ryu_controller.py >/tmp/ryu.log 2>&1 &
RYU_PID=$!
trap 'kill $RYU_PID 2>/dev/null || true; sudo mn -c >/dev/null 2>&1 || true' EXIT
sleep 3

echo "[2] building topology + pingall ..."
sudo "$PY" topology/topology.py --test

echo "[3] done. (controller log: /tmp/ryu.log)"
