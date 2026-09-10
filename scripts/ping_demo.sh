#!/usr/bin/env bash
# =============================================================================
# ping_demo.sh -- show connectivity between all 13 hosts in the topology.
#
# Plain L2 switches (userspace OVS datapath), no controller / Ryu / ML model --
# a pure "is the topology wired correctly" check.
#
#   sudo bash scripts/ping_demo.sh
#
# Needs Ubuntu + Mininet + Open vSwitch. GitHub Codespaces frequently CANNOT run
# Mininet (no 'openvswitch' kernel module, no real init) -- if this fails, run
# it in an Ubuntu VM or under WSL2.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

command -v mn >/dev/null || { echo "Mininet missing:  sudo apt-get install -y mininet"; exit 1; }

# pick the python that actually has the mininet bindings (usually /usr/bin/python3)
PYBIN=""
for p in /usr/bin/python3 /usr/bin/python3.12 /usr/bin/python3.11 /usr/bin/python3.10 python3; do
  if command -v "$p" >/dev/null 2>&1 && "$p" -c "import mininet" >/dev/null 2>&1; then
    PYBIN="$p"; break
  fi
done
[ -n "$PYBIN" ] || { echo "No python3 with the 'mininet' module found. Try: sudo apt-get install --reinstall -y mininet"; exit 1; }
echo "*** using $PYBIN ($("$PYBIN" -V 2>&1)) ***"

# config/topology.yaml is read with PyYAML
"$PYBIN" -c "import yaml" 2>/dev/null || sudo "$PYBIN" -m pip install --break-system-packages -q pyyaml

# start Open vSwitch userspace daemons (Codespaces have no systemd auto-start)
sudo ovs-vsctl show >/dev/null 2>&1 || \
  sudo /usr/share/openvswitch/scripts/ovs-ctl --system-id=random start --no-ovs-vswitchd=no 2>/dev/null || \
  sudo service openvswitch-switch start 2>/dev/null || true

sudo mn -c >/dev/null 2>&1 || true
trap 'sudo mn -c >/dev/null 2>&1 || true' EXIT

echo "*** building topology + pingall ***"
sudo "$PYBIN" topology/topology.py --standalone --test
