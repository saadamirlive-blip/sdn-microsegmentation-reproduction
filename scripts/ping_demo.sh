#!/usr/bin/env bash
# =============================================================================
# ping_demo.sh -- show connectivity between all 13 hosts in the topology.
#
# Uses Mininet's built-in L2 controller (no Ryu / no ML model needed), so this
# is a pure "is the topology wired correctly" check.
#
#   sudo ./scripts/ping_demo.sh          # or:  sudo bash scripts/ping_demo.sh
#
# Needs: Ubuntu + Mininet + Open vSwitch, and the SYSTEM python3 (Mininet's
# bindings live in the system site-packages, not the .venv).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

command -v mn >/dev/null || { echo "Mininet missing:  sudo apt-get install -y mininet"; exit 1; }

# config/topology.yaml is read with PyYAML -- make sure the system python3 has it
python3 -c "import yaml" 2>/dev/null || sudo pip install --break-system-packages -q pyyaml

# bring Open vSwitch up (Codespaces have no systemd auto-start)
sudo ovs-vsctl show >/dev/null 2>&1 || {
  sudo /usr/share/openvswitch/scripts/ovs-ctl start 2>/dev/null \
    || sudo service openvswitch-switch start 2>/dev/null || true
}

sudo mn -c >/dev/null 2>&1 || true
trap 'sudo mn -c >/dev/null 2>&1 || true' EXIT

echo "*** building topology + pingall ***"
sudo python3 topology/topology.py --standalone --test
