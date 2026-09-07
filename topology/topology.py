#!/usr/bin/env python3
"""Mininet build of the enterprise topology testbed  (Fig 2, Sec III.B / IV.B).

  1 Core OpenFlow switch (s_core) + 3 Edge switches (s1, s2, s3)
  13 hosts h1..h13, roles/segments per config/topology.yaml
  every link: 100 Mbps, 1.0 ms delay, 0% loss   [PAPER]

Runs ONLY on Ubuntu 22.04 with Mininet 2.3.0 + OVS 2.17.0 + a running Ryu
controller (controller/ryu_controller.py) reachable at the address in
config/topology.yaml.

Usage:
    sudo python3 topology/topology.py               # interactive CLI
    sudo python3 topology/topology.py --test        # pingall + teardown
"""
from __future__ import annotations

import argparse
import sys

try:
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.link import TCLink
    from mininet.log import setLogLevel, info
    from mininet.cli import CLI
    _HAVE_MININET = True
except Exception:  # pragma: no cover - not installed off-Ubuntu
    _HAVE_MININET = False

# allow running from repo root
sys.path.insert(0, __file__.rsplit("topology", 1)[0])
from common import config  # noqa: E402


def build_net():
    if not _HAVE_MININET:
        raise SystemExit("Mininet not available -- run this on the Ubuntu 22.04 testbed.")

    T = config.topology()
    ctl = T["controller"]
    link = T["links"]

    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=False)

    info("*** Adding Ryu controller\n")
    c0 = net.addController("c0", controller=RemoteController,
                           ip=ctl["listen_ip"], port=int(ctl["listen_port"]))

    info("*** Adding switches (OpenFlow 1.3)\n")
    sw = {}
    for name, meta in T["switches"].items():
        s = net.addSwitch(name, dpid=f'{int(meta["dpid"]):016x}', protocols="OpenFlow13")
        sw[name] = s

    info("*** Adding hosts\n")
    hosts = {}
    for name, h in T["hosts"].items():
        hosts[name] = net.addHost(name, ip=f'{h["ip"]}/24', mac=h["mac"])

    info("*** Wiring core <-> edge fabric\n")
    for a, b in T["switch_links"]:
        net.addLink(sw[a], sw[b], bw=link["bandwidth_mbps"],
                    delay=f'{link["delay_ms"]}ms', loss=link["loss_pct"],
                    max_queue_size=int(link["max_queue_size"]))

    info("*** Wiring hosts to their edge switch\n")
    for name, h in T["hosts"].items():
        net.addLink(hosts[name], sw[h["switch"]], bw=link["bandwidth_mbps"],
                    delay=f'{link["delay_ms"]}ms', loss=link["loss_pct"],
                    max_queue_size=int(link["max_queue_size"]))

    net.build()
    c0.start()
    for s in sw.values():
        s.start([c0])
    return net


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", action="store_true", help="pingall then exit")
    args = ap.parse_args()
    setLogLevel("info")
    net = build_net()
    try:
        if args.test:
            net.pingAll()
        else:
            info("\n*** Topology up. Attacker = h4. Critical = h2(HR) h5(DB).\n")
            CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
