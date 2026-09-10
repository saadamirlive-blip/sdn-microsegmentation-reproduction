#!/usr/bin/env python3
"""Mininet build of the enterprise topology testbed.

  1 core OpenFlow switch (s_core) + 3 edge switches (s1, s2, s3)
  13 hosts h1..h13, roles / segments / IPs / MACs from config/topology.yaml
  every link: 100 Mbps, 1.0 ms delay, 0% loss

Runs on Ubuntu with Mininet + Open vSwitch.

Usage:
    # connectivity demo -- built-in L2 controller, no Ryu / no ML needed:
    sudo python3 topology/topology.py --standalone --test     # pingall + exit
    sudo python3 topology/topology.py --standalone            # mininet> CLI

    # full DME testbed -- needs controller/ryu_controller.py running separately:
    sudo python3 topology/topology.py --test
    sudo python3 topology/topology.py
"""
from __future__ import annotations

import argparse
import os
import sys

# make the repo root importable no matter where this is launched from
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    from mininet.net import Mininet
    from mininet.node import OVSController, OVSSwitch, RemoteController
    from mininet.link import TCLink
    from mininet.log import info, setLogLevel
    from mininet.cli import CLI
    _HAVE_MININET = True
except Exception:  # pragma: no cover - not installed off-Ubuntu
    _HAVE_MININET = False

from common import config  # noqa: E402


def build_net(standalone: bool = False):
    """Build the topology.

    standalone=True  -> Mininet's built-in reference controller (basic L2
                        learning). `pingall` works with no Ryu app running.
    standalone=False -> RemoteController pointing at controller/ryu_controller.py
                        (start it first, or every ping drops).
    """
    if not _HAVE_MININET:
        raise SystemExit(
            "Mininet not importable. Run on Ubuntu with:  sudo apt-get install -y mininet\n"
            "and use the SYSTEM python3 (sudo python3 ...), not the venv.")

    T = config.topology()
    ctl = T["controller"]
    link = T["links"]

    of_proto = None if standalone else "OpenFlow13"
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=False)

    if standalone:
        info("*** Adding built-in reference controller (L2 learning)\n")
        c0 = net.addController("c0", controller=OVSController)
    else:
        info("*** Adding RemoteController (expects controller/ryu_controller.py)\n")
        c0 = net.addController("c0", controller=RemoteController,
                               ip=ctl["listen_ip"], port=int(ctl["listen_port"]))

    info("*** Adding switches\n")
    sw = {}
    for name, meta in T["switches"].items():
        kw = {"dpid": f'{int(meta["dpid"]):016x}'}
        if of_proto:
            kw["protocols"] = of_proto
        sw[name] = net.addSwitch(name, **kw)

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
    ap.add_argument("--test", action="store_true", help="run pingall then exit")
    ap.add_argument("--standalone", action="store_true",
                    help="use Mininet's built-in L2 controller (no Ryu app needed)")
    args = ap.parse_args()
    setLogLevel("info")
    net = build_net(standalone=args.standalone)
    try:
        if args.test:
            net.pingAll()
        else:
            info("\n*** Topology up. Attacker = h4. Critical = h2(HR) h5(DB).\n"
                 "*** Try:  pingall   |   pingallfull   |   h4 ping -c 4 h2\n")
            CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    main()
