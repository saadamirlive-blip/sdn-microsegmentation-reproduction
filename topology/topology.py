#!/usr/bin/env python3
"""Mininet build of the enterprise topology testbed.

  1 core OpenFlow switch (s_core) + 3 edge switches (s1, s2, s3)
  13 hosts h1..h13, roles / segments / IPs / MACs from config/topology.yaml
  every link: 100 Mbps, 1.0 ms delay, 0% loss

Runs on Ubuntu with Mininet + Open vSwitch. Use the SYSTEM python3 (Mininet's
bindings live in /usr/lib/python3/dist-packages, not the .venv).

Usage:
    # connectivity demo -- OVS acts as a plain learning switch, no controller,
    # no Ryu, no ML model, userspace datapath (works without the OVS kernel
    # module, e.g. inside a container):
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
from functools import partial

# make the repo root importable no matter where this is launched from
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

_MININET_ERR = None
try:
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    from mininet.nodelib import LinuxBridge
    from mininet.link import TCLink
    from mininet.log import info, setLogLevel
    from mininet.cli import CLI
    _HAVE_MININET = True
except Exception as exc:  # pragma: no cover - not installed / wrong python
    _HAVE_MININET = False
    _MININET_ERR = exc

from common import config  # noqa: E402


def _require_mininet() -> None:
    if _HAVE_MININET:
        return
    raise SystemExit(
        "Mininet is not importable from this Python.\n"
        f"  ({type(_MININET_ERR).__name__}: {_MININET_ERR})\n\n"
        "Fixes:\n"
        "  * run with the SYSTEM python3:  sudo /usr/bin/python3 topology/topology.py ...\n"
        "  * install it:                   sudo apt-get install -y mininet\n"
        "  * GitHub Codespaces / containers often lack the 'openvswitch' kernel\n"
        "    module -- the --standalone mode below uses the userspace datapath,\n"
        "    but if that also fails, run the testbed in an Ubuntu VM or WSL2.")


def build_net(standalone: bool = False, switch_kind: str = "ovs"):
    _require_mininet()
    T = config.topology()
    ctl = T["controller"]
    link = T["links"]

    if standalone:
        # no controller / Ryu / ML model -- just L2 forwarding.
        #   lxbr : Linux bridge (needs `bridge-utils`; best for containers)
        #   ovs  : OVS userspace datapath (needs ovs-vswitchd running)
        if switch_kind == "lxbr":
            # inside a container, bridged frames get pushed through iptables and
            # Docker's FORWARD DROP policy eats them -- turn that off.
            import subprocess
            for knob in ("net.bridge.bridge-nf-call-iptables",
                         "net.bridge.bridge-nf-call-ip6tables",
                         "net.bridge.bridge-nf-call-arptables"):
                subprocess.run(["sysctl", "-w", f"{knob}=0"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            switch_cls = LinuxBridge
        else:
            switch_cls = partial(OVSSwitch, failMode="standalone", datapath="user")
        net = Mininet(controller=None, switch=switch_cls, link=TCLink, autoSetMacs=False)
        c0 = None
        of_proto = None
    else:
        net = Mininet(controller=None, switch=OVSSwitch, link=TCLink, autoSetMacs=False)
        info("*** Adding RemoteController (expects controller/ryu_controller.py)\n")
        c0 = net.addController("c0", controller=RemoteController,
                               ip=ctl["listen_ip"], port=int(ctl["listen_port"]))
        of_proto = "OpenFlow13"

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
    if c0 is not None:
        c0.start()
    for s in sw.values():
        s.start([c0] if c0 is not None else [])
    return net


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--test", action="store_true", help="run pingall then exit")
    ap.add_argument("--standalone", action="store_true",
                    help="plain L2 switches, no controller / Ryu / ML model")
    ap.add_argument("--switch", choices=["ovs", "lxbr"], default="ovs",
                    help="standalone switch type: ovs (userspace datapath) or "
                         "lxbr (Linux bridge -- best inside containers)")
    args = ap.parse_args()

    _require_mininet()
    setLogLevel("info")
    net = build_net(standalone=args.standalone, switch_kind=args.switch)
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
