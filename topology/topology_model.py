"""Pure-Python graph model of the enterprise testbed  (Fig 2, Sec III.B / IV.B).

G = (V, E, W),  V = H u S u {C}
  s_core  +  {s1, s2, s3}   (1 core + 3 edge OpenFlow switches)
  h1..h13                    (13 host endpoints)

Used by the simulation for:
  * routing a flow src->dst through switches (which edge switch sees it),
  * enumerating the N(N-1) = 156 directed host-to-host paths for the
    Network Availability metric (Sec IV.F.5),
  * mapping host -> segment / role / server-ness / criticality.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from common import config

_T = config.topology()


@dataclass(frozen=True)
class Host:
    name: str
    switch: str
    ip: str
    mac: str
    base_vlan: int
    role: str
    server: bool


@dataclass
class TopologyModel:
    hosts: Dict[str, Host]
    switches: Dict[str, dict]
    switch_links: List[Tuple[str, str]]
    core: str = "s_core"
    attacker: str = "h4"
    critical_hosts: List[str] = field(default_factory=list)

    # --- lookups -------------------------------------------------------------
    def host_names(self) -> List[str]:
        return sorted(self.hosts, key=lambda h: int(h[1:]))

    def edge_switch_of(self, host: str) -> str:
        return self.hosts[host].switch

    def segment_of(self, host: str) -> str:
        return self.switches[self.hosts[host].switch].get("segment", "CORE")

    def path_switches(self, src: str, dst: str) -> List[str]:
        """Switch hop list for a src->dst flow (star through the core)."""
        ss, ds = self.edge_switch_of(src), self.edge_switch_of(dst)
        if ss == ds:
            return [ss]
        return [ss, self.core, ds]

    def directed_host_pairs(self) -> List[Tuple[str, str]]:
        """All ordered (u, v), u != v  ->  N(N-1) = 156 pairs."""
        return [(u, v) for u, v in itertools.permutations(self.host_names(), 2)]

    def n_directed_paths(self) -> int:
        n = len(self.hosts)
        return n * (n - 1)

    def is_server(self, host: str) -> bool:
        return self.hosts[host].server

    def is_critical(self, host: str) -> bool:
        return host in self.critical_hosts


def load_topology() -> TopologyModel:
    hosts = {
        name: Host(
            name=name, switch=h["switch"], ip=h["ip"], mac=h["mac"],
            base_vlan=int(h["base_vlan"]), role=h["role"], server=bool(h.get("server", False)),
        )
        for name, h in _T["hosts"].items()
    }
    model = TopologyModel(
        hosts=hosts,
        switches=_T["switches"],
        switch_links=[tuple(x) for x in _T["switch_links"]],
        core="s_core",
        attacker=_T["attacker_host"],
        critical_hosts=list(_T["critical_hosts"]),
    )
    assert len(model.hosts) == int(_T["host_count"]) == 13
    assert model.n_directed_paths() == int(_T["directed_path_count"]) == 156
    return model
