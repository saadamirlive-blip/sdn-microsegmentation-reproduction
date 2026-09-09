"""Dynamic Microsegmentation Engine -- Ryu OF 1.3 controller app.

Closed loop (Fig 5), Ubuntu 22.04 testbed:

  L2 learning switch  +  every 3.0 s:
    OFPFlowStatsRequest -> parse -> 6-D features -> RandomForest(model.pkl)
      -> host risk score R_i(t) (Eq 4) -> Algorithm 1 (common.policy_engine)
      -> OFPFlowMod / OFPMeterMod (controller.openflow_rules)
      -> append a telemetry + decision row to results/testbed/telemetry_<ts>.csv

Run:
    ryu-manager controller/ryu_controller.py
"""
from __future__ import annotations

import csv
import importlib
import importlib.util
import os
import sys
import time

import joblib

# --- Ryu / os-ken backend shim (mirror of controller/__init__.py, inlined so it
#     runs even when ryu-manager / osken-manager loads this file directly) ------
try:  # pragma: no cover
    import ryu  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    from importlib.abc import Loader, MetaPathFinder

    class _OsKenAsRyu(MetaPathFinder, Loader):
        def find_spec(self, name, path=None, target=None):
            if name == "ryu" or name.startswith("ryu."):
                return importlib.util.spec_from_loader(name, self)
            return None

        def create_module(self, spec):
            mod = importlib.import_module("os_ken" + spec.name[len("ryu"):])
            sys.modules[spec.name] = mod
            return mod

        def exec_module(self, module):
            pass

    import os_ken  # noqa: F401  -- raises if neither backend is installed
    if not any(isinstance(f, _OsKenAsRyu) for f in sys.meta_path):
        sys.meta_path.insert(0, _OsKenAsRyu())

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3

from common import config
from common.policy_engine import run_dmca
from common.risk_engine import RiskSignals, derive_signals_from_flow
from controller.openflow_rules import to_flow_mod, to_meter_mod
from controller.telemetry import (POLLING_INTERVAL_S, build_flow_stats_request,
                                  parse_flow_stats_reply)

_MODEL_DIR = config.model_dir()


class DynamicMicrosegmentationEngine(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]      # OpenFlow 1.3

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self._prev_stats = {}
        self.clf = joblib.load(_MODEL_DIR / "model.pkl")
        self.scaler = joblib.load(_MODEL_DIR / "scaler.pkl")
        self.compromised_hosts = set()
        outdir = config.results_dir() / "testbed"
        outdir.mkdir(parents=True, exist_ok=True)
        self._log_path = outdir / f"telemetry_{int(time.time())}.csv"
        with open(self._log_path, "w", newline="") as fh:
            csv.writer(fh).writerow(
                ["poll_ts", "dpid", "flow_id", "src_ip", "dst_ip", "protocol",
                 "pps", "bps", "duration_s", "p_attack", "risk_score",
                 "compromised", "action"])
        self.monitor_thread = hub.spawn(self._poll_loop)
        self.logger.info("DME up: OF1.3, telemetry every %.1fs, model=%s",
                         POLLING_INTERVAL_S, _MODEL_DIR / "model.pkl")

    # --- switch bring-up: table-miss -> controller --------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        p = dp.ofproto_parser
        match = p.OFPMatch()
        actions = [p.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER,
                                     dp.ofproto.OFPCML_NO_BUFFER)]
        inst = [p.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=0, match=match, instructions=inst))
        self.datapaths[dp.id] = dp

    # --- L2 learning ------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        p = dp.ofproto_parser
        in_port = msg.match["in_port"]
        from ryu.lib.packet import packet, ethernet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        self.mac_to_port.setdefault(dp.id, {})[eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, dp.ofproto.OFPP_FLOOD)
        actions = [p.OFPActionOutput(out_port)]
        if out_port != dp.ofproto.OFPP_FLOOD:
            match = p.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            inst = [p.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
            dp.send_msg(p.OFPFlowMod(datapath=dp, priority=1, match=match,
                                     idle_timeout=15, instructions=inst))
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions,
                                   data=msg.data if msg.buffer_id == dp.ofproto.OFP_NO_BUFFER else None))

    # --- 3.0 s telemetry poll ------------------------------------------
    def _poll_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                dp.send_msg(build_flow_stats_request(dp))
            hub.sleep(POLLING_INTERVAL_S)          # 3.0 -- KEEP EXACT

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _stats_reply(self, ev):
        dp = ev.msg.datapath
        flows = parse_flow_stats_reply(ev.msg.body, dpid=dp.id, prev=self._prev_stats)
        if not flows:
            return

        def predict_proba(X):
            return self.clf.predict_proba(self.scaler.transform(X))[:, 1]

        def signal_lookup(f: RiskSignals):  # noqa: ANN001
            return derive_signals_from_flow(
                pps=f.pps, distinct_dst=int(f.meta.get("distinct_dst", 1)),
                failed_auth=int(f.meta.get("failed_auth", 0)))

        result = run_dmca(flows, predict_proba, signal_lookup=signal_lookup)
        self.compromised_hosts |= result.compromised_hosts

        ts = time.time()
        rows = []
        for f, d in zip(flows, result.decisions):
            if d.action.name != "MONITOR":
                rule = d.rule
                try:
                    if rule.kind == "meter_mod":
                        dp.send_msg(to_meter_mod(dp, rule))
                    dp.send_msg(to_flow_mod(dp, rule))
                except Exception as exc:  # pragma: no cover
                    self.logger.warning("rule push failed: %s", exc)
            rows.append([f"{ts:.3f}", dp.id, f.flow_id, f.src_ip, f.dst_ip, f.protocol,
                         f"{f.pps:.4f}", f"{f.bps:.4f}", f"{f.duration_s:.3f}",
                         f"{d.p_attack:.4f}", f"{d.risk_score:.2f}",
                         int(d.compromised), d.action.name])
        with open(self._log_path, "a", newline="") as fh:
            csv.writer(fh).writerows(rows)
