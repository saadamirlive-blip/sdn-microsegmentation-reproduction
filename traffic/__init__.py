"""Traffic generation.

Simulation path (host-agnostic):
  traffic/benign_traffic.py   -- benign flow-telemetry generator
  traffic/attack_traffic.py   -- malicious flow-telemetry generator

Real testbed path (Ubuntu):
  traffic/iperf_generator.py  -- iPerf3 client/server orchestration
  traffic/socket_generator.py -- custom Python socket HTTP/HTTPS/SQL/file-xfer
  attacks/*.py                -- Scapy / hping3 attack scripts (h4)
"""
