"""Attack traffic scripts for the Mininet testbed (Sec IV.C.2, Table VII).

All launched from the attacker host h4.  Six vectors + a horizontal probe:

  syn_flood.py       udp_flood.py       icmp_flood.py
  mixed_ddos.py      slowloris.py       http_flood.py       horizontal_probe.py

Each exposes ``run(target_ip, duration_s, **kw)`` and a ``__main__`` CLI, and
prefers Scapy 2.5.0; the volumetric floods fall back to ``hping3`` when Scapy is
unavailable.  Attack rate profile: pps ~ N(3.0, 0.5), bps ~ N(1.5, 0.3)
(paper's normalised units -> rendered here as high-rate packet trains).
"""
