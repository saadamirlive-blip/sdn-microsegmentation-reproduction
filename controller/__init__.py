"""Ryu SDN controller package (Ubuntu 22.04 testbed).

  ryu_controller.py  -- the Ryu app (OF 1.3): L2 learning + 3.0 s telemetry
                        polling + DME closed loop
  telemetry.py       -- flow-stats polling / parsing / unit normalisation
  openflow_rules.py  -- rule structs -> real OFPFlowMod / OFPMeterMod

The feature / risk / policy logic is the shared `common/` code -- the controller
imports it directly; only the data plane is real here.

--------------------------------------------------------------------------------
Ryu backend compatibility
--------------------------------------------------------------------------------
The paper specifies the Ryu SDN Framework (MODELING_NOTES.md #1 pins v4.34, the last
release). Ryu 4.34 (Jan 2020) is unmaintained and no longer builds/installs on
modern Python toolchains (setuptools >= 58 removed `easy_install.get_script_args`;
`uv` rejects its `0.0.0` sdist metadata).

If the real ``ryu`` package is importable it is used unchanged -- the paper-
faithful path. Otherwise, when ``os_ken`` (the actively-maintained Ryu fork with
a byte-compatible API, `pip install os-ken`) is present, the shim below aliases
``ryu.*`` -> ``os_ken.*`` so ``controller/*.py`` runs untouched.

This is a DOCUMENTED SUBSTITUTION (recorded in MODELING_NOTES.md #1), used only when
Ryu itself cannot be installed. It changes the controller runtime, not the
methodology: identical OpenFlow 1.3 messages, identical DME logic.
``controller.SDN_BACKEND`` reports which one is active.
"""
from __future__ import annotations

import importlib
import importlib.util
import sys
from importlib.abc import Loader, MetaPathFinder


class _OsKenAsRyu(MetaPathFinder, Loader):
    """Route every ``ryu`` / ``ryu.<sub>`` import to the ``os_ken`` equivalent."""

    def find_spec(self, name, path=None, target=None):  # noqa: D401
        if name == "ryu" or name.startswith("ryu."):
            return importlib.util.spec_from_loader(name, self)
        return None

    def create_module(self, spec):
        real_name = "os_ken" + spec.name[len("ryu"):]
        module = importlib.import_module(real_name)
        sys.modules[spec.name] = module
        return module

    def exec_module(self, module):  # already executed by import_module above
        pass


def _install_backend() -> str | None:
    try:
        import ryu  # noqa: F401
        return "ryu"
    except ModuleNotFoundError:
        pass
    try:
        import os_ken  # noqa: F401
    except ModuleNotFoundError:
        return None
    if not any(isinstance(f, _OsKenAsRyu) for f in sys.meta_path):
        sys.meta_path.insert(0, _OsKenAsRyu())
    return "os_ken"


SDN_BACKEND = _install_backend()
"""'ryu', 'os_ken' (drop-in fork), or None (no controller backend installed)."""
