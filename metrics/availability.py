"""Network Service Availability  (NA %)  -- Sec IV.F.5 / Eq 8.

    NA = ( sum_{u != v} I(Path(u, v) operational) / (N(N-1)) ) * 100

measured as the TIME-AVERAGE of the operational-path fraction over the 300 s
window (Fig 7 tracks exactly this quantity).  A directed path is non-operational
at a tick when either endpoint host is quarantined/blocked for legitimate
traffic, or the edge switch on the path is transiently saturated by an
un-contained attack burst.
"""
from __future__ import annotations

from statistics import mean
from typing import Iterable, List

from metrics.records import PathAvailabilitySample


def network_availability(samples: Iterable[PathAvailabilitySample]) -> float:
    s: List[PathAvailabilitySample] = list(samples)
    if not s:
        return float("nan")
    fracs = [100.0 * x.operational_paths / x.total_paths for x in s]
    return mean(fracs)


def availability_timeline(samples: Iterable[PathAvailabilitySample]) -> List[dict]:
    return [
        {"t_s": x.t_s,
         "availability_pct": 100.0 * x.operational_paths / x.total_paths,
         "under_attack": x.under_attack}
        for x in samples
    ]


def min_availability(samples: Iterable[PathAvailabilitySample]) -> float:
    s = list(samples)
    if not s:
        return float("nan")
    return min(100.0 * x.operational_paths / x.total_paths for x in s)
