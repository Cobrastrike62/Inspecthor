"""Optional-dependency probing.

Single source of truth for "can we parse X, and if not, what do I type to fix it".
Parsers reference a capability by name instead of hardcoding install strings, so
an extra can be renamed in one place.

CONSTRAINT: silent library. ``hint()`` returns the string; the console prints it.
"""
from __future__ import annotations

import importlib.util
import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    name: str
    modules: tuple[str, ...]      # any one present satisfies it (primary, then fallbacks)
    binary: str | None            # an external tool that would also do
    extra: str | None             # pip extra that installs it
    apt: str | None               # system package, when pip is not the route
    unlocks: str                  # human description for the tools view


CAPABILITIES: tuple[Capability, ...] = (
    Capability("evtx", ("dissect.eventlog", "Evtx"), None, "evtx", None,
               "Windows Event Logs (.evtx)"),
    Capability("registry", ("dissect.regf", "regipy"), None, "registry", None,
               "Registry hives, amcache/shimcache"),
    Capability("ntfs", ("dissect.ntfs",), None, "ntfs", None,
               "$MFT and $J USN journal"),
    Capability("ese", ("dissect.esedb",), None, "ese", None,
               "SRUM / ESE databases (exfil byte counts)"),
    Capability("yara", ("yara",), None, "yara", None,
               "YARA scanning of artifacts and memory"),
    Capability("sigma", ("sigma",), None, "sigma", None,
               "Sigma rules over normalized events"),
    Capability("pcap", ("scapy", "dpkt"), "tshark", "pcap", "tshark",
               "PCAP / PCAPNG network evidence"),
    Capability("memory", ("volatility3",), "vol", "memory", None,
               "Memory images via Volatility 3"),
    Capability("ioc", ("iocextract",), None, "ioc", None,
               "Richer IOC extraction than the stdlib regexes"),
)

_BY_NAME = {cap.name: cap for cap in CAPABILITIES}


def get(name: str) -> Capability | None:
    return _BY_NAME.get(name)


def _module_present(module: str) -> bool:
    """True if importable, without importing it.

    ``find_spec`` avoids the cost and side effects of a real import — some of
    these packages are heavy, and probing must stay cheap enough to run for every
    parser on startup.
    """
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def probe(cap: Capability | str) -> bool:
    """Is this capability satisfied on this machine?"""
    resolved = _BY_NAME.get(cap) if isinstance(cap, str) else cap
    if resolved is None:
        return False
    if any(_module_present(m) for m in resolved.modules):
        return True
    return bool(resolved.binary and shutil.which(resolved.binary))


def available(name: str) -> bool:
    return probe(name)


def hint(cap: Capability | str) -> str:
    """The one line that tells the analyst how to unlock this capability."""
    resolved = _BY_NAME.get(cap) if isinstance(cap, str) else cap
    if resolved is None:
        return ""
    if resolved.extra:
        return f"pip install 'inspecthor[{resolved.extra}]'   # unlocks {resolved.unlocks}"
    if resolved.apt:
        return f"apt-get install -y {resolved.apt}   # unlocks {resolved.unlocks}"
    return f"(no known install route for {resolved.name})"


def status() -> list[tuple[str, bool, str, str]]:
    """``(name, available, unlocks, hint)`` for every capability — the tools view."""
    return [
        (cap.name, probe(cap), cap.unlocks, "" if probe(cap) else hint(cap))
        for cap in CAPABILITIES
    ]
