"""Detector contract.

A Detector is the second plugin type. Where a Parser owns one file format, a
Detector scans everything — so it is registered separately and driven by the
engine after (or alongside) parsing.

CONSTRAINT: the extension path for detection is a RULE file, not Python. Dropping
a ``.yar`` into ``data/yara/`` or a ``.yml`` into ``data/sigma/`` is the whole
process; these two classes exist so rules have somewhere to run.
"""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

from ..models import Event, ParseContext


class Detector:
    """Base class for detection engines."""

    name: str = "detector"
    display: str = "Detector"
    requires: str = ""
    install_hint: str = ""

    def available(self) -> tuple[bool, str]:
        if not self.requires:
            return True, ""
        import importlib.util
        try:
            if importlib.util.find_spec(self.requires) is not None:
                return True, ""
        except (ImportError, ValueError):
            pass
        return False, self.install_hint

    def scan(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        """Scan one artifact file. Yields detection Events."""
        return iter(())

    def evaluate(self, store, ctx: ParseContext) -> Iterator[Event]:
        """Post-ingest pass over normalized events (Sigma-style analytics).

        Separate from :meth:`scan` because rule logic that needs the whole
        timeline cannot run while artifacts are still being parsed.
        """
        return iter(())


_DETECTORS: list[type[Detector]] = []


def register_detector(cls: type[Detector]) -> type[Detector]:
    if cls not in _DETECTORS:
        _DETECTORS.append(cls)
    return cls


def registered_detectors() -> list[type[Detector]]:
    return list(_DETECTORS)


def all_detectors(only_available: bool = True) -> list[Detector]:
    """Instantiate detectors, optionally filtering to the usable ones."""
    from . import sigma_eval, yara_scan     # noqa: F401  (import registers them)
    out = []
    for cls in registered_detectors():
        detector = cls()
        if not only_available:
            out.append(detector)
            continue
        ok, _hint = detector.available()
        if ok:
            out.append(detector)
    return out
