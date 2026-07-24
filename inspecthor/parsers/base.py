"""Parser contract and registry.

A parser is sniff -> parse -> yield. Nothing else.

CONSTRAINT: the plugin interface is the backbone — a new artifact type must be
addable as a ~20-line file dropped into ``plugins/`` with NO engine, store, or
console edits. The ``@register`` decorator plus the pkgutil auto-import in
``_loader.py`` is what makes that true.

CONSTRAINT: ``parse()`` never prints and never lets one bad record abort the run.
Guard per record inside the loop; report anything the analyst needs to know
through ``ctx.hint()``.

CONSTRAINT: import optional dependencies LAZILY, inside ``parse()``. Every plugin
module is imported at registry load so its decorator runs; a top-level
``import dissect...`` would break discovery on a stdlib-only install.
"""
from __future__ import annotations

import importlib
from pathlib import Path
from typing import Iterator, Optional

from ..models import Event, ParseContext


class Parser:
    """Base class for artifact parsers."""

    name: str = "parser"                    # snake_case id; usually becomes Event.source_artifact
    display: str = "Parser"                 # human label for tables
    category: str = "generic"               # 'windows'|'linux'|'network'|'memory'|'cloud'|'browser'|'generic'
    magic: tuple[bytes, ...] = ()           # header signatures this parser claims
    path_globs: tuple[str, ...] = ()        # filename patterns, e.g. ("*.evtx",)
    kinds: tuple[str, ...] = ()             # engine sniff labels this parser claims, e.g. ("evtx",)
    requires: str = ""                      # optional-dep import name ("" = pure stdlib)
    install_hint: str = ""                  # one-line hint shown when `requires` is missing

    # True when this format omits the year or the UTC offset, so the parser needs
    # the case timezone and year worked out first. The engine parses everything
    # else, derives that context from the evidence, and only then comes back for
    # these — which is why the tool does not have to ask for --year or --tz.
    needs_time_context: bool = False

    # Confidence returned for each kind of evidence, highest wins in selection.
    CONF_MAGIC = 1.0
    CONF_KIND = 0.9
    CONF_GLOB = 0.6

    def sniff(self, path: Path, header: bytes, kind: str = "") -> float:
        """Confidence 0..1 that this parser should own ``path``.

        Runs for every parser on every file, so it must be cheap and must not
        import anything optional. Magic bytes beat the engine's sniffed kind,
        which beats a filename pattern.
        """
        if self.magic and any(header.startswith(m) for m in self.magic):
            return self.CONF_MAGIC
        if kind and kind in self.kinds:
            return self.CONF_KIND
        name = path.name.lower()
        if any(Path(name).match(g) for g in self.path_globs):
            return self.CONF_GLOB
        return 0.0

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        """Yield normalized Events.

        A generator by contract: a 100k-record EVTX must stream rather than
        materialize.
        """
        raise NotImplementedError

    def dependency_ok(self) -> tuple[bool, str]:
        """``(available, hint)`` for this parser's optional dependency."""
        if not self.requires:
            return True, ""
        try:
            importlib.import_module(self.requires)
            return True, ""
        except Exception:
            hint = self.install_hint or f"missing dependency: {self.requires}"
            return False, hint


_REGISTRY: list[type[Parser]] = []


def register(cls: type[Parser]) -> type[Parser]:
    """Class decorator: add a parser to the global registry."""
    if cls not in _REGISTRY:
        _REGISTRY.append(cls)
    return cls


def registered() -> list[type[Parser]]:
    return list(_REGISTRY)
