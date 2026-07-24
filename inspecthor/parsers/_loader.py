"""Parser discovery and selection.

Auto-imports every submodule under ``plugins/`` so that dropping a
``@register``-decorated file is enough to add a parser — no engine or console
edits (the CONSTRAINT).

Named with a leading underscore so the loader never collides with a parser called
``registry`` (Windows registry hives are an artifact type here).
"""
from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import Optional

from .base import Parser, registered

_LOADED = False


def _load_all() -> None:
    global _LOADED
    if _LOADED:
        return
    from . import plugins
    for pkg in (plugins,):
        for info in pkgutil.iter_modules(pkg.__path__, pkg.__name__ + "."):
            try:
                importlib.import_module(info.name)
            except Exception:
                # A plugin that cannot even import (syntax error, missing
                # top-level dep it should not have had) must not take down
                # discovery for every other parser.
                continue
    _LOADED = True


def all_parsers() -> list[Parser]:
    _load_all()
    return [cls() for cls in registered()]


def by_name(name: str) -> Optional[Parser]:
    for parser in all_parsers():
        if parser.name == name:
            return parser
    return None


def select_parser(
    path: Path, header: bytes, kind: str = ""
) -> tuple[Optional[Parser], Optional[Parser]]:
    """Pick the parser for a fingerprinted file.

    Returns ``(chosen, best_unavailable)``:

    * ``chosen`` — highest-confidence parser whose dependency is present.
    * ``best_unavailable`` — highest-confidence parser that WOULD have claimed the
      file but is missing its optional dependency. The console turns this into
      "would parse with evtx — pip install ...", which is the difference between
      a useful hint and a silently skipped artifact.

    A parser whose ``sniff()`` raises scores 0 rather than aborting selection.
    """
    scored: list[tuple[float, Parser]] = []
    for parser in all_parsers():
        try:
            confidence = parser.sniff(path, header, kind)
        except Exception:
            confidence = 0.0
        if confidence > 0:
            scored.append((confidence, parser))

    # Stable: highest confidence first, ties broken by name so selection is
    # deterministic across runs and platforms.
    scored.sort(key=lambda item: (-item[0], item[1].name))

    chosen: Optional[Parser] = None
    unavailable: Optional[Parser] = None
    for _confidence, parser in scored:
        available, _hint = parser.dependency_ok()
        if available:
            if chosen is None:
                chosen = parser
        elif unavailable is None:
            unavailable = parser
    return chosen, unavailable
