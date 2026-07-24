"""Artifact parsers.

CONSTRAINT: the plugin interface is the backbone — a new artifact type must be
addable as a ~20-line file dropped into ``plugins/`` with NO engine, store or
console edits. The ``@register`` decorator plus pkgutil auto-import makes that
true.
"""
from __future__ import annotations
