"""inspecthor — read-only forensic timeline and artifact analysis.

Point it at an evidence folder or a Sherlock package and it fingerprints every
file, routes each to a parser plugin, and normalizes the results into a single
time-sorted event store you can search across artifact boundaries.

CONSTRAINT: this tool never writes to evidence. Artifacts are opened read-only
and hashed on ingest; all derived state lives in a separate per-case SQLite DB.
"""
from __future__ import annotations

__version__ = "0.4.0"
__all__ = ["__version__"]
