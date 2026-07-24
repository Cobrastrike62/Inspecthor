"""Detection overlay (YARA over artifacts, Sigma over normalized events).

Detectors are a second plugin type: they do not own a file format, they scan
everything. Adding a rule file — not Python — is the extension path.
"""
from __future__ import annotations
