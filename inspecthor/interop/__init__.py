"""Interoperability with the Matrix case framework.

Inspecthor is standalone: it bundles its own ATT&CK copy and never requires
Matrix to be installed. When Matrix IS co-located it prefers Matrix's ATT&CK DB
so both tools validate technique IDs against the same version, and it can emit
cases Matrix's ``import`` accepts.
"""
from __future__ import annotations
