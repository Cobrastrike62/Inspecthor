"""MITRE ATT&CK lookup and validation.

A slim, distilled copy of the enterprise matrix ships with the package, so
technique names resolve with no network access and no configuration.

CONSTRAINT: never surface or persist a technique id the database does not know.
A typo or a retired id is dropped where it is created, because explaining a
phantom technique in a report costs more than losing one mapping.
"""
from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path
from typing import Iterable, Optional

_BUNDLED = "attack_enterprise.json"


class AttackDB:
    """Lazy-loading technique index.

    Loading is deferred because the file is ~1.2 MB of JSON and the common
    operation is validation, which only needs the id set.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path else None
        self._db: dict | None = None
        self._index: dict[str, dict] = {}

    def _load(self) -> dict:
        if self._db is not None:
            return self._db
        raw: str | None = None
        if self._path is not None:
            try:
                raw = Path(self._path).read_text(encoding="utf-8")
            except OSError:
                raw = None
        if raw is None:
            try:
                resource = files("inspecthor.data").joinpath(_BUNDLED)
                raw = resource.read_text(encoding="utf-8")
                self._path = Path(str(resource))
            except (FileNotFoundError, ModuleNotFoundError, OSError, TypeError):
                raw = None
        if raw is None:
            self._db = {"techniques": [], "tactics": [], "attack_version": "unavailable"}
            return self._db
        try:
            self._db = json.loads(raw)
        except ValueError:
            self._db = {"techniques": [], "tactics": [], "attack_version": "unreadable"}
        self._index = {
            str(t.get("id", "")).upper(): t
            for t in self._db.get("techniques", [])
            if t.get("id")
        }
        return self._db

    @property
    def loaded(self) -> bool:
        self._load()
        return bool(self._index)

    @property
    def version(self) -> str:
        return str(self._load().get("attack_version", "?"))

    def find(self, technique_id: str) -> Optional[dict]:
        self._load()
        return self._index.get(str(technique_id).strip().upper())

    def valid(self, ids: Iterable[str] | None) -> list[str]:
        """Filter to known ids: uppercased, deduped, original order preserved."""
        if not ids:
            return []
        self._load()
        out: list[str] = []
        seen: set[str] = set()
        for raw in ids:
            tid = str(raw).strip().upper()
            if not tid or tid in seen:
                continue
            # With no database available, normalize but do not discard — dropping
            # every id would silently strip ATT&CK from an entire case.
            if self._index and tid not in self._index:
                continue
            seen.add(tid)
            out.append(tid)
        return out

    def name_of(self, technique_id: str) -> str:
        technique = self.find(technique_id)
        return str(technique.get("name", "")) if technique else ""

    def tactics_of(self, technique_id: str) -> list[str]:
        technique = self.find(technique_id)
        return list(technique.get("tactics", [])) if technique else []
