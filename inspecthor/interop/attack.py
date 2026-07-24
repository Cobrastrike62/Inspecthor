"""MITRE ATT&CK lookup and validation.

CONSTRAINT: never surface or persist a technique id the database does not know.
A typo or a retired id poisons the Navigator layer and any export downstream, and
it is far cheaper to drop it at the point of creation than to explain a phantom
technique in a report.

Resolution prefers a co-located Matrix installation so both tools agree on one
ATT&CK version, but a bundled copy means inspecthor never *requires* Matrix.
"""
from __future__ import annotations

import json
import os
from importlib.resources import files
from pathlib import Path
from typing import Any, Iterable, Optional

_ENV_DB = "INSPECTHOR_ATTACK_DB"
_ENV_MATRIX = "MATRIX_HOME"
_REL = Path("data") / "attack" / "enterprise.json"


def _candidate_paths() -> list[Path]:
    """Search order, most explicit first."""
    out: list[Path] = []

    explicit = os.environ.get(_ENV_DB)
    if explicit:
        out.append(Path(explicit))

    matrix_home = os.environ.get(_ENV_MATRIX)
    if matrix_home:
        out.append(Path(matrix_home) / _REL)

    # A sibling Matrix checkout: .../Projects/Inspecthor and .../Projects/Matrix.
    here = Path(__file__).resolve()
    for parent in list(here.parents)[:6]:
        out.append(parent.parent / "Matrix" / _REL)
        out.append(parent / "Matrix" / _REL)
    out.append(Path.cwd().parent / "Matrix" / _REL)

    return out


def resolve_attack_db() -> tuple[Optional[Path], str]:
    """Return ``(path, origin)``. ``origin`` is 'matrix' or 'bundled'."""
    for candidate in _candidate_paths():
        try:
            if candidate.is_file():
                return candidate, "matrix"
        except OSError:
            continue
    try:
        bundled = files("inspecthor.data").joinpath("attack/enterprise.json")
        if bundled.is_file():
            return Path(str(bundled)), "bundled"
    except (FileNotFoundError, ModuleNotFoundError, OSError, TypeError):
        pass
    return None, "none"


class AttackDB:
    """Lazy-loading ATT&CK technique index.

    Loading is deferred because most commands never touch ATT&CK, and the slim
    database is still ~1.2 MB of JSON.
    """

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path else None
        self._origin = "explicit" if path else ""
        self._db: dict | None = None
        self._index: dict[str, dict] = {}

    def _load(self) -> dict:
        if self._db is not None:
            return self._db
        if self._path is None:
            self._path, self._origin = resolve_attack_db()
        if self._path is None:
            self._db = {"techniques": [], "tactics": [], "attack_version": "none"}
            return self._db
        try:
            self._db = json.loads(Path(self._path).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._db = {"techniques": [], "tactics": [], "attack_version": "unreadable"}
        self._index = {
            str(t.get("id", "")).upper(): t
            for t in self._db.get("techniques", [])
            if t.get("id")
        }
        return self._db

    # ---- properties ----

    @property
    def loaded(self) -> bool:
        self._load()
        return bool(self._index)

    @property
    def version(self) -> str:
        return str(self._load().get("attack_version", "?"))

    @property
    def origin(self) -> str:
        self._load()
        return self._origin or "none"

    @property
    def source(self) -> str:
        self._load()
        return str(self._path) if self._path else "(none)"

    @property
    def counts(self) -> dict:
        return dict(self._load().get("counts", {}))

    # ---- lookup ----

    def find(self, technique_id: str) -> Optional[dict]:
        """Exact lookup, case-insensitive."""
        self._load()
        return self._index.get(str(technique_id).strip().upper())

    def valid(self, ids: Iterable[str] | None) -> list[str]:
        """Filter to known ids, uppercased, deduped, original order preserved."""
        if not ids:
            return []
        self._load()
        # With no database available, normalize but do not silently discard —
        # dropping everything would quietly strip ATT&CK from a whole case.
        if not self._index:
            out, seen = [], set()
            for raw in ids:
                tid = str(raw).strip().upper()
                if tid and tid not in seen:
                    seen.add(tid)
                    out.append(tid)
            return out
        out, seen = [], set()
        for raw in ids:
            tid = str(raw).strip().upper()
            if tid in self._index and tid not in seen:
                seen.add(tid)
                out.append(tid)
        return out

    def name_of(self, technique_id: str) -> str:
        technique = self.find(technique_id)
        return str(technique.get("name", "")) if technique else ""

    def describe(self, technique_id: str) -> dict:
        """Everything known about one technique, for a detail view."""
        technique = self.find(technique_id)
        if not technique:
            return {}
        return {
            "id": technique.get("id"),
            "name": technique.get("name"),
            "sub": technique.get("sub"),
            "parent": technique.get("parent"),
            "tactics": technique.get("tactics", []),
            "platforms": technique.get("platforms", []),
            "detection": technique.get("detection", ""),
            "description": technique.get("description", ""),
            "url": technique.get("url", ""),
        }

    def search(self, query: str, limit: int = 20) -> list[dict]:
        """Rank techniques by keyword or id match."""
        self._load()
        needle = query.strip().lower()
        if not needle:
            return []
        scored: list[tuple[int, dict]] = []
        for technique in self._db.get("techniques", []):
            tid = str(technique.get("id", "")).lower()
            name = str(technique.get("name", "")).lower()
            description = str(technique.get("description", "")).lower()
            score = 0
            if needle == tid:
                score = 100
            elif tid.startswith(needle):
                score = 80
            elif needle in name:
                score = 60 - name.index(needle)
            elif needle in description:
                score = 20
            if score:
                scored.append((score, technique))
        scored.sort(key=lambda item: (-item[0], str(item[1].get("id"))))
        return [t for _s, t in scored[:limit]]
