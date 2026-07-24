"""YARA scanning of raw artifacts.

Rules come from two places: the small bundled set in ``data/yara/`` and whatever
directory the analyst points at. A broken rule is skipped with a note rather than
failing the compile, because one bad rule in a downloaded pack should not disable
detection for the whole case.
"""
from __future__ import annotations

from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any, Iterator

from ..capabilities import hint as cap_hint
from ..models import Event, ParseContext
from .base import Detector, register_detector

# Scanning a memory image or disk image with YARA is useful but slow; skip the
# truly huge files unless the analyst asks for them specifically.
_MAX_SCAN_BYTES = 512 * 1024 * 1024
_MATCH_TIMEOUT = 60
_MAX_STRINGS_PER_MATCH = 5
_PREVIEW_BYTES = 32

_SEV_FROM_META = {"critical": "high", "high": "high", "medium": "med", "low": "info"}


def _bundled_rule_dir() -> Path | None:
    try:
        path = Path(str(files("inspecthor.data").joinpath("yara")))
        return path if path.is_dir() else None
    except (FileNotFoundError, ModuleNotFoundError, OSError, TypeError):
        return None


def _rule_files(extra_dirs: tuple[Path, ...] = ()) -> list[Path]:
    out: list[Path] = []
    for directory in [d for d in (_bundled_rule_dir(),) if d] + list(extra_dirs):
        try:
            out.extend(sorted(p for p in Path(directory).rglob("*")
                              if p.suffix.lower() in (".yar", ".yara")))
        except OSError:
            continue
    return out


def _attck_from_meta(meta: dict) -> list[str]:
    """Pull technique ids out of rule metadata.

    Rule authors spell this half a dozen ways, so accept the common keys and
    split on the usual separators.
    """
    found: list[str] = []
    for key in ("attack", "mitre", "mitre_attack", "mitre_att&ck", "technique", "attck"):
        raw = meta.get(key)
        if not raw:
            continue
        for token in str(raw).replace(";", ",").replace("|", ",").split(","):
            token = token.strip().upper().replace("ATTACK.", "").replace("MITRE.", "")
            if token.startswith("T") and token[1:2].isdigit():
                found.append(token)
    return found


@register_detector
class YaraScan(Detector):
    """Signature scanning over artifact bytes."""

    name = "yara"
    display = "YARA"
    requires = "yara"
    install_hint = cap_hint("yara")

    def __init__(self, rule_dirs: tuple[Path, ...] = ()) -> None:
        self.rule_dirs = tuple(rule_dirs)
        self._rules: Any = None
        self._compiled = False

    def _compile(self, ctx: ParseContext) -> Any:
        if self._compiled:
            return self._rules
        self._compiled = True
        try:
            import yara
        except ImportError:
            ctx.hint(self.install_hint)
            return None

        paths = _rule_files(self.rule_dirs)
        if not paths:
            ctx.hint("yara: no rule files found (add .yar files or pass a rules dir)")
            return None

        # Compile per file so one broken rule costs only itself.
        namespaces: dict[str, str] = {}
        for path in paths:
            try:
                yara.compile(filepath=str(path))
            except Exception as exc:
                ctx.hint(f"yara: skipped {path.name} ({exc})")
                continue
            namespaces[path.stem] = str(path)
        if not namespaces:
            return None
        try:
            self._rules = yara.compile(filepaths=namespaces)
        except Exception as exc:
            ctx.hint(f"yara: could not build ruleset ({exc})")
            self._rules = None
        return self._rules

    def scan(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        rules = self._compile(ctx)
        if rules is None:
            return
        try:
            if path.stat().st_size > _MAX_SCAN_BYTES:
                ctx.hint(f"yara: skipped {path.name} (larger than the scan cap)")
                return
        except OSError:
            return

        try:
            import yara
            matches = rules.match(filepath=str(path), timeout=_MATCH_TIMEOUT)
        except Exception as exc:
            ctx.hint(f"yara: scan failed on {path.name} ({exc})")
            return

        # A YARA hit has no event time of its own — anchor it to the artifact's
        # mtime so it lands near the activity rather than at "now".
        try:
            when = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            when = datetime.now(timezone.utc)

        for match in matches:
            meta = dict(getattr(match, "meta", {}) or {})
            strings = []
            for string_match in getattr(match, "strings", [])[:_MAX_STRINGS_PER_MATCH]:
                identifier = getattr(string_match, "identifier", "?")
                for instance in getattr(string_match, "instances", [])[:2]:
                    strings.append({
                        "id": identifier,
                        "offset": getattr(instance, "offset", None),
                        "preview": bytes(
                            getattr(instance, "matched_data", b"")[:_PREVIEW_BYTES]
                        ).hex(),
                    })
            severity = _SEV_FROM_META.get(
                str(meta.get("severity", "")).lower(), "high"
            )
            yield ctx.event(
                timestamp=when,
                timestamp_desc="Artifact mtime (YARA hit)",
                event_type="yara_match",
                message=f"YARA {match.rule} matched {path.name}",
                data={
                    "rule": match.rule,
                    "namespace": getattr(match, "namespace", ""),
                    "rule_tags": list(getattr(match, "tags", []) or []),
                    "meta": {k: str(v)[:200] for k, v in meta.items()},
                    "strings": strings,
                },
                attck=_attck_from_meta(meta),
                tags=["detection"],
                severity=severity,
                source_artifact=self.name,
                artifact_path=str(path),
                parser=self.name,
            )
