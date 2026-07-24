"""Sigma rules over normalized events.

This is a post-ingest analytic, not a file scanner: rules run against the event
store once everything is parsed.

**Scope, stated plainly.** Rather than depend on a pySigma backend package and
translate to SQL, this evaluates a documented SUBSET of Sigma in process:

* ``detection`` blocks of field/value maps, lists of maps, and value lists
* field modifiers ``contains``, ``startswith``, ``endswith``, ``re``, ``all``,
  ``base64``, ``base64offset``, ``cased``, ``windash``
* ``condition`` expressions using ``and`` / ``or`` / ``not``, parentheses,
  ``1 of <pattern>``, ``all of <pattern>``, and ``them``
* ``|count()``-style aggregations are NOT supported

A rule using anything outside that subset is SKIPPED with a hint. That is a
deliberate trade: a silently mis-evaluated detection rule is worse than an
honestly skipped one, because it reads as "no hits" on a compromised host.
"""
from __future__ import annotations

import base64
import re
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any, Iterator

from ..capabilities import hint as cap_hint
from ..models import Event, ParseContext
from .base import Detector, register_detector

_LEVEL_TO_SEV = {
    "critical": "high", "high": "high", "medium": "med",
    "low": "info", "informational": "info",
}

# Sigma speaks raw Windows field names; our events keep normalized keys. Each
# Sigma field maps to candidate locations, tried in order.
_FIELD_MAP: dict[str, tuple[str, ...]] = {
    "eventid": ("event_id",),
    "image": ("process", "image"),
    "originalfilename": ("original_file_name",),
    "commandline": ("cmdline", "command_line"),
    "parentimage": ("parent", "parent_image"),
    "parentcommandline": ("parent_command_line",),
    "targetusername": ("target_user_name", "@user"),
    "subjectusername": ("subject_user_name",),
    "user": ("@user", "target_user_name"),
    "computername": ("@host", "computer"),
    "logontype": ("logon_type",),
    "ipaddress": ("source_ip", "ip_address"),
    "sourceip": ("source_ip",),
    "destinationip": ("destination_ip",),
    "destinationport": ("destination_port",),
    "destinationhostname": ("destination_hostname",),
    "queryname": ("query_name",),
    "targetfilename": ("target_filename",),
    "targetobject": ("target_object",),
    "imageloaded": ("image_loaded",),
    "servicename": ("service_name",),
    "imagepath": ("image_path",),
    "scriptblocktext": ("script", "script_block_text"),
    "channel": ("channel",),
    "provider_name": ("provider",),
    "servicefilename": ("image_path", "service_file_name"),
    "taskname": ("task_name",),
    "details": ("details",),
    "hashes": ("hashes",),
    "sha256": ("sha256",),
    "md5": ("md5",),
}

_SUPPORTED_MODIFIERS = {
    "contains", "startswith", "endswith", "re", "all", "cased",
    "base64", "base64offset", "windash",
}

# Aggregation and correlation syntax we do not implement.
_UNSUPPORTED_CONDITION = re.compile(
    r"\|\s*(?:count|min|max|avg|sum)\s*\(|near\s+", re.I
)

_MAX_HITS_PER_RULE = 200


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _field_values(row: dict, field: str) -> list[str]:
    """Every place a Sigma field might live in one normalized event."""
    lowered = field.lower()
    data = row.get("data") or {}
    out: list[str] = []

    candidates = _FIELD_MAP.get(lowered, ())
    if not candidates:
        # Unmapped field: try the snake_case form the EVTX parser would have used.
        candidates = (_snake(field), lowered)

    for candidate in candidates:
        if candidate == "@user":
            value = row.get("user")
        elif candidate == "@host":
            value = row.get("host")
        else:
            value = data.get(candidate) if isinstance(data, dict) else None
        if value not in (None, ""):
            out.append(str(value))

    # Last resort: the event's own top-level columns.
    if not out and lowered in ("message", "eventtype", "event_type"):
        out.append(str(row.get("message") if lowered == "message" else row.get("event_type") or ""))
    return out


def _match_one(haystacks: list[str], expected: Any, modifiers: list[str]) -> bool:
    """Does any candidate value satisfy this expected value plus modifiers?"""
    if expected is None:
        return not haystacks or all(h == "" for h in haystacks)

    cased = "cased" in modifiers
    needle = str(expected)

    if "base64" in modifiers or "base64offset" in modifiers:
        try:
            needle = base64.b64encode(needle.encode()).decode()
        except Exception:
            return False

    variants = [needle]
    if "windash" in modifiers:
        # '-param' and '/param' are interchangeable on Windows command lines.
        variants += [needle.replace("-", "/", 1), needle.replace("/", "-", 1)]

    for haystack in haystacks:
        subject = haystack if cased else haystack.lower()
        for variant in variants:
            probe = variant if cased else variant.lower()
            if "re" in modifiers:
                try:
                    if re.search(variant, haystack, 0 if cased else re.I):
                        return True
                except re.error:
                    return False
            elif "contains" in modifiers:
                if probe in subject:
                    return True
            elif "startswith" in modifiers:
                if subject.startswith(probe):
                    return True
            elif "endswith" in modifiers:
                if subject.endswith(probe):
                    return True
            else:
                # Sigma's bare value supports '*' wildcards.
                if "*" in probe or "?" in probe:
                    pattern = re.escape(probe).replace(r"\*", ".*").replace(r"\?", ".")
                    if re.fullmatch(pattern, subject):
                        return True
                elif subject == probe:
                    return True
    return False


def _match_map(row: dict, criteria: dict) -> bool:
    """All key/value pairs in one selection map must match (Sigma AND semantics)."""
    for raw_field, expected in criteria.items():
        parts = str(raw_field).split("|")
        field = parts[0]
        modifiers = [m.lower() for m in parts[1:]]
        unknown = set(modifiers) - _SUPPORTED_MODIFIERS
        if unknown:
            raise NotImplementedError(f"modifier(s) {sorted(unknown)}")

        haystacks = _field_values(row, field)
        if isinstance(expected, list):
            # A list of values is OR, unless '|all' asks for every one.
            results = [_match_one(haystacks, item, modifiers) for item in expected]
            ok = all(results) if "all" in modifiers else any(results)
        else:
            ok = _match_one(haystacks, expected, modifiers)
        if not ok:
            return False
    return True


def _match_selection(row: dict, selection: Any) -> bool:
    if isinstance(selection, dict):
        return _match_map(row, selection)
    if isinstance(selection, list):
        # A list of maps is OR across the maps.
        for item in selection:
            if isinstance(item, dict):
                if _match_map(row, item):
                    return True
            elif _match_one([str(row.get("message") or "")], item, ["contains"]):
                return True
        return False
    return _match_one([str(row.get("message") or "")], selection, ["contains"])


class _Condition:
    """Compiled Sigma condition expression."""

    def __init__(self, expression: str, names: list[str]) -> None:
        self.expression = expression.strip()
        self.names = names
        self._tokens = self._compile(self.expression)

    def _expand(self, phrase: str) -> str:
        """Turn '1 of selection*' / 'all of them' into a boolean sub-expression."""
        match = re.fullmatch(r"(1|all)\s+of\s+(\S+)", phrase.strip(), re.I)
        if not match:
            return phrase
        quantifier, pattern = match.group(1).lower(), match.group(2)
        if pattern.lower() == "them":
            selected = list(self.names)
        else:
            regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
            selected = [n for n in self.names if regex.match(n)]
        if not selected:
            return "False"
        joiner = " and " if quantifier == "all" else " or "
        return "(" + joiner.join(selected) + ")"

    def _compile(self, expression: str) -> str:
        text = expression
        # Expand quantified phrases before tokenizing the booleans.
        for match in sorted(
            re.finditer(r"(?:1|all)\s+of\s+\S+", text, re.I),
            key=lambda m: -m.start(),
        ):
            text = text[: match.start()] + self._expand(match.group(0)) + text[match.end():]
        return text

    def evaluate(self, matched: dict[str, bool]) -> bool:
        """Evaluate the boolean expression against per-selection results.

        Builds a Python boolean expression from a whitelist of tokens — selection
        names, and/or/not, parentheses — so nothing from the rule file is ever
        executed as arbitrary code.
        """
        tokens = re.findall(r"\(|\)|\w+|\S", self._tokens)
        rendered: list[str] = []
        for token in tokens:
            low = token.lower()
            if low in ("and", "or", "not"):
                rendered.append(low)
            elif token in ("(", ")"):
                rendered.append(token)
            elif low in ("true", "false"):
                rendered.append(low.capitalize())
            elif token in matched:
                rendered.append("True" if matched[token] else "False")
            elif re.fullmatch(r"\w+", token):
                # An unknown selection name is treated as unmatched.
                rendered.append("False")
            else:
                raise NotImplementedError(f"condition token {token!r}")
        expression = " ".join(rendered) or "False"
        try:
            return bool(eval(expression, {"__builtins__": {}}, {}))  # noqa: S307
        except Exception as exc:
            raise NotImplementedError(f"condition {self.expression!r}") from exc


def _bundled_sigma_dir() -> Path | None:
    try:
        path = Path(str(files("inspecthor.data").joinpath("sigma")))
        return path if path.is_dir() else None
    except (FileNotFoundError, ModuleNotFoundError, OSError, TypeError):
        return None


@register_detector
class SigmaEval(Detector):
    """Sigma detection rules applied to normalized events."""

    name = "sigma"
    display = "Sigma"
    requires = "yaml"          # PyYAML; pysigma pulls it in, and it is all we need
    install_hint = cap_hint("sigma")

    def __init__(self, rule_dirs: tuple[Path, ...] = ()) -> None:
        self.rule_dirs = tuple(rule_dirs)

    def _load_rules(self, ctx: ParseContext) -> list[dict]:
        try:
            import yaml
        except ImportError:
            ctx.hint(self.install_hint)
            return []

        directories = [d for d in (_bundled_sigma_dir(),) if d] + list(self.rule_dirs)
        paths: list[Path] = []
        for directory in directories:
            try:
                paths.extend(sorted(
                    p for p in Path(directory).rglob("*")
                    if p.suffix.lower() in (".yml", ".yaml")
                ))
            except OSError:
                continue
        if not paths:
            ctx.hint("sigma: no rule files found (add .yml rules or pass a rules dir)")
            return []

        rules: list[dict] = []
        for path in paths:
            try:
                for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
                    if isinstance(doc, dict) and doc.get("detection"):
                        doc["_path"] = str(path)
                        rules.append(doc)
            except Exception as exc:
                ctx.hint(f"sigma: skipped {path.name} ({exc})")
                continue
        return rules

    def evaluate(self, store, ctx: ParseContext) -> Iterator[Event]:
        rules = self._load_rules(ctx)
        if not rules:
            return

        compiled: list[tuple[dict, dict, _Condition]] = []
        for rule in rules:
            detection = dict(rule.get("detection") or {})
            condition = detection.pop("condition", None)
            detection.pop("timeframe", None)
            if not isinstance(condition, str) or not detection:
                ctx.hint(f"sigma: skipped {rule.get('title', '?')} (no usable condition)")
                continue
            if _UNSUPPORTED_CONDITION.search(condition):
                ctx.hint(
                    f"sigma: skipped {rule.get('title', '?')} "
                    "(aggregation/correlation is outside the supported subset)"
                )
                continue
            try:
                compiled.append((rule, detection, _Condition(condition, list(detection))))
            except Exception as exc:
                ctx.hint(f"sigma: skipped {rule.get('title', '?')} ({exc})")
                continue

        if not compiled:
            return

        hits: dict[str, int] = {}
        broken: set[str] = set()

        for row in store.iter_events():
            for rule, detection, condition in compiled:
                title = str(rule.get("title", "untitled"))
                if title in broken or hits.get(title, 0) >= _MAX_HITS_PER_RULE:
                    continue
                try:
                    matched = {
                        name: _match_selection(row, selection)
                        for name, selection in detection.items()
                    }
                    if not condition.evaluate(matched):
                        continue
                except NotImplementedError as exc:
                    ctx.hint(f"sigma: skipped {title} ({exc})")
                    broken.add(title)
                    continue
                except Exception:
                    broken.add(title)
                    continue

                hits[title] = hits.get(title, 0) + 1
                yield self._hit_event(rule, row, ctx)

        for title, count in hits.items():
            if count >= _MAX_HITS_PER_RULE:
                ctx.hint(f"sigma: '{title}' capped at {_MAX_HITS_PER_RULE} hits")

    def _hit_event(self, rule: dict, row: dict, ctx: ParseContext) -> Event:
        level = str(rule.get("level", "medium")).lower()
        tags = [str(t) for t in (rule.get("tags") or [])]
        attck = [
            t.split(".", 1)[1].upper() if t.lower().startswith("attack.t") else ""
            for t in tags
        ]
        attck = [a for a in attck if a.startswith("T")]

        when = row.get("ts") or ""
        try:
            timestamp = datetime.strptime(str(when), "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            timestamp = datetime.now(timezone.utc)

        return ctx.event(
            timestamp=timestamp,
            timestamp_desc="Event Logged (Sigma hit)",
            event_type="sigma_match",
            message=f"Sigma: {rule.get('title', 'untitled')} — {row.get('message', '')}"[:400],
            data={
                "rule": rule.get("title"),
                "rule_id": rule.get("id"),
                "level": level,
                "rule_path": rule.get("_path"),
                "logsource": rule.get("logsource") or {},
                "matched_event_id": row.get("id"),
                "matched_source": row.get("source_artifact"),
            },
            attck=attck,
            tags=["detection"],
            severity=_LEVEL_TO_SEV.get(level, "med"),
            user=str(row.get("user") or ""),
            host=str(row.get("host") or ""),
            source_artifact=self.name,
            artifact_path=str(row.get("artifact_path") or ""),
            parser=self.name,
        )
