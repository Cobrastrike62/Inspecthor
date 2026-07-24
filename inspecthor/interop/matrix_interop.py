"""Export a case into the Matrix framework.

The shapes here are not "compatible-ish" — they are copied from Matrix's own
``case.json`` and ``cmd_import``:

* timestamps use Matrix's ``now()`` format, ``"%Y-%m-%d %H:%M:%S"`` local time
* slugs use Matrix's ``slugify``: non-alphanumerics collapse to '-'
* the tarball contains ``cases/<slug>/`` because ``cmd_import`` extracts to the
  Matrix root and then derives the slug from member paths starting with ``cases/``

Getting any of those wrong produces a tarball Matrix accepts but files under the
wrong name, which is worse than one it rejects outright.
"""
from __future__ import annotations

import json
import re
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

# Matrix paints Sherlock layers orange and Challenge layers blue.
_SHERLOCK_COLOR = "#fd8d3c"
_CHALLENGE_COLOR = "#6baed6"

# Indicator types Matrix expects. Anything else is coerced to 'other' rather than
# inventing a type its UI cannot render.
_MATRIX_IOC_TYPES = {"ip", "domain", "url", "hash", "email", "file", "other"}

_TYPE_MAP = {
    "ipv4": "ip", "ipv6": "ip", "domain": "domain", "url": "url",
    "email": "email", "md5": "hash", "sha1": "hash", "sha256": "hash",
}

_NOISE_TAGS = ("private", "allowlisted", "loopback", "reserved", "multicast")


def matrix_now() -> str:
    """Matrix's ``now()`` — local time, no timezone suffix."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def slugify(name: str) -> str:
    """Matrix's ``slugify``, character for character."""
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "case"


def _ioc_type(kind: str) -> str:
    mapped = _TYPE_MAP.get(kind, kind)
    return mapped if mapped in _MATRIX_IOC_TYPES else "other"


def build_case(
    store,
    name: str,
    case_type: str = "sherlock",
    category: str = "dfir",
    difficulty: str = "",
    platforms: Iterable[str] = (),
    url: str | None = None,
    timeline_severity: str | None = "high",
    timeline_limit: int = 500,
    include_noise: bool = False,
) -> dict:
    """Build a Matrix ``case.json`` dict from an inspecthor case.

    Only notable events reach the Matrix timeline by default. Matrix's timeline is
    a hand-curated narrative rendered in a terminal; pushing 100k normalized rows
    into it would make the case unusable. The full timeline stays in the
    inspecthor database, which is the right place to query it.
    """
    from ..models import EventFilter

    stamp = matrix_now()

    rows = store.query_events(EventFilter(severity=timeline_severity, limit=timeline_limit))
    if not rows:
        rows = store.query_events(EventFilter(limit=timeline_limit))

    timeline: list[dict] = []
    seen_timeline: set[tuple[str, str]] = set()
    for row in rows:
        key = (str(row.get("ts")), str(row.get("message")))
        if key in seen_timeline:
            continue
        seen_timeline.add(key)
        timeline.append({
            "time": str(row.get("ts") or ""),
            "event": str(row.get("message") or "")[:500],
            "added": stamp,
        })

    summary = store.attck_summary()
    # One streaming pass to grab the first supporting event per technique. Looking
    # each one up separately would be O(techniques x events), which at 100k events
    # turns a report into a coffee break.
    wanted = {tid for tid, _count in summary}
    evidence_for: dict[str, str] = {}
    if wanted:
        for row in store.iter_events():
            for technique_id in row.get("attck") or []:
                if technique_id in wanted and technique_id not in evidence_for:
                    evidence_for[technique_id] = str(row.get("message") or "")[:180]
            if len(evidence_for) == len(wanted):
                break

    techniques = [
        {
            "id": technique_id,
            "note": f"{count} event(s) from inspecthor",
            "evidence": evidence_for.get(technique_id, ""),
            "added": stamp,
        }
        for technique_id, count in summary
    ]

    iocs: list[dict] = []
    for row in store.get_iocs():
        tags = row.get("tags") or []
        if not include_noise and any(t in _NOISE_TAGS for t in tags):
            continue
        iocs.append({
            "type": _ioc_type(str(row.get("type") or "")),
            "value": str(row.get("value") or ""),
            "note": f"inspecthor: {row.get('count', 0)} sighting(s)"
                    + (f" [{', '.join(tags)}]" if tags else ""),
            "added": stamp,
        })

    return {
        "name": name,
        "slug": slugify(name),
        "type": case_type,
        "category": category,
        "difficulty": difficulty,
        "platforms": list(platforms),
        "status": "active",
        "created": stamp,
        "updated": stamp,
        "tags": [],
        "flag": None,
        "url": url,
        "techniques": techniques,
        "iocs": iocs,
        "timeline": timeline,
        "questions": [],
    }


def _notes_markdown(case: dict, store) -> str:
    """The ``notes.md`` Matrix seeds beside ``case.json``."""
    lines = [
        f"# {case['name']}",
        "",
        f"- Type: {case['type']} / {case['category']}",
        f"- Imported from inspecthor: {case['created']}",
        f"- Events analyzed: {store.count_events()}",
        f"- Artifacts: {len(store.get_artifacts())}",
        "",
        "## inspecthor findings",
        "",
    ]
    if case["techniques"]:
        lines += ["### ATT&CK", ""]
        lines += [f"- **{t['id']}** — {t['note']}" + (f" — {t['evidence']}" if t["evidence"] else "")
                  for t in case["techniques"]]
        lines += [""]
    if case["iocs"]:
        lines += ["### Indicators", ""]
        lines += [f"- `{i['value']}` ({i['type']}) — {i['note']}" for i in case["iocs"][:100]]
        lines += [""]
    findings = store.get_findings()
    if findings:
        lines += ["### Detections", ""]
        lines += [f"- [{f.get('severity')}] {f.get('engine')}: {f.get('rule')} — "
                  f"{f.get('detail') or f.get('title') or ''}" for f in findings[:100]]
        lines += [""]
    lines += [
        "## Notes",
        "",
        "_The full normalized timeline stays in the inspecthor case database;"
        " query it there rather than pasting it here._",
        "",
    ]
    return "\n".join(lines)


def export_case_targz(
    store,
    name: str,
    out_path: str | Path,
    **case_kwargs: Any,
) -> tuple[str, dict]:
    """Write a ``.tar.gz`` that ``matrix.py import`` accepts.

    Returns ``(path, case_dict)``.
    """
    case = build_case(store, name, **case_kwargs)
    slug = case["slug"]
    out_path = Path(out_path)

    with tempfile.TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "cases" / slug
        (case_dir / "artifacts").mkdir(parents=True, exist_ok=True)
        # Matrix keeps artifacts out of git via a .gitkeep in that folder.
        (case_dir / "artifacts" / ".gitkeep").write_text("", encoding="utf-8")
        (case_dir / "case.json").write_text(
            json.dumps(case, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        (case_dir / "notes.md").write_text(_notes_markdown(case, store), encoding="utf-8")

        with tarfile.open(out_path, "w:gz") as tar:
            # arcname must be exactly 'cases/<slug>' — cmd_import parses the slug
            # out of the member paths.
            tar.add(case_dir, arcname=f"cases/{slug}")

    return str(out_path), case


def export_case_json(store, name: str, out_path: str | Path, **case_kwargs: Any) -> str:
    """Write just the ``case.json`` payload, for programmatic consumers."""
    case = build_case(store, name, **case_kwargs)
    out_path = Path(out_path)
    out_path.write_text(json.dumps(case, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(out_path)


def navigator_layer(
    store,
    name: str = "inspecthor case",
    case_type: str = "sherlock",
    attack_version: str = "19",
) -> dict:
    """An ATT&CK Navigator layer of the techniques observed in this case.

    Scores carry the event count so the heat map reflects where the activity
    actually concentrated, which a flat score would hide.
    """
    color = _SHERLOCK_COLOR if case_type == "sherlock" else _CHALLENGE_COLOR
    summary = store.attck_summary()
    max_count = max((count for _tid, count in summary), default=1)

    techniques = [
        {
            "techniqueID": technique_id,
            "score": count,
            "color": color,
            "comment": f"{count} event(s) — inspecthor",
            "enabled": True,
            "showSubtechniques": True,
        }
        for technique_id, count in summary
    ]

    return {
        "name": f"{name} (inspecthor)",
        "versions": {
            "attack": str(attack_version).split(".")[0],
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"inspecthor case {name} — generated {matrix_now()}",
        "sorting": 0,
        "layout": {"layout": "side", "showID": True, "showName": True},
        "hideDisabled": True,
        "techniques": techniques,
        "gradient": {"colors": ["#ffffff", color], "minValue": 0, "maxValue": max_count},
        "legendItems": [{"label": case_type, "color": color}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
    }


def write_navigator_layer(
    store, out_path: str | Path, name: str = "inspecthor case", **kwargs: Any
) -> str:
    layer = navigator_layer(store, name=name, **kwargs)
    out_path = Path(out_path)
    out_path.write_text(json.dumps(layer, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(out_path)
