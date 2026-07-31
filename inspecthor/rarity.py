"""Rarity scoring: what is unusual *on this host*, with no idea what an attack is.

Everything else in this tool asks "does this match something known bad" — a curated
event map, a LOLBin regex list, a Sigma rule, a path heuristic. All of it encodes
attacks somebody already described. It was tuned against one confirmed intrusion whose
answer was known in advance, which means its measured precision is memorization and
its behaviour on the next intrusion is unmeasured.

This module asks a different question, and it is the one that survives an adversary
nobody has written up yet:

    Has this host ever done this before?

On the collection that motivated it, the implant's ``node.exe`` executed six times,
all inside twenty minutes on one day. ``chrome.exe`` executed thousands of times
across eight months. Nothing about "node" or "AppData" is needed to tell those apart —
only the host's own history, which the case database already holds in full.

Three signals, weakest to strongest:

**Binary rarity.** A binary seen on one day only, a handful of times. Real but noisy
on its own: installers and one-shot maintenance tasks look identical.

**Parent-child pair rarity.** ``powershell.exe -> node.exe`` happened once, ever.
``explorer.exe -> chrome.exe`` happened constantly. A first-ever parent/child edge is
far more discriminating than a first-ever binary, because normal software has a stable
process tree and intrusions almost never reuse one.

**Burst structure, from a parent that is itself rare.** ``NitSSMjZ.exe`` spawned twenty
``cmd.exe`` children in eight seconds. A scripted sweep is visible from the *rate*,
whatever the commands are — and the commands are the part an adversary can trivially
change.

The rare-parent qualifier is not a refinement, it is the difference between a signal
and nothing. Measured on the reference host, an absolute child-count threshold promoted
**19,817 of 24,475 process events — 80.97% — and none of them were the intrusion.**
``services.exe`` legitimately started 142 children in a minute, ``msiexec.exe`` 143,
``svchost.exe`` 80, Acrobat's renderer 23. Fan-out measures how chatty a process is,
not whether anything is wrong. Restricted to parents this host has barely ever run, the
same signal isolates the implant.

**Deliberately a multiplier, not an alarm.** Rarity alone re-flags every installer
that ever extracted to a temp directory — measured, not hypothesized: the first
version of the path scorer produced roughly 300 such false positives on one
workstation. So a rare thing is promoted one level, and only reaches ``high`` when
something independent already found it suspicious. A signal that fires on every
software install teaches an analyst to ignore the column, which is the failure this
whole exercise is about.

This runs after ingest because it needs counts over the finished case.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from .models import LEVEL_RANK, SEVERITIES

# A binary is 'rare' below these. Chosen to sit far below normal software behaviour
# rather than tightly around the measured implant: on the reference host, ordinary
# executables ran on tens of days, and the shape being caught is "existed only during
# the incident window", not "ran fewer than N times".
RARE_MAX_DAYS = 1
RARE_MAX_RUNS = 25

# A burst: this many children from one parent inside this window, from a parent whose
# whole spawning history fits in this many days. The last of the three is what makes
# the signal mean anything — see _find_bursts.
BURST_MIN_CHILDREN = 8
BURST_WINDOW_SECONDS = 60
BURST_MAX_PARENT_DAYS = 1

# Cap the promotion. Rarity can lift something into view; it may not by itself
# declare an intrusion.
RARITY_MAX_LEVEL = "med"


@dataclass
class Stats:
    """Per-binary history across the whole case."""

    runs: int = 0
    days: set[str] = field(default_factory=set)
    first_ts: str = ""
    last_ts: str = ""

    @property
    def rare(self) -> bool:
        return len(self.days) <= RARE_MAX_DAYS and self.runs <= RARE_MAX_RUNS


@dataclass
class Findings:
    """What the pass concluded, for reporting rather than for scoring."""

    scanned: int = 0
    promoted: int = 0
    rare_images: list[tuple[str, int]] = field(default_factory=list)
    rare_pairs: list[tuple[str, str, int]] = field(default_factory=list)
    bursts: list[tuple[str, str, int]] = field(default_factory=list)


def _basename(path: object) -> str:
    text = str(path or "").strip().strip('"').replace("/", "\\").lower()
    return text.rsplit("\\", 1)[-1]


def _next_level(level: str) -> str:
    """One step up, capped at RARITY_MAX_LEVEL — and never downwards.

    The cap used to be applied with a bare ``min()``, which turned a curated ``high``
    into ``med`` the moment any rarity signal touched it: a cap meant to stop this
    pass over-claiming was instead demoting findings the curated map was sure about.
    """
    current = LEVEL_RANK.get(level, 0)
    if current >= LEVEL_RANK[RARITY_MAX_LEVEL]:
        return level
    rank = min(current + 1, LEVEL_RANK[RARITY_MAX_LEVEL])
    for name in SEVERITIES:
        if LEVEL_RANK[name] == rank:
            return name
    return level


def profile(rows: Iterable[dict]) -> tuple[dict[str, Stats], dict[tuple[str, str], int],
                                           list[tuple[str, str, int]]]:
    """Build the host's execution baseline from its own process events.

    Returns per-image stats, parent->child pair counts, and detected bursts. Keyed on
    basenames, not full paths: a dropper that copies itself to a new directory each
    run would otherwise look novel every time and defeat the whole idea.
    """
    stats: dict[str, Stats] = defaultdict(Stats)
    pairs: dict[tuple[str, str], int] = defaultdict(int)
    # parent -> [(epoch, child)] for burst detection
    spawns: dict[str, list[tuple[int, str]]] = defaultdict(list)
    # A parent's fan-out history, which is what qualifies a burst. NOT the parent's
    # own execution count: services.exe and svchost.exe start once at boot, so by
    # execution count they are the rarest binaries on the host while being its most
    # prolific parents.
    parent_days: dict[str, set[str]] = defaultdict(set)

    for row in rows:
        data = row.get("data")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (ValueError, TypeError):
                data = {}
        data = data or {}

        image = _basename(data.get("new_process_name") or data.get("image"))
        if not image:
            continue
        parent = _basename(data.get("parent_process_name") or data.get("parent_image")
                           or data.get("creator_process_name"))
        ts = str(row.get("ts") or "")

        entry = stats[image]
        entry.runs += 1
        if ts:
            entry.days.add(ts[:10])
            if not entry.first_ts or ts < entry.first_ts:
                entry.first_ts = ts
            if ts > entry.last_ts:
                entry.last_ts = ts

        if parent:
            pairs[(parent, image)] += 1
            if ts:
                parent_days[parent].add(ts[:10])
            epoch = int(row.get("ts_epoch") or 0)
            if epoch:
                spawns[parent].append((epoch, image))

    bursts = _find_bursts(spawns, parent_days)
    return dict(stats), dict(pairs), bursts


def _find_bursts(spawns: dict[str, list[tuple[int, str]]],
                 parent_days: dict[str, set[str]] | None = None,
                 ) -> list[tuple[str, str, int]]:
    """Parents whose *entire* spawning history is one short burst.

    Returns (parent, window start as an epoch string, child count). A sliding window
    rather than a fixed bucket, so a sweep straddling a minute boundary is not split
    into two halves that each fall under the threshold.

    The qualification is here rather than in the scorer because it is a property of
    the data, not of the verdict. Without it this returned services.exe (142
    children), msiexec.exe (143), svchost.exe (80) and Acrobat's renderer (23) — and
    promoted 81% of one real host's process events while missing the intrusion.
    """
    out: list[tuple[str, str, int]] = []
    window_us = BURST_WINDOW_SECONDS * 1_000_000
    days = parent_days or {}
    for parent, events in spawns.items():
        if len(events) < BURST_MIN_CHILDREN:
            continue
        # Spawned on more than one day, so bursting is simply what it does.
        if len(days.get(parent, ())) > BURST_MAX_PARENT_DAYS:
            continue
        events.sort()
        start = 0
        best = 0
        best_at = events[0][0]
        for end in range(len(events)):
            while events[end][0] - events[start][0] > window_us:
                start += 1
            count = end - start + 1
            if count > best:
                best, best_at = count, events[start][0]
        if best >= BURST_MIN_CHILDREN:
            out.append((parent, str(best_at), best))
    out.sort(key=lambda item: -item[2])
    return out


def score_row(row: dict, stats: dict[str, Stats], pairs: dict[tuple[str, str], int],
              burst_parents: dict[str, int]) -> tuple[str, list[str], list[str]]:
    """Rarity verdict for one process event. Returns (level, tags, reasons)."""
    data = row.get("data")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except (ValueError, TypeError):
            data = {}
    data = data or {}

    image = _basename(data.get("new_process_name") or data.get("image"))
    parent = _basename(data.get("parent_process_name") or data.get("parent_image")
                       or data.get("creator_process_name"))
    level = str(row.get("severity") or "info")
    if not image:
        return level, [], []

    tags: list[str] = []
    reasons: list[str] = []

    entry = stats.get(image)
    if entry is None:
        # Not in the baseline at all. Cannot happen via apply(), which profiles the
        # same rows it scores, but a caller scoring one row against another host's
        # baseline is asking a meaningful question and "unknown binary" is the most
        # anomalous answer there is, not the least.
        reasons.append(f"{image} does not appear in this host's baseline at all")
        tags.append("rare_binary")
        level = _next_level(level)
    elif entry.rare:
        reasons.append(
            f"{image} ran {entry.runs}x on {len(entry.days)} day(s) in the whole case"
        )
        tags.append("rare_binary")
        level = _next_level(level)

    if parent:
        seen = pairs.get((parent, image), 0)
        if seen and seen <= 2:
            # The strongest of the three: normal software has a stable process tree.
            reasons.append(f"{parent} -> {image} happened {seen}x in the whole case")
            tags.append("rare_parent_child")
            level = _next_level(level)

    # burst_parents is already restricted to parents whose entire spawning history is
    # this one burst — _find_bursts does that, because it is a property of the data.
    # An earlier version qualified it here on the parent's own execution count and was
    # wrong twice over: services.exe and svchost.exe start once at boot, so by
    # execution count they are the host's rarest binaries and its busiest parents.
    if parent and parent in burst_parents:
        reasons.append(
            f"{parent} spawned {burst_parents[parent]} children within "
            f"{BURST_WINDOW_SECONDS}s and has never spawned anything on another day"
        )
        tags.append("spawn_burst")
        level = _next_level(level)

    return level, tags, reasons


def apply(store, limit: int = 400_000) -> Findings:
    """Second pass over process events, promoting what this host has never done.

    ``limit`` bounds the baseline scan. A case with more process events than this is
    already so large that the tail contributes nothing to a frequency judgement, and
    the cap keeps a pathological collection from turning one pass into the whole run.
    """
    from .models import EventFilter

    findings = Findings()
    rows = list(store.iter_events(chunk=5000, filt=EventFilter(event_type="process_created")))
    if not rows:
        return findings
    if len(rows) > limit:
        rows = rows[:limit]
    findings.scanned = len(rows)

    stats, pairs, bursts = profile(rows)
    burst_parents = {parent: count for parent, _at, count in bursts}

    findings.rare_images = sorted(
        ((name, s.runs) for name, s in stats.items() if s.rare),
        key=lambda item: item[1],
    )[:25]
    findings.rare_pairs = sorted(
        ((p, c, n) for (p, c), n in pairs.items() if n <= 2), key=lambda item: item[2],
    )[:25]
    findings.bursts = bursts[:25]

    updates: list[tuple[int, str, list[str], str]] = []
    for row in rows:
        level, tags, reasons = score_row(row, stats, pairs, burst_parents)
        if not reasons or level == row.get("severity"):
            continue
        # Merge here, not in SQL. Both the path scorer's verdict and this one are
        # true, and an analyst reading the row wants both — the first attempt merged
        # with json_patch, which replaces arrays and quietly dropped the path tags.
        existing_tags = row.get("tags") or []
        if isinstance(existing_tags, str):
            try:
                existing_tags = json.loads(existing_tags)
            except (ValueError, TypeError):
                existing_tags = []
        merged_tags = list(existing_tags) + [t for t in tags if t not in existing_tags]

        data = row.get("data")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except (ValueError, TypeError):
                data = {}
        prior_why = str((data or {}).get("why") or "")
        merged_why = "; ".join(p for p in (prior_why, "; ".join(reasons)) if p)

        updates.append((int(row["id"]), level, merged_tags, merged_why))

    if updates:
        store.apply_rarity(updates)
        findings.promoted = len(updates)
    return findings


def describe(findings: Findings) -> list[str]:
    """Lines for the run summary, so the baseline is visible rather than implied."""
    if not findings.scanned:
        return []
    out = [
        f"baseline from {findings.scanned:,} process events; "
        f"promoted {findings.promoted:,}"
    ]
    for parent, child, n in findings.rare_pairs[:3]:
        out.append(f"first-time parent/child: {parent} -> {child} ({n}x)")
    for parent, _at, count in findings.bursts[:3]:
        out.append(f"spawn burst: {parent} started {count} children in "
                   f"{BURST_WINDOW_SECONDS}s")
    return out


