"""Sherlock answer-hint mode.

Given a question in the words HTB asked it, work out which artifact and field
probably holds the answer, then pull the candidates and format them the way the
platform expects.

CONSTRAINT: this never submits and never claims certainty. It returns ranked
Candidates with their provenance, and the console labels them as candidates to
verify. A confidently wrong answer costs an attempt and sends the analyst down
the wrong path, which is worse than no suggestion at all.

CONSTRAINT: formatting matters as much as the value. HTB rejects a correct
timestamp in the wrong format, so the formatters here are part of the answer, not
cosmetic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from .models import Candidate, EventFilter

# ---- HTB answer formatters ----


def fmt_utc(value: Any) -> str:
    """'2024-03-01 09:15:14' — the format HTB asks for most often."""
    text = str(value).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(text[:19], fmt).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return text


def fmt_hash(value: Any) -> str:
    """Hashes uppercase — HTB's convention for hash answers."""
    return str(value).strip().upper()


def fmt_int(value: Any) -> str:
    """Bare integer, no separators (byte counts, run counts)."""
    try:
        return str(int(float(str(value).replace(",", "").strip())))
    except (TypeError, ValueError):
        return str(value).strip()


def fmt_plain(value: Any) -> str:
    return str(value).strip()


def fmt_path(value: Any) -> str:
    """Exact path, backslashes preserved."""
    return str(value).strip().strip('"')


# ---- rules ----


@dataclass
class AnswerRule:
    """Maps a question shape to where the answer lives."""

    label: str
    patterns: tuple[re.Pattern, ...]
    # One or more data keys, tried in order, plus the pseudo-keys '@ts', '@user',
    # '@host' and '@message'. Several keys because the same fact lands under
    # different names depending on which parser produced it — a command line is
    # 'cmdline' from EVTX but 'cmd' from sudo, and a rule that knows only one of
    # them silently answers nothing.
    field: str | tuple[str, ...]
    formatter: Callable[[Any], str] = fmt_plain
    sources: tuple[str, ...] = ()               # source_artifact prefixes to search
    event_types: tuple[str, ...] = ()           # event_type values to search
    severity: str | None = None
    confidence: float = 0.6
    prefer: str = "first"                       # 'first'|'last'|'most_common'|'given'
    require_keywords: tuple[str, ...] = ()      # extra words that must appear

    # Registry value names allowed to answer, best first. A registry key holds
    # several values and only some of them are the answer: TimeZoneInformation
    # also carries StandardName and DaylightName, which on a real host are
    # unresolved MUI references ('@tzres.dll,-162'). Without this the tool offered
    # one of those as the timezone and pushed the real answer, 'Central Standard
    # Time', off the end of the list. Use with prefer='given'.
    value_names: tuple[str, ...] = ()

    # Formatted values that are never the answer, however often they appear.
    exclude: frozenset[str] = frozenset()


def _c(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.I)


# Loopback and the unspecified address are where a *local* logon comes from. A real
# collection had 61 successful logons from '::1', which normalize_ip renders as
# 127.0.0.1, and the tool offered it as the attacker's source IP at 0.70 — a
# confident false lead pointing at the victim's own machine.
_NOT_A_REMOTE_IP = frozenset({"127.0.0.1", "::1", "0.0.0.0", "::", "-", "localhost"})


ANSWER_RULES: tuple[AnswerRule, ...] = (
    AnswerRule(
        label="Attacker source IP",
        patterns=(_c(r"attacker'?s? ip"), _c(r"source ip"), _c(r"ip address of the attack"),
                  _c(r"which ip"), _c(r"what ip"), _c(r"originat\w+ ip"), _c(r"remote ip")),
        field=("source_ip", "ip_address"), formatter=fmt_plain,
        event_types=("logon_failed", "ssh_failed_login", "ssh_invalid_user",
                     "ssh_login_success", "logon_success", "rdp_connection"),
        confidence=0.8, prefer="most_common", exclude=_NOT_A_REMOTE_IP,
    ),
    AnswerRule(
        label="Compromised account",
        patterns=(_c(r"which account"), _c(r"what account"), _c(r"compromised (?:user|account)"),
                  _c(r"account was (?:compromised|breached)"), _c(r"successful\w* (?:logon|login) .*user")),
        field="@user", formatter=fmt_plain,
        event_types=("ssh_login_success", "logon_success"),
        confidence=0.7, prefer="most_common",
    ),
    AnswerRule(
        label="Account created by attacker",
        # 'create' shows up on either side of 'account' depending on phrasing
        # ("what account was created" / "what account did they create"), and both
        # must beat the compromised-account rule, which also matches "what account".
        patterns=(_c(r"account\b.{0,30}\bcreat"), _c(r"creat\w*\b.{0,30}\baccount"),
                  _c(r"new (?:user|account)"), _c(r"account (?:was )?(?:added|made)"),
                  _c(r"backdoor account"), _c(r"persistence account")),
        field="@user", formatter=fmt_plain,
        event_types=("account_created",),
        confidence=0.85, prefer="first",
    ),
    AnswerRule(
        label="First successful logon time",
        patterns=(_c(r"when did .*(?:log|sign) ?(?:on|in)"), _c(r"time of .*(?:logon|login)"),
                  _c(r"first (?:successful )?(?:logon|login)"), _c(r"initial access")),
        field="@ts", formatter=fmt_utc,
        event_types=("ssh_login_success", "logon_success"),
        confidence=0.75, prefer="first",
    ),
    AnswerRule(
        label="Brute-force success time",
        patterns=(_c(r"brute ?forc"), _c(r"password spray"), _c(r"guessed the password")),
        field="@ts", formatter=fmt_utc,
        event_types=("ssh_login_success",), severity="high",
        confidence=0.8, prefer="first",
    ),
    AnswerRule(
        label="Executed process / command line",
        patterns=(_c(r"what command"), _c(r"command line"), _c(r"which (?:process|binary|executable)"),
                  _c(r"what (?:process|binary|executable)"), _c(r"was executed"), _c(r"did .* run")),
        field=("cmdline", "cmd", "script", "process", "image_path"),
        formatter=fmt_plain,
        event_types=("process_created", "sudo_command", "powershell_scriptblock"),
        confidence=0.65, prefer="first",
    ),
    AnswerRule(
        label="First execution time",
        patterns=(_c(r"first (?:run|execut)"), _c(r"when .*(?:executed|ran)"),
                  _c(r"execution time"), _c(r"time .* was run")),
        field="@ts", formatter=fmt_utc,
        event_types=("process_created", "amcache_exec", "userassist_exec",
                     "scheduled_task_executed"),
        confidence=0.7, prefer="first",
    ),
    AnswerRule(
        label="Persistence mechanism",
        patterns=(_c(r"persist"), _c(r"auto ?(?:start|run)"), _c(r"run key"),
                  _c(r"scheduled task"), _c(r"service (?:was )?(?:created|installed)"),
                  _c(r"maintain access")),
        field="@message", formatter=fmt_plain,
        event_types=("autostart_run_key", "service_installed", "scheduled_task_created",
                     "scheduled_task_registered", "ifeo_hijack", "winlogon_config"),
        confidence=0.7, prefer="first",
    ),
    AnswerRule(
        label="Service name",
        patterns=(_c(r"(?:name of the )?service"), _c(r"service name")),
        field="service_name", formatter=fmt_plain,
        event_types=("service_installed",),
        confidence=0.7, prefer="first",
    ),
    AnswerRule(
        label="Malicious file path",
        patterns=(_c(r"(?:file|malware|payload|binary) path"), _c(r"where was .* (?:dropped|written|saved)"),
                  _c(r"full path"), _c(r"dropped file")),
        field=("image_path", "target_filename", "program_path", "process", "value"),
        formatter=fmt_path,
        event_types=("service_installed", "file_created", "amcache_exec"),
        confidence=0.6, prefer="first",
    ),
    AnswerRule(
        label="File hash",
        patterns=(_c(r"\bsha ?256\b"), _c(r"\bsha ?1\b"), _c(r"\bmd5\b"), _c(r"\bhash\b")),
        field=("sha256", "sha1", "md5", "hashes"), formatter=fmt_hash,
        confidence=0.7, prefer="first",
    ),
    AnswerRule(
        label="C2 destination IP",
        patterns=(_c(r"c2|command and control"), _c(r"destination ip"), _c(r"beacon"),
                  _c(r"connect\w* (?:out|to)"), _c(r"exfiltrat\w+ to")),
        field=("destination_ip", "destination_hostname", "query_name"),
        formatter=fmt_plain,
        event_types=("network_connection", "dns_query"),
        confidence=0.75, prefer="most_common",
    ),
    AnswerRule(
        label="Domain queried",
        patterns=(_c(r"(?:what|which) domain"), _c(r"dns (?:query|request)"), _c(r"resolved")),
        field="query_name", formatter=fmt_plain,
        event_types=("dns_query",),
        confidence=0.75, prefer="most_common",
    ),
    AnswerRule(
        label="Bytes transferred",
        patterns=(_c(r"how (?:much|many) (?:data|bytes)"), _c(r"bytes (?:sent|transferred|out)"),
                  _c(r"data (?:exfiltrated|transferred)")),
        field=("bytes_sent", "bytes", "size"), formatter=fmt_int,
        confidence=0.6, prefer="first",
    ),
    AnswerRule(
        label="System hostname",
        patterns=(_c(r"host ?name"), _c(r"name of the (?:host|machine|computer|system)"),
                  _c(r"computer name")),
        field="value", formatter=fmt_plain,
        event_types=("computer_name",),
        # The ComputerName key also has a (Default) value, which on a real host
        # held 'mnmsrvc'. Offered at the same confidence as the true hostname, it
        # is indistinguishable from it.
        value_names=("ComputerName",),
        confidence=0.85, prefer="given",
    ),
    AnswerRule(
        label="System timezone",
        patterns=(_c(r"time ?zone"), _c(r"utc offset")),
        # The zone name answers the question; the biases are the next best thing.
        # ActiveTimeBias before Bias because it accounts for DST — on a real host
        # they read UTC-05:00 and UTC-06:00 respectively, and only the first was
        # true on the day the evidence was collected.
        field=("utc_offset", "value"), formatter=fmt_plain,
        event_types=("system_timezone",),
        value_names=("TimeZoneKeyName", "ActiveTimeBias", "Bias"),
        confidence=0.85, prefer="given",
    ),
    AnswerRule(
        label="USB device",
        patterns=(_c(r"usb"), _c(r"removable (?:media|device)"), _c(r"external drive")),
        field=("device", "name", "value"), formatter=fmt_plain,
        event_types=("usb_device",),
        confidence=0.8, prefer="first",
    ),
    AnswerRule(
        label="Privilege escalation command",
        patterns=(_c(r"privile\w+ escalat"), _c(r"\bsudo\b"), _c(r"become root"),
                  _c(r"elevat\w+")),
        field=("cmd", "cmdline"), formatter=fmt_plain,
        event_types=("sudo_command",),
        confidence=0.7, prefer="first",
    ),
    AnswerRule(
        label="Anti-forensics / log clearing time",
        patterns=(_c(r"log\w* (?:were |was )?clear"), _c(r"anti.?forensic"),
                  _c(r"cover\w* (?:their|his|her) track")),
        field="@ts", formatter=fmt_utc,
        event_types=("audit_log_cleared",),
        confidence=0.85, prefer="first",
    ),
    AnswerRule(
        label="Detection rule triggered",
        patterns=(_c(r"which (?:rule|signature|detection)"), _c(r"yara"), _c(r"sigma")),
        field=("rule",), formatter=fmt_plain,
        event_types=("yara_match", "sigma_match"),
        confidence=0.7, prefer="most_common",
    ),
)


# ---- question extraction ----

_Q_NUMBERED = re.compile(r"^\s*(?:\d+|Q\d+|Task\s*\d+)[\).:\-]?\s*(.+\?)\s*$", re.I | re.M)
_Q_BARE = re.compile(r"^\s*(.{12,300}\?)\s*$", re.M)


def questions_from_text(text: str) -> list[str]:
    """Pull investigation questions out of a Sherlock readme or task file.

    Numbered lines first (how HTB writes them); if none are found, fall back to
    any line ending in a question mark.
    """
    found = [m.group(1).strip() for m in _Q_NUMBERED.finditer(text)]
    if not found:
        found = [m.group(1).strip() for m in _Q_BARE.finditer(text)]
    seen, out = set(), []
    for question in found:
        key = question.lower()
        if key not in seen:
            seen.add(key)
            out.append(question)
    return out


def questions_from_file(path: str | Path) -> list[str]:
    try:
        return questions_from_text(Path(path).read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return []


# ---- answering ----


def _matching_rules(question: str) -> list[AnswerRule]:
    """Rules whose patterns fire for this question, best-matching first."""
    scored: list[tuple[int, AnswerRule]] = []
    for rule in ANSWER_RULES:
        hits = sum(1 for pattern in rule.patterns if pattern.search(question))
        if hits:
            scored.append((hits, rule))
    scored.sort(key=lambda item: (-item[0], -item[1].confidence))
    return [rule for _hits, rule in scored]


def _value_for(row: dict, field: str | tuple[str, ...]) -> Any:
    """First non-empty value among the rule's candidate keys."""
    keys = (field,) if isinstance(field, str) else tuple(field)
    data = row.get("data") or {}
    for key in keys:
        if key == "@ts":
            value = row.get("ts")
        elif key == "@user":
            value = row.get("user")
        elif key == "@host":
            value = row.get("host")
        elif key == "@message":
            value = row.get("message")
        else:
            value = data.get(key) if isinstance(data, dict) else None
        if value not in (None, ""):
            return value
    return None


def _rows_for(store, rule: AnswerRule) -> list[dict]:
    """Candidate rows for a rule, unioned across its event types."""
    rows: list[dict] = []
    seen_ids: set[int] = set()
    filters: list[EventFilter] = []
    if rule.event_types:
        for event_type in rule.event_types:
            filters.append(EventFilter(event_type=event_type, severity=rule.severity))
    else:
        filters.append(EventFilter(severity=rule.severity))
    for filt in filters:
        for row in store.query_events(filt):
            row_id = int(row.get("id", 0))
            if row_id in seen_ids:
                continue
            seen_ids.add(row_id)
            rows.append(row)

    if rule.value_names:
        rank = {name.lower(): i for i, name in enumerate(rule.value_names)}

        def _name(row: dict) -> str:
            data = row.get("data") or {}
            return str(data.get("name") or "").lower() if isinstance(data, dict) else ""

        rows = [row for row in rows if _name(row) in rank]
        # Value-name priority outranks time: these keys hold one fact each, so the
        # question is which value holds it, not which was written first.
        rows.sort(key=lambda r: (rank[_name(r)], str(r.get("ts") or ""), int(r.get("id", 0))))
        return rows

    rows.sort(key=lambda r: (str(r.get("ts") or ""), int(r.get("id", 0))))
    return rows


def answer_question(store, question: str, limit: int = 5) -> list[Candidate]:
    """Ranked candidate answers for one question."""
    out: list[Candidate] = []
    for rule in _matching_rules(question):
        rows = _rows_for(store, rule)
        if not rows:
            continue

        # value -> (count, first_row)
        tally: dict[str, tuple[int, dict]] = {}
        for row in rows:
            raw = _value_for(row, rule.field)
            if raw in (None, ""):
                continue
            try:
                formatted = rule.formatter(raw)
            except Exception:
                continue
            if not formatted:
                continue
            if formatted.strip().lower() in rule.exclude:
                continue
            count, first = tally.get(formatted, (0, row))
            tally[formatted] = (count + 1, first)

        if not tally:
            continue

        if rule.prefer == "given":
            # _rows_for already ordered these; dicts keep insertion order.
            ordered = list(tally.items())
        elif rule.prefer == "most_common":
            ordered = sorted(tally.items(), key=lambda kv: (-kv[1][0], kv[0]))
        elif rule.prefer == "last":
            ordered = sorted(tally.items(), key=lambda kv: str(kv[1][1].get("ts")), reverse=True)
        else:
            ordered = sorted(tally.items(), key=lambda kv: (
                str(kv[1][1].get("ts") or ""), int(kv[1][1].get("id", 0))
            ))

        # A single distinct value is a much stronger signal than one of forty.
        distinct = len(ordered)
        for formatted, (count, row) in ordered[:limit]:
            spread_penalty = 1.0 if distinct == 1 else max(0.45, 1.0 - (distinct - 1) * 0.12)
            confidence = round(min(0.97, rule.confidence * spread_penalty), 2)
            out.append(Candidate(
                answer=formatted,
                label=rule.label,
                confidence=confidence,
                source=str(row.get("source_artifact") or ""),
                why=f"{row.get('event_type')} @ {row.get('ts')}"
                    + (f" ({count} occurrences)" if count > 1 else ""),
                event_id=int(row.get("id", 0)) or None,
            ))

    out.sort(key=lambda c: -c.confidence)
    # Same answer surfaced by two rules adds noise, not confidence.
    seen: set[tuple[str, str]] = set()
    deduped: list[Candidate] = []
    for cand in out:
        key = (cand.label, cand.answer)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cand)
    return deduped[: limit * 2]


def answer_questions(store, questions: Iterable[str], limit: int = 3) -> list[tuple[str, list[Candidate]]]:
    """Answer a batch, preserving order."""
    return [(question, answer_question(store, question, limit)) for question in questions]


def overview(store) -> list[Candidate]:
    """The facts worth knowing before reading any question.

    Runs the high-confidence context rules unprompted, because "what host, what
    timezone, who logged in, from where" is the opening move on every Sherlock.
    """
    seed_questions = (
        "what is the hostname",
        "what is the system timezone",
        "what is the attacker ip",
        "which account was compromised",
        "when was the first successful logon",
        "what account was created",
        "what persistence was installed",
        "when were the logs cleared",
    )
    out: list[Candidate] = []
    seen: set[tuple[str, str]] = set()
    for question in seed_questions:
        for cand in answer_question(store, question, limit=2):
            key = (cand.label, cand.answer)
            if key not in seen:
                seen.add(key)
                out.append(cand)
    out.sort(key=lambda c: -c.confidence)
    return out
