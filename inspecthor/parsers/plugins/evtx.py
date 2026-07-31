"""Windows Event Logs (.evtx).

The highest-value artifact in practice: most Sherlocks and most real intrusions
are reconstructed primarily from Security, System, PowerShell and Sysmon channels.

Two design notes worth knowing:

* Mapping is keyed on ``(channel_family, EventID)``, not the ID alone. Sysmon
  event 1 and Security event 4688 both mean "process created", and several IDs
  collide across providers — keying on the ID alone silently mislabels events.
* Records stream. A single Security.evtx of a few hundred MB holds well over a
  million records, so this is a generator all the way down and never builds a list.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from ... import details as details_mod
from ... import score
from ...capabilities import hint as cap_hint
from ...models import LEVEL_RANK, Event, ParseContext
from ..base import Parser, register
from ._evtx_ids import EVENT_TEMPLATES

# ---- provider -> channel family ----


# Providers that legitimately emit the System-channel event IDs mapped below.
#
# This list exists because the family must NOT be a catch-all. Event IDs are only
# meaningful within a provider: 104 means "log cleared" from the Eventlog service,
# but Microsoft-Windows-StateRepository, SentinelOne and a dozen storage drivers
# also emit 104 for entirely unrelated things. A real KAPE collection had 215
# distinct providers reaching this point, and treating them all as System turned
# 9,726 routine events into high-severity "audit log cleared" findings — the kind
# of false positive that makes an analyst stop believing the tool.
_SYSTEM_PROVIDERS = frozenset({
    "service control manager",
    "eventlog",
    "microsoft-windows-eventlog",
    "user32",
    "microsoft-windows-winlogon",
    "microsoft-windows-kernel-general",
    "microsoft-windows-kernel-power",
})


def _family(provider: str, channel: str = "") -> str:
    """Collapse a provider/channel into the family the ID map is keyed on.

    Returns ``"other"`` for anything unrecognized, so an unmapped provider cannot
    inherit another channel's meaning for the same numeric ID.
    """
    text = f"{provider} {channel}".lower()
    if "sysmon" in text:
        return "sysmon"
    if "powershell" in text:
        return "powershell"
    if "taskscheduler" in text or "task scheduler" in text:
        return "task"
    if "terminalservices" in text or "remoteconnectionmanager" in text:
        return "rdp"
    if "defender" in text:
        return "defender"
    # Security IDs (4624, 4688, …) come from the audit provider or the Security
    # channel — not from every provider with 'security' somewhere in its name.
    if "security-auditing" in text or channel.strip().lower() == "security":
        return "security"
    if provider.strip().lower() in _SYSTEM_PROVIDERS or channel.strip().lower() == "system":
        return "system"
    return "other"


# (family, EventID) -> (event_type, [attck], severity)
EVTX_MAP: dict[tuple[str, str], tuple[str, list[str], str]] = {
    ("security", "4624"): ("logon_success", ["T1078"], "info"),
    ("security", "4625"): ("logon_failed", ["T1110"], "info"),
    ("security", "4634"): ("logoff", [], "info"),
    ("security", "4647"): ("logoff", [], "info"),
    ("security", "4648"): ("explicit_cred_logon", ["T1078", "T1550.002"], "med"),
    ("security", "4672"): ("special_privileges", ["T1078.002"], "info"),
    ("security", "4688"): ("process_created", ["T1059"], "info"),
    ("security", "4697"): ("service_installed", ["T1543.003"], "high"),
    ("security", "4698"): ("scheduled_task_created", ["T1053.005"], "high"),
    ("security", "4699"): ("scheduled_task_deleted", ["T1053.005"], "med"),
    ("security", "4702"): ("scheduled_task_updated", ["T1053.005"], "med"),
    ("security", "4720"): ("account_created", ["T1136.001"], "high"),
    ("security", "4722"): ("account_enabled", ["T1098"], "med"),
    ("security", "4724"): ("password_reset", ["T1098"], "med"),
    ("security", "4726"): ("account_deleted", ["T1531"], "med"),
    ("security", "4728"): ("added_to_global_group", ["T1098"], "med"),
    ("security", "4732"): ("added_to_local_group", ["T1098"], "high"),
    ("security", "4735"): ("local_group_changed", ["T1098"], "med"),
    ("security", "4738"): ("account_changed", ["T1098"], "info"),
    ("security", "4740"): ("account_lockout", ["T1110"], "med"),
    ("security", "4768"): ("kerberos_tgt_request", ["T1078"], "info"),
    ("security", "4769"): ("kerberos_tgs_request", ["T1558.003"], "info"),
    ("security", "4771"): ("kerberos_preauth_failed", ["T1110"], "info"),
    ("security", "4776"): ("ntlm_validation", ["T1110"], "info"),
    ("security", "5140"): ("share_accessed", ["T1021.002"], "med"),
    ("security", "5145"): ("share_object_checked", ["T1021.002"], "info"),
    ("security", "1102"): ("audit_log_cleared", ["T1070.001"], "high"),
    ("system", "7045"): ("service_installed", ["T1543.003"], "high"),
    ("system", "7040"): ("service_startmode_changed", ["T1543.003"], "med"),
    ("system", "7034"): ("service_crashed", [], "info"),
    ("system", "7036"): ("service_state_changed", [], "info"),
    ("system", "104"): ("audit_log_cleared", ["T1070.001"], "high"),
    ("system", "1074"): ("system_shutdown", [], "info"),
    ("system", "6005"): ("eventlog_started", [], "info"),
    ("powershell", "4103"): ("powershell_module_log", ["T1059.001"], "info"),
    ("powershell", "4104"): ("powershell_scriptblock", ["T1059.001"], "med"),
    ("powershell", "400"): ("powershell_engine_start", ["T1059.001"], "info"),
    ("powershell", "600"): ("powershell_provider_start", ["T1059.001"], "info"),
    ("sysmon", "1"): ("process_created", ["T1059"], "info"),
    ("sysmon", "2"): ("file_time_changed", ["T1070.006"], "med"),
    ("sysmon", "3"): ("network_connection", ["T1071"], "info"),
    ("sysmon", "7"): ("image_loaded", ["T1574.002"], "info"),
    ("sysmon", "8"): ("remote_thread_created", ["T1055"], "high"),
    ("sysmon", "10"): ("process_access", ["T1003.001"], "med"),
    ("sysmon", "11"): ("file_created", [], "info"),
    ("sysmon", "12"): ("registry_key_event", ["T1112"], "info"),
    ("sysmon", "13"): ("registry_value_set", ["T1112"], "info"),
    ("sysmon", "15"): ("file_stream_created", ["T1564.004"], "med"),
    ("sysmon", "22"): ("dns_query", ["T1071.004"], "info"),
    ("sysmon", "23"): ("file_deleted", ["T1070.004"], "med"),
    ("task", "106"): ("scheduled_task_registered", ["T1053.005"], "med"),
    ("task", "129"): ("scheduled_task_process", ["T1053.005"], "info"),
    ("task", "200"): ("scheduled_task_executed", ["T1053.005"], "info"),
    ("task", "201"): ("scheduled_task_completed", ["T1053.005"], "info"),
    ("rdp", "1149"): ("rdp_connection", ["T1021.001"], "med"),
    ("rdp", "21"): ("rdp_logon", ["T1021.001"], "med"),
    ("rdp", "24"): ("rdp_disconnect", ["T1021.001"], "info"),
    ("defender", "1116"): ("malware_detected", [], "high"),
    ("defender", "1117"): ("malware_action_taken", [], "med"),
    ("defender", "5001"): ("defender_disabled", ["T1562.001"], "high"),
}

# Command-line shapes worth escalating on. A match upgrades severity and adds the
# specific sub-technique, which is the difference between "a process ran" and
# "an encoded PowerShell downloader ran".
_LOLBIN: tuple[tuple[re.Pattern, str, str], ...] = (
    (re.compile(r"-e(?:nc|ncoded|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}", re.I), "T1059.001", "high"),
    (re.compile(r"\b(?:iex|invoke-expression)\b", re.I), "T1059.001", "high"),
    (re.compile(r"\bdownloadstring\b|\bdownloadfile\b|\bnet\.webclient\b", re.I), "T1105", "high"),
    (re.compile(r"\binvoke-webrequest\b|\bcurl\b|\bwget\b|\bbitsadmin\b", re.I), "T1105", "med"),
    (re.compile(r"\bcertutil\b.*(?:-urlcache|-decode|-encode)", re.I), "T1140", "high"),
    (re.compile(r"\bmshta\b|\brundll32\b.*javascript", re.I), "T1218.005", "high"),
    (re.compile(r"\bregsvr32\b.*(?:scrobj|/i:http)", re.I), "T1218.010", "high"),
    (re.compile(r"\bschtasks\b\s*/create", re.I), "T1053.005", "high"),
    (re.compile(r"\bsc\b\s+(?:create|config)|\bnew-service\b", re.I), "T1543.003", "high"),
    (re.compile(r"\bnet\d?\b\s+user\b.*\/add", re.I), "T1136.001", "high"),
    (re.compile(r"\bnet\d?\b\s+localgroup\b.*\/add", re.I), "T1098", "high"),
    (re.compile(r"\bvssadmin\b.*delete|\bwbadmin\b.*delete", re.I), "T1490", "high"),
    (re.compile(r"\bwevtutil\b\s+cl|\bclear-eventlog\b", re.I), "T1070.001", "high"),
    (re.compile(r"\bwhoami\b|\bnltest\b|\bnet\s+group\b.*domain", re.I), "T1087", "info"),
    (re.compile(r"\bpsexec\b|\bwmic\b.*\/node:", re.I), "T1021", "high"),
    (re.compile(r"\bmimikatz\b|sekurlsa|lsadump", re.I), "T1003.001", "high"),
    (re.compile(r"\breg\b\s+save.*(?:sam|system|security)", re.I), "T1003.002", "high"),
    (re.compile(r"\bntdsutil\b|\bdiskshadow\b", re.I), "T1003.003", "high"),
    (re.compile(r"-nop|-noprofile|-w\s+hidden|-windowstyle\s+hidden", re.I), "T1564.003", "med"),
)

# Candidate keys for the same logical field, since exact spelling varies by
# provider and by dissect version.
_K_EVENTID = ("EventID", "EventID_", "EventId")
_K_TIME = ("TimeCreated_SystemTime", "TimeCreated", "SystemTime")
_K_PROVIDER = ("Provider_Name", "Provider", "ProviderName", "Provider_Guid")
_K_CHANNEL = ("Channel",)
_K_COMPUTER = ("Computer", "Computer_", "ComputerName")
_K_RECORDID = ("EventRecordID", "RecordId", "RecordNumber")
_K_USER = (
    "TargetUserName", "SubjectUserName", "User", "AccountName", "TargetAccount",
)
_K_IP = ("IpAddress", "SourceIp", "SourceAddress", "ClientAddress", "Address")
_K_PROC = ("NewProcessName", "Image", "ProcessName", "ImagePath")
_K_CMD = ("CommandLine", "ProcessCommandLine", "NewProcessCommandLine")
_K_PARENT = ("ParentProcessName", "ParentImage", "ParentProcessId")

_SCRIPT_CAP = 4096

# Field-capture budget. The allow-list this replaces discarded everything it did
# not name, but removing it without a budget turns an 800k-event case into a
# multi-gigabyte database. Every limit is deliberate; every truncation is marked.
_MAX_DATA_KEYS = 40
_MAX_VALUE_CHARS = 512
_MAX_DATA_CHARS = 3000

# Container fields already promoted to their own Event columns — keeping them in
# data as well would only duplicate.
_SYSTEM_KEYS = frozenset({
    "eventid", "eventid_", "eventid_qualifiers", "eventidqualifiers",
    "timecreated", "timecreated_systemtime", "systemtime", "provider",
    "provider_name", "providername", "provider_guid", "channel", "computer",
    "computer_", "computername", "eventrecordid", "recordid", "recordnumber",
    "level", "task", "opcode", "keywords", "version", "correlation",
    "correlation_activityid", "execution", "execution_processid",
    "execution_threadid", "security", "security_userid", "eventsourcename",
})

# A researched template level never exceeds 'med'. EVTX_MAP is the only source of
# 'high' and 'crit' because it has been checked against real event volumes —
# applying a table of 74 high/critical templates blind is exactly how a tool
# manufactures nine thousand confident falsehoods.
_RESEARCH_TO_LEVEL = {
    "critical": "med", "high": "med", "medium": "med",
    "low": "low", "informational": "info",
}


def _unwrap(value: Any) -> Any:
    """dissect wraps some substituted values; unwrap to the plain Python value."""
    getter = getattr(value, "get", None)
    if callable(getter) and not isinstance(value, dict):
        try:
            return getter()
        except Exception:
            return value
    return value


def _first(record: dict, keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in record:
            value = _unwrap(record[key])
            if value not in (None, ""):
                return value
    return None


def _as_text(value: Any) -> str:
    value = _unwrap(value)
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _as_time(value: Any) -> datetime | None:
    value = _unwrap(value)
    if isinstance(value, datetime):
        return value
    text = _as_text(value)
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def _escalate(cmdline: str, attck: list[str], severity: str) -> tuple[list[str], str]:
    """Upgrade technique list and severity when a command line looks offensive."""
    if not cmdline:
        return attck, severity
    out = list(attck)
    worst = severity
    for pattern, technique, sev in _LOLBIN:
        if pattern.search(cmdline):
            if technique not in out:
                out.append(technique)
            if LEVEL_RANK.get(sev, 0) > LEVEL_RANK.get(worst, 0):
                worst = sev
    return out, worst


def _iter_records(path: Path, ctx: ParseContext) -> Iterator[dict]:
    """Yield raw event records, preferring dissect and falling back to python-evtx.

    Both are optional; if neither is present the parser records a hint and yields
    nothing rather than raising.
    """
    try:
        from dissect.eventlog.evtx import Evtx
    except ImportError:
        Evtx = None

    if Evtx is not None:
        try:
            with path.open("rb") as handle:
                for record in Evtx(handle):
                    if isinstance(record, dict):
                        yield record
            return
        except Exception as exc:
            ctx.hint(f"{path.name}: dissect could not read this log ({exc})")
            return

    try:
        import Evtx.Evtx as pyevtx        # python-evtx, pure-python fallback
    except ImportError:
        ctx.hint(cap_hint("evtx"))
        return

    # python-evtx exposes XML per record; regex is enough for the fields we map and
    # avoids a namespace-aware parse of every record.
    re_pair = re.compile(r'<Data[^>]*\bName="([^"]+)"[^>]*>(.*?)</Data>', re.S)
    re_eid = re.compile(r"<EventID[^>]*>(\d+)</EventID>")
    re_time = re.compile(r'<TimeCreated[^>]*\bSystemTime="([^"]+)"')
    re_prov = re.compile(r'<Provider[^>]*\bName="([^"]+)"')
    re_chan = re.compile(r"<Channel>([^<]+)</Channel>")
    re_comp = re.compile(r"<Computer>([^<]+)</Computer>")
    from html import unescape

    try:
        with pyevtx.Evtx(str(path)) as log:
            for entry in log.records():
                try:
                    xml = entry.xml()
                except Exception:
                    continue
                eid = re_eid.search(xml)
                if not eid:
                    continue
                record: dict[str, Any] = {"EventID": eid.group(1)}
                for pattern, key in (
                    (re_time, "TimeCreated_SystemTime"), (re_prov, "Provider_Name"),
                    (re_chan, "Channel"), (re_comp, "Computer"),
                ):
                    match = pattern.search(xml)
                    if match:
                        record[key] = unescape(match.group(1))
                for name, value in re_pair.findall(xml):
                    record[name] = unescape(value).strip()
                yield record
    except Exception as exc:
        ctx.hint(f"{path.name}: python-evtx could not read this log ({exc})")


@register
class EvtxParser(Parser):
    """Windows Event Log parser."""

    name = "evtx"
    display = "Windows Event Log"
    category = "windows"
    magic = (b"ElfFile\x00",)
    path_globs = ("*.evtx",)
    kinds = ("evtx",)
    requires = "dissect.eventlog"
    install_hint = cap_hint("evtx")

    def dependency_ok(self) -> tuple[bool, str]:
        """Either backend will do, so check both before reporting unavailable."""
        import importlib.util
        for module in ("dissect.eventlog", "Evtx"):
            try:
                if importlib.util.find_spec(module) is not None:
                    return True, ""
            except (ImportError, ValueError):
                continue
        return False, self.install_hint

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        channel_label = path.stem or "evtx"
        emitted = 0

        for record in _iter_records(path, ctx):
            if emitted >= ctx.max_records:
                ctx.hint(f"{path.name}: stopped at the {ctx.max_records} record cap")
                return
            try:
                event = self._event_for(record, path, channel_label, ctx)
            except Exception:
                # One unparseable record must not end the log.
                continue
            if event is not None:
                emitted += 1
                yield event

    def _event_for(
        self, record: dict, path: Path, channel_label: str, ctx: ParseContext
    ) -> Event | None:
        timestamp = _as_time(_first(record, _K_TIME))
        if timestamp is None:
            return None

        eid = _as_text(_first(record, _K_EVENTID)).strip()
        provider = _as_text(_first(record, _K_PROVIDER))
        channel = _as_text(_first(record, _K_CHANNEL)) or channel_label
        record_id = _as_text(_first(record, _K_RECORDID)).strip()
        family = _family(provider, channel)

        # Keep EVERY EventData field, bounded. The allow-list this replaces read
        # each record's fields and then discarded all but 25 names, which is why
        # 418,514 events in one real collection had nothing to show but the words
        # "windows event".
        data = self._capture(record)
        data["event_id"] = eid
        data["channel"] = channel
        if provider:
            data["provider"] = provider

        user = _as_text(_first(record, _K_USER))
        host = _as_text(_first(record, _K_COMPUTER))

        # The curated map decides taxonomy and severity: event_type is what the
        # rest of the tool filters and answers questions on, and it is the only
        # source of 'high' and 'crit'.
        curated = EVTX_MAP.get((family, eid))
        template = EVENT_TEMPLATES.get((provider.strip().lower(), eid))

        if curated:
            event_type, attck, severity = curated
            attck = list(attck)
        else:
            event_type = "windows_event" if family == "other" else f"{family}_event"
            attck = list(template[3]) if template else []
            severity = _RESEARCH_TO_LEVEL.get(template[1], "info") if template else "info"

        # Title and Details are the display layer, kept separate from taxonomy. An
        # id with no template says so in plain words rather than being dressed up
        # as something the tool understood.
        if template:
            title, fields = template[0], template[2]
        else:
            fields = ()
            title = (
                f"EventID {eid} — {provider or channel or 'unknown provider'} (no template)"
            )

        detail_text, extra_text = details_mod.build_details(
            record, fields, provider=provider, channel=channel, event_id=eid,
        )

        # Sysmon packs hashes as "SHA256=...,MD5=..." — split so a hash search hits.
        if data.get("hashes"):
            for chunk in str(data["hashes"]).split(","):
                if "=" in chunk:
                    algo, _, digest = chunk.partition("=")
                    algo = algo.strip().lower()
                    if algo in ("md5", "sha1", "sha256", "imphash"):
                        data[algo] = digest.strip().lower()

        script = _as_text(record.get("ScriptBlockText", ""))
        if script:
            data["script"] = script[:_SCRIPT_CAP]

        cmdline = str(data.get("command_line") or data.get("process_command_line") or "")
        haystack = " ".join(filter(None, [
            cmdline, script,
            str(data.get("image_path") or ""), str(data.get("service_file_name") or ""),
            str(data.get("new_process_name") or ""), str(data.get("image") or ""),
        ]))
        attck, severity = _escalate(haystack, attck, severity)
        if severity == "high" and cmdline:
            data["suspicious_cmdline"] = True

        tags: list[str] = []

        # Where code lives and what it does, not what it is called. _escalate above
        # is a LOLBin blocklist; it matched nothing in a confirmed intrusion whose
        # implant shipped its own node.exe. score.py asks the questions that did
        # separate that chain from the noise, and can also LOWER the OS's own churn
        # out of a 'high' tier that was otherwise 100% false positives.
        severity, tags, attck, reasons = self._score(
            event_type, data, cmdline, severity, tags, attck,
        )
        if reasons:
            data["why"] = score.summarize(reasons)

        if data.get("logon_type") == "10":
            tags.append("rdp")
        if event_type == "process_created" and LEVEL_RANK.get(severity, 0) >= LEVEL_RANK["high"]:
            tags.append("suspicious")
        if not template:
            # The machine-readable counterpart to "(no template)" in the title, so
            # the coverage summary is a query rather than a string match.
            tags.append("auto_fields")

        return ctx.event(
            timestamp=timestamp,
            timestamp_desc="Event Logged",
            event_type=event_type,
            message="",                 # derived from title + details
            title=title,
            details=detail_text,
            extra_fields=extra_text,
            channel=channel,
            record_id=record_id or None,
            data=data,
            user=user,
            host=host,
            attck=attck,
            tags=tags,
            severity=severity,
            event_id=eid or None,
            source_artifact=f"{self.name}/{channel_label}",
            artifact_path=str(path),
            parser=self.name,
        )

    @staticmethod
    def _score(event_type: str, data: dict, cmdline: str, severity: str,
               tags: list[str], attck: list[str]) -> tuple[str, list[str], list[str], list[str]]:
        """Apply path/behaviour scoring for the event types where it changes the answer.

        Split out so the scoring rules are testable against a plain dict and the
        3-line dispatch here cannot drift from them.
        """
        reasons: list[str] = []

        if event_type == "process_created":
            image = str(data.get("new_process_name") or data.get("image") or "")
            parent = str(data.get("parent_process_name") or data.get("parent_image")
                         or data.get("creator_process_name") or "")
            severity, new_tags, new_attck, reasons = score.score_process(
                image, cmdline, parent, base=severity,
            )
            tags = tags + [t for t in new_tags if t not in tags]
            attck = attck + [a for a in new_attck if a not in attck]

        elif event_type == "service_installed":
            name = str(data.get("service_name") or data.get("name") or "")
            image = str(data.get("service_file_name") or data.get("image_path") or "")
            severity, new_tags, reasons = score.score_service(name, image, base=severity)
            tags = tags + [t for t in new_tags if t not in tags]

        elif event_type == "scheduled_task_created":
            name = str(data.get("task_name") or data.get("name") or "")
            xml = str(data.get("task_content") or data.get("xml") or "")
            severity, new_tags, reasons = score.score_task(name, xml, base=severity)
            tags = tags + [t for t in new_tags if t not in tags]

        return severity, tags, attck, reasons

    @staticmethod
    def _capture(record: dict) -> dict[str, Any]:
        """Every EventData field, snake_cased and bounded.

        Bounded rather than unlimited: 800k events times unbounded fields is a
        multi-gigabyte database. Anything dropped is counted in ``_truncated`` so
        the loss is visible rather than silent.
        """
        data: dict[str, Any] = {}
        budget = _MAX_DATA_CHARS
        dropped = 0

        for key, raw in record.items():
            name = str(key)
            if name.lower() in _SYSTEM_KEYS:
                continue
            value = _as_text(raw)
            if not value:
                continue
            if len(data) >= _MAX_DATA_KEYS or budget <= 0:
                dropped += 1
                continue
            value = value[:_MAX_VALUE_CHARS]
            lowered = name.lower()
            if "ipaddress" in lowered or lowered.endswith("address"):
                value = details_mod.normalize_ip(value)
                if not value:
                    continue
            data[_snake(name)] = value
            budget -= len(value)

        if dropped:
            data["_truncated"] = dropped
        return data

    # There is deliberately no _message() here any more. It built the summary from
    # a second hardcoded list of ten keys, so any event outside that list rendered
    # as the bare string "windows event" — 418,514 rows of it in one collection.
    # title + details replace it, and details.build_details() cannot return empty.


def _snake(name: str) -> str:
    """'TargetUserName' -> 'target_user_name' so data keys are consistent."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
