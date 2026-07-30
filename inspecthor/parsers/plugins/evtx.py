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

from ...capabilities import hint as cap_hint
from ...models import Event, ParseContext
from ..base import Parser, register

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

_SEV_ORDER = {"info": 0, "med": 1, "high": 2}

# Candidate keys for the same logical field, since exact spelling varies by
# provider and by dissect version.
_K_EVENTID = ("EventID", "EventID_", "EventId")
_K_TIME = ("TimeCreated_SystemTime", "TimeCreated", "SystemTime")
_K_PROVIDER = ("Provider_Name", "Provider", "ProviderName", "Provider_Guid")
_K_CHANNEL = ("Channel",)
_K_COMPUTER = ("Computer", "Computer_", "ComputerName")
_K_USER = (
    "TargetUserName", "SubjectUserName", "User", "AccountName", "TargetAccount",
)
_K_IP = ("IpAddress", "SourceIp", "SourceAddress", "ClientAddress", "Address")
_K_PROC = ("NewProcessName", "Image", "ProcessName", "ImagePath")
_K_CMD = ("CommandLine", "ProcessCommandLine", "NewProcessCommandLine")
_K_PARENT = ("ParentProcessName", "ParentImage", "ParentProcessId")

_SCRIPT_CAP = 4096
_MSG_CAP = 400


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
            if _SEV_ORDER.get(sev, 0) > _SEV_ORDER.get(worst, 0):
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
        family = _family(provider, channel)

        # An unmapped (family, id) pair keeps a neutral label. 'other' becomes
        # 'windows_event' rather than 'other_event' because the channel is the
        # useful discriminator and it is already carried in data.
        fallback = "windows_event" if family == "other" else f"{family}_event"
        event_type, attck, severity = EVTX_MAP.get(
            (family, eid), (fallback, [], "info")
        )
        attck = list(attck)

        data: dict[str, Any] = {"event_id": eid, "channel": channel}
        if provider:
            data["provider"] = provider

        user = _as_text(_first(record, _K_USER))
        host = _as_text(_first(record, _K_COMPUTER))

        for key, candidates in (
            ("source_ip", _K_IP), ("process", _K_PROC),
            ("cmdline", _K_CMD), ("parent", _K_PARENT),
        ):
            value = _as_text(_first(record, candidates))
            if value:
                data[key] = value

        # Family-specific fields that answer the questions people actually ask.
        for key in (
            "LogonType", "WorkstationName", "AuthenticationPackageName",
            "LogonProcessName", "TargetDomainName", "SubjectUserName", "Status",
            "ServiceName", "ImagePath", "ServiceType", "StartType",
            "DestinationIp", "DestinationPort", "DestinationHostname", "SourcePort",
            "QueryName", "QueryResults", "TargetFilename", "Hashes", "TargetObject",
            "Details", "TaskName", "ProcessId", "ParentCommandLine", "Path",
        ):
            if key in record:
                value = _as_text(record[key])
                if value:
                    data[_snake(key)] = value[:1000]

        # Sysmon packs hashes as "SHA256=...,MD5=..." — split so a hash search hits.
        if data.get("hashes"):
            for chunk in str(data["hashes"]).split(","):
                if "=" in chunk:
                    algo, _, digest = chunk.partition("=")
                    algo = algo.strip().lower()
                    if algo in ("md5", "sha1", "sha256", "imphash"):
                        data[algo] = digest.strip().lower()

        # PowerShell script blocks are the payload; keep a bounded copy.
        script = _as_text(record.get("ScriptBlockText", ""))
        if script:
            data["script"] = script[:_SCRIPT_CAP]

        cmdline = str(data.get("cmdline") or "")
        haystack = " ".join(filter(None, [cmdline, script, str(data.get("image_path") or "")]))
        attck, severity = _escalate(haystack, attck, severity)
        if severity == "high" and cmdline:
            data["suspicious_cmdline"] = True

        # A failed logon from an external address matters more than an internal one,
        # but that judgement needs the whole case — leave severity, add a tag.
        tags: list[str] = []
        if event_type in ("logon_failed", "logon_success") and data.get("logon_type") == "10":
            tags.append("rdp")
        if event_type in ("process_created",) and severity == "high":
            tags.append("suspicious")

        return ctx.event(
            timestamp=timestamp,
            timestamp_desc="Event Logged",
            event_type=event_type,
            message=self._message(event_type, eid, data, user),
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
    def _message(event_type: str, eid: str, data: dict, user: str) -> str:
        """A one-line summary that reads like a sentence, not a field dump."""
        parts: list[str] = [f"[{eid}] {event_type.replace('_', ' ')}"]
        if user:
            parts.append(f"user={user}")
        for key in ("source_ip", "logon_type", "service_name", "image_path",
                    "process", "destination_ip", "destination_port", "query_name",
                    "target_filename", "task_name"):
            if data.get(key):
                parts.append(f"{key}={data[key]}")
        cmdline = data.get("cmdline") or data.get("script")
        if cmdline:
            parts.append(f"cmd={str(cmdline)[:180]}")
        return " ".join(parts)[:_MSG_CAP]


def _snake(name: str) -> str:
    """'TargetUserName' -> 'target_user_name' so data keys are consistent."""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
