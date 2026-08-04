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
from typing import Any, Callable, Iterator

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
    # 'new_process_name' FIRST, and this one line decides whether SigmaHQ works at
    # all. Security 4688 stores the executable under NewProcessName; Sysmon 1 stores
    # it as Image. Nearly every SigmaHQ Windows rule is logsource
    # category: process_creation keyed on Image, so without the 4688 spelling the
    # entire process_creation corpus — the largest and most valuable part of it —
    # silently matches nothing on any collection without Sysmon. Silently: the rules
    # load, evaluate, and report zero hits, which reads as a clean host.
    "image": ("new_process_name", "image", "process"),
    "originalfilename": ("original_file_name",),
    "commandline": ("command_line", "process_command_line", "cmdline"),
    "parentimage": ("parent_process_name", "parent_image", "creator_process_name",
                    "parent"),
    "parentcommandline": ("parent_command_line",),
    "parentuser": ("parent_user",),
    "currentdirectory": ("current_directory",),
    "integritylevel": ("mandatory_label", "integrity_level"),
    "logonid": ("subject_logon_id", "logon_id", "target_logon_id"),
    "processid": ("new_process_id", "process_id"),
    "parentprocessid": ("process_id", "creator_process_id"),
    "company": ("company",),
    "description": ("description",),
    "product": ("product",),
    "signature": ("signature",),
    "signed": ("signed",),
    "sourceimage": ("source_image",),
    "targetimage": ("target_image",),
    "grantedaccess": ("granted_access",),
    "calltrace": ("call_trace",),
    "startmodule": ("start_module",),
    "startfunction": ("start_function",),
    "pipename": ("pipe_name",),
    "queryresults": ("query_results",),
    "querystatus": ("query_status",),
    "sourceport": ("source_port",),
    "initiated": ("initiated",),
    "protocol": ("protocol",),
    "hostapplication": ("host_application",),
    "contextinfo": ("context_info",),
    "payload": ("payload",),
    "eventtype": ("event_type_field", "event_type"),
    "servicefilename": ("service_file_name", "image_path"),
    "servicestarttype": ("service_start_type", "start_type"),
    "accountname": ("account_name",),
    "objectname": ("object_name",),
    "objecttype": ("object_type",),
    "sharename": ("share_name",),
    "relativetargetname": ("relative_target_name",),
    "workstationname": ("workstation_name",),
    "authenticationpackagename": ("authentication_package_name",),
    "logonprocessname": ("logon_process_name",),
    "status": ("status",),
    "substatus": ("sub_status",),
    "ticketoptions": ("ticket_options",),
    "ticketencryptiontype": ("ticket_encryption_type",),
    "preauthtype": ("pre_auth_type",),
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

# ---------------------------------------------------------------------------
# logsource: which events a rule is even about
# ---------------------------------------------------------------------------
#
# The evaluator read `logsource`, stored it on the hit event, and never consulted it.
# That is the same defect as an EventID with no provider qualifier, at corpus scale: a
# SigmaHQ checkout is ~3,000 rules across Linux, macOS, AWS, Azure, Okta, M365, Zeek
# and Windows, and every one of them was being tested against every Windows event.
# One unqualified 104/1102 rule in this repo produced 205 false positives on a single
# host; thousands of cross-product rules is the same mistake without a bottom.
#
# It is also what makes SigmaHQ *possible*. Testing 798,000 events against 3,000 rules
# is 2.4 billion selection evaluations. Keyed on logsource, each event is tested only
# against rules that could apply to it.

# Sigma category -> the event ids that carry it. Security first, Sysmon second:
# a KAPE collection from a fleet without Sysmon has 4688 and nothing else.
_CATEGORY_EVENT_IDS: dict[str, frozenset[str]] = {
    "process_creation": frozenset({"4688", "1"}),
    "process_termination": frozenset({"4689", "5"}),
    "network_connection": frozenset({"3", "5156", "5158"}),
    "image_load": frozenset({"7"}),
    "driver_load": frozenset({"6"}),
    "file_event": frozenset({"11"}),
    "file_delete": frozenset({"23", "26"}),
    "file_change": frozenset({"2"}),
    "file_rename": frozenset({"29"}),
    "file_block_executable": frozenset({"27"}),
    "create_stream_hash": frozenset({"15"}),
    "create_remote_thread": frozenset({"8"}),
    "process_access": frozenset({"10"}),
    "process_tampering": frozenset({"25"}),
    "raw_access_thread": frozenset({"9"}),
    "registry_add": frozenset({"12", "4657"}),
    "registry_delete": frozenset({"12", "4657"}),
    "registry_event": frozenset({"12", "13", "14", "4657"}),
    "registry_set": frozenset({"13", "4657"}),
    "registry_rename": frozenset({"14"}),
    "pipe_created": frozenset({"17", "18"}),
    "wmi_event": frozenset({"19", "20", "21"}),
    "dns_query": frozenset({"22"}),
    "sysmon_error": frozenset({"255"}),
    "sysmon_status": frozenset({"4", "16"}),
    "ps_script": frozenset({"4104"}),
    "ps_module": frozenset({"4103"}),
    "ps_classic_start": frozenset({"400"}),
    "ps_classic_provider_start": frozenset({"600"}),
    "ps_classic_script": frozenset({"800"}),
}

# Sigma service -> a token matched against the event's channel, case-insensitively.
# Substring rather than exact because channels arrive spelled several ways
# ('Microsoft-Windows-Sysmon/Operational', 'Sysmon', 'Microsoft-Windows-Sysmon%4Operational').
_SERVICE_CHANNEL_TOKENS: dict[str, tuple[str, ...]] = {
    "security": ("security",),
    "system": ("system",),
    "application": ("application",),
    "sysmon": ("sysmon",),
    "powershell": ("powershell",),
    "powershell-classic": ("windows powershell",),
    "taskscheduler": ("taskscheduler",),
    "windefend": ("windows defender",),
    "applocker": ("applocker",),
    "wmi": ("wmi-activity",),
    "smbclient-security": ("smbclient",),
    "smbclient-connectivity": ("smbclient",),
    "smbserver-security": ("smbserver",),
    "terminalservices-localsessionmanager": ("terminalservices-localsessionmanager",),
    "terminalservices-remoteconnectionmanager": ("remoteconnectionmanager",),
    "remotedesktopservices-rdpcorets": ("rdpcorets",),
    "bits-client": ("bits-client",),
    "codeintegrity-operational": ("codeintegrity",),
    "firewall-as": ("firewall",),
    "ntlm": ("ntlm",),
    "dhcp": ("dhcp",),
    "appmodel-runtime": ("appmodel-runtime",),
    "shell-core": ("shell-core",),
    "printservice-admin": ("printservice",),
    "printservice-operational": ("printservice",),
    "driver-framework": ("driverframeworks",),
    "windowsupdatefailure": ("windowsupdateclient",),
    "capi2": ("capi2",),
    "certificateservicesclient-lifecycle-system": ("certificateservicesclient",),
    "dns-client": ("dns-client",),
    "dns-server-analytic": ("dns-server",),
    "ldap_debug": ("ldap",),
    "vhdmp": ("vhdmp",),
    "openssh": ("openssh",),
    "microsoft-servicebus-client": ("servicebus",),
    "security-mitigations": ("security-mitigations",),
    "diagnosis-scripted": ("diagnosis-scripted",),
    "msexchange-management": ("msexchange",),
    "sense": ("sense",),
    "bitlocker": ("bitlocker",),
    "appxdeployment-server": ("appxdeployment",),
    "appxpackaging-om": ("appxpackaging",),
    "lsa-server": ("lsa",),
    "hyper-v-worker": ("hyper-v",),
    "windows-defender-application-guard": ("appguard",),
}

# Products for which this tool produces no events at all: cloud control planes, SaaS
# audit logs and network appliances. Evaluating a CloudTrail rule against a disk image
# can only waste time or produce a coincidence.
#
# The list is deliberately short, and 'linux' is deliberately NOT in it — the first
# version included it and silenced the Linux syslog rules, which is the one log source
# this tool has parsed since before it could read a Windows event. The test suite
# caught that. 'sentinelone' and 'cisco' are out too: both write Windows event
# channels that appear in real collections.
_FOREIGN_PRODUCTS = frozenset({
    "aws", "azure", "gcp", "m365", "okta", "onelogin", "github", "gworkspace",
    "google_workspace", "kubernetes", "kubernetes_audit", "zeek", "netflow",
    "opencanary", "rpc_firewall", "velocity", "django", "ruby_on_rails", "spring",
    "paloalto", "fortinet", "huawei", "juniper", "modsecurity", "apache", "nginx",
    "jvm", "qualys", "bitbucket", "gitlab", "atlassian", "salesforce", "cloudflare",
    "bitwarden", "snowflake", "airflow", "rclone",
})


# Categories that only ever apply to text logs — Apache/nginx access logs and the
# like. Measured: 134 of the 185 untargeted rules were 'webserver' or 'proxy', and each
# was being tested against all 798,000 Windows event rows where it cannot possibly
# match. Keyed on source_artifact rather than channel, because a text log has no
# channel.
#
# These are matched against the part of source_artifact BEFORE the first '/' (see
# ``candidates``), so they are prefixes: 'text' covers text/mongodb, text/apt and the
# rest. Spelling one of them 'generic_text' — the parser's name rather than its source
# prefix — silently routes the rule to a bucket no event ever lands in, which reads as
# a clean host.
_TEXT_SOURCE_PREFIXES = ("text", "linux_syslog", "mongodb")

_TEXT_CATEGORIES: dict[str, tuple[str, ...]] = {
    "webserver": ("text", "linux_syslog"),
    "proxy": ("text",),
    "firewall": ("text", "linux_syslog"),
    "dns": ("text", "linux_syslog"),
    "antivirus": ("text",),
    "database": ("text", "mongodb"),
    "application": ("text", "linux_syslog"),
}


def _rule_scope(rule: dict) -> tuple[str, frozenset[str], tuple[str, ...]]:
    """What a rule is about: ``(verdict, event_ids, channel_tokens)``.

    ``verdict`` is ``'foreign'`` for a product this tool never produces events for,
    otherwise ``'ok'``. Empty ids and tokens mean the rule could apply to anything and
    has to be tested against every event.
    """
    source = rule.get("logsource") or {}
    if not isinstance(source, dict):
        return "ok", frozenset(), ()

    product = str(source.get("product") or "").strip().lower()
    if product in _FOREIGN_PRODUCTS:
        return "foreign", frozenset(), ()

    category = str(source.get("category") or "").strip().lower()
    service = str(source.get("service") or "").strip().lower()

    # A Linux rule cannot match a Windows event log, and testing it against 798,000 of
    # them costs the same as testing one that can.
    if product in ("linux", "macos", "unix") and not service:
        return "text", frozenset(), _TEXT_SOURCE_PREFIXES

    event_ids = _CATEGORY_EVENT_IDS.get(category, frozenset())
    tokens = _SERVICE_CHANNEL_TOKENS.get(service, ())
    if not tokens and service:
        # Unknown service: use it as its own token rather than dropping the
        # constraint. A wrong-but-narrow guess yields no hits; no constraint at all
        # yields hits from the wrong log.
        tokens = (service,)
    if not event_ids and not tokens:
        text_sources = _TEXT_CATEGORIES.get(category, ())
        if text_sources:
            return "text", frozenset(), text_sources
    return "ok", event_ids, tokens

# Aggregation and correlation syntax we do not implement.
_UNSUPPORTED_CONDITION = re.compile(
    r"\|\s*(?:count|min|max|avg|sum)\s*\(|near\s+", re.I
)

_MAX_HITS_PER_RULE = 200


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _field_values(row: dict, field: str, cache: dict | None = None) -> list[str]:
    """Every place a Sigma field might live in one normalized event.

    ``cache`` is a per-row memo. Without it this was called 1,078,413 times for 4,000
    events, because 1,458 process_creation rules each resolve ``Image`` against the
    same row independently.
    """
    lowered = field.lower()
    if cache is not None:
        hit = cache.get(lowered)
        if hit is not None:
            return hit
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
    if cache is not None:
        cache[lowered] = out
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


def _match_map(row: dict, criteria: dict, cache: dict | None = None) -> bool:
    """All key/value pairs in one selection map must match (Sigma AND semantics)."""
    for raw_field, expected in criteria.items():
        parts = str(raw_field).split("|")
        field = parts[0]
        modifiers = [m.lower() for m in parts[1:]]
        unknown = set(modifiers) - _SUPPORTED_MODIFIERS
        if unknown:
            raise NotImplementedError(f"modifier(s) {sorted(unknown)}")

        haystacks = _field_values(row, field, cache)
        if isinstance(expected, list):
            # A list of values is OR, unless '|all' asks for every one.
            results = [_match_one(haystacks, item, modifiers) for item in expected]
            ok = all(results) if "all" in modifiers else any(results)
        else:
            ok = _match_one(haystacks, expected, modifiers)
        if not ok:
            return False
    return True


def _match_selection(row: dict, selection: Any, cache: dict | None = None) -> bool:
    if isinstance(selection, dict):
        return _match_map(row, selection, cache)
    if isinstance(selection, list):
        # A list of maps is OR across the maps.
        for item in selection:
            if isinstance(item, dict):
                if _match_map(row, item, cache):
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
        self._name_set = set(names)
        self._tokens = self._compile(self.expression)
        self._fn = self._build()

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

    def _build(self) -> Callable[[Callable[[str], bool]], bool]:
        """Compile the expression ONCE into a tree of closures.

        This used to render a Python boolean string per event and hand it to ``eval``.
        Profiling the real 3,308-rule corpus over 4,000 events measured **741,328
        eval() calls** — one per event/rule pair — and the whole run extrapolated to
        184 minutes. Closures are built once per rule instead of per row.

        They also make evaluation LAZY, which matters more than the eval cost. The old
        code computed every selection in the detection block up front, so a rule shaped
        ``selection and not filter1 and not filter2`` did all three even when
        ``selection`` was false — and for most rules on most events, it is.

        Nothing from the rule file is ever executed as code: the tokens accepted are
        selection names, and/or/not and parentheses, and anything else raises.
        """
        tokens = re.findall(r"\(|\)|[\w*]+|\S", self._tokens)
        pos = 0

        def peek() -> str | None:
            return tokens[pos] if pos < len(tokens) else None

        def take() -> str:
            nonlocal pos
            token = tokens[pos]
            pos += 1
            return token

        def parse_or():
            node = parse_and()
            while peek() and peek().lower() == "or":
                take()
                right = parse_and()
                left = node
                node = lambda r, a=left, b=right: a(r) or b(r)
            return node

        def parse_and():
            node = parse_not()
            while peek() and peek().lower() == "and":
                take()
                right = parse_not()
                left = node
                node = lambda r, a=left, b=right: a(r) and b(r)
            return node

        def parse_not():
            if peek() and peek().lower() == "not":
                take()
                inner = parse_not()
                return lambda r, a=inner: not a(r)
            return parse_atom()

        def parse_atom():
            token = peek()
            if token is None:
                raise NotImplementedError(f"condition {self.expression!r} ended early")
            if token == "(":
                take()
                node = parse_or()
                if peek() != ")":
                    raise NotImplementedError(f"condition {self.expression!r} unbalanced")
                take()
                return node
            take()
            low = token.lower()
            if low == "true":
                return lambda r: True
            if low == "false":
                return lambda r: False
            if not re.fullmatch(r"[\w*]+", token):
                raise NotImplementedError(f"condition token {token!r}")
            if token not in self._name_set:
                # An unknown selection name is treated as unmatched, as before.
                return lambda r: False
            return lambda r, n=token: r(n)

        node = parse_or()
        if pos != len(tokens):
            raise NotImplementedError(
                f"condition {self.expression!r} has trailing {tokens[pos]!r}"
            )
        return node

    def evaluate(self, matched: dict[str, bool]) -> bool:
        """Evaluate against a fully-computed selection map (kept for callers/tests)."""
        return self.evaluate_lazy(lambda name: bool(matched.get(name, False)))

    def evaluate_lazy(self, resolve: Callable[[str], bool]) -> bool:
        """Evaluate, asking ``resolve`` only for the selections actually needed."""
        return bool(self._fn(resolve))


def _required_conjuncts(expression: str, names: list[str]) -> list[list[str]]:
    """Selection groups that MUST match, as a list of OR-alternatives.

    ``[['selection'], ['a', 'b']]`` means selection must match, AND at least one of
    a/b must. Handles the three shapes that cover almost all of SigmaHQ:

    * ``selection and not filter``      -> [['selection']]
    * ``all of selection_* and not ...``-> one group per matching selection
    * ``1 of selection_* and not ...``  -> [['selection_a', 'selection_b', ...]]

    The last one matters: measuring the corpus showed the first version returned
    nothing for every ``1 of`` rule, so those rules skipped the prefilter entirely and
    were fully evaluated against every candidate event.

    Anything with parentheses or a top-level ``or`` yields nothing and the prefilter
    stays out of the way — being slow is recoverable, dropping a real hit is not.
    """
    text = expression.strip()
    if "(" in text or ")" in text or re.search(r"\bor\b", text, re.I):
        return []

    def expand(pattern: str) -> list[str]:
        if pattern.lower() == "them":
            return list(names)
        regex = re.compile("^" + re.escape(pattern).replace(r"\*", ".*") + "$")
        return [n for n in names if regex.match(n)]

    out: list[list[str]] = []
    for part in re.split(r"\band\b", text, flags=re.I):
        token = part.strip()
        if not token or re.match(r"\bnot\b", token, re.I):
            continue
        quantified = re.fullmatch(r"(1|all)\s+of\s+(\S+)", token, re.I)
        if quantified:
            selected = expand(quantified.group(2))
            if not selected:
                continue
            if quantified.group(1).lower() == "all":
                out.extend([name] for name in selected)
            else:
                out.append(selected)
        elif re.fullmatch(r"[\w*]+", token) and token.lower() not in ("true", "false"):
            out.append([token])
    return out


def _literal_groups(criteria: dict) -> list[frozenset[str]]:
    """Lowercase literals a selection map requires, as AND-of-OR groups.

    Every group must have at least one member present in the row's text. Fields using
    ``re``, or with non-string values, contribute nothing — a prefilter that guesses
    would drop real hits, which is the one outcome worse than being slow.
    """
    groups: list[frozenset[str]] = []
    for raw_field, expected in criteria.items():
        parts = str(raw_field).split("|")
        modifiers = {m.lower() for m in parts[1:]}
        if "re" in modifiers or "base64" in modifiers or "base64offset" in modifiers:
            continue
        if "windash" in modifiers:
            continue                        # '-x' may legitimately appear as '/x'
        values = expected if isinstance(expected, list) else [expected]
        literals = set()
        usable = True
        for value in values:
            if not isinstance(value, str) or not value.strip():
                usable = False
                break
            text = value.lower()
            if "*" in text or "?" in text:
                # Use the longest wildcard-free run; short runs are not selective.
                chunks = [c for c in re.split(r"[*?]+", text) if len(c) >= 4]
                if not chunks:
                    usable = False
                    break
                text = max(chunks, key=len)
            if len(text) < 4:
                usable = False
                break
            literals.add(text)
        if not usable or not literals:
            continue
        if isinstance(expected, list) and "all" in modifiers:
            groups.extend(frozenset({lit}) for lit in literals)
        else:
            groups.append(frozenset(literals))
    return groups


def _rule_prefilter(detection: dict, condition: str) -> list[frozenset[str]]:
    """Literal groups every matching row must contain, or ``[]`` for no prefilter.

    This is the change that makes a 3,308-rule corpus usable. 1,458 rules target
    process_creation, so each 4688 event was fully evaluated against all of them;
    with a prefilter, a row is checked against one lowercase haystack and nearly every
    rule is eliminated by a substring test.
    """
    def selection_groups(selection: Any) -> list[frozenset[str]]:
        if isinstance(selection, dict):
            return _literal_groups(selection)
        if isinstance(selection, list) and all(isinstance(i, dict) for i in selection):
            # OR across maps: only literals common to every branch are required.
            per_branch = [
                {lit for group in _literal_groups(item) for lit in group}
                for item in selection
            ]
            if per_branch and all(per_branch):
                shared = set.intersection(*per_branch)
                if shared:
                    return [frozenset(shared)]
        return []

    groups: list[frozenset[str]] = []
    for alternatives in _required_conjuncts(condition, list(detection)):
        if len(alternatives) == 1:
            groups.extend(selection_groups(detection.get(alternatives[0])))
            continue
        # '1 of x_*': the union across branches is required only if EVERY branch
        # contributes literals. One literal-free branch means any row could satisfy it.
        per_branch = [selection_groups(detection.get(name)) for name in alternatives]
        if not all(per_branch):
            continue
        union: set[str] = set()
        for branch in per_branch:
            for group in branch:
                union |= group
        if union:
            groups.append(frozenset(union))
    return groups


_HAYSTACK_COLUMNS = ("message", "event_type", "user", "host", "extra_fields",
                     "channel", "event_id", "source_artifact")


def _row_haystack(row: dict) -> str:
    """One lowercase blob per row for the prefilter to test against.

    It must cover EVERY place ``_field_values`` can look, or the prefilter silently
    drops real matches — which is the one failure worse than being slow. The first
    version used only ``data`` and ``message`` and lost a rule keyed on the
    ``event_type`` column; the test suite caught it.

    ``title`` and ``details`` are omitted deliberately: ``message`` is derived from
    exactly those two, so including them triples the string work for no coverage.

    ``data`` arrives as a JSON string straight from the store, so it already carries
    every captured field value with no per-field work.
    """
    data = row.get("data")
    parts = [data if isinstance(data, str) else ""]
    if isinstance(data, dict):
        parts.append(" ".join(map(str, data.values())))
    for column in _HAYSTACK_COLUMNS:
        value = row.get(column)
        if value:
            parts.append(value if isinstance(value, str) else str(value))
    return " ".join(parts).lower()


# Parsing 3,308 SigmaHQ YAML files costs ~17 seconds, and it is the entire top of the
# profile. JSON rather than pickle: the cache lives in a user-writable directory, and
# a cache file should never be able to execute code. YAML dates round-trip to strings,
# which is harmless — nothing here reads them.
_CACHE_VERSION = 2


def _cache_path(paths: list[Path]) -> Path | None:
    import hashlib

    try:
        digest = hashlib.sha256()
        digest.update(str(_CACHE_VERSION).encode())
        for path in paths:
            stat = path.stat()
            digest.update(str(path).encode())
            digest.update(f"{stat.st_mtime_ns}:{stat.st_size}".encode())
        root = Path.home() / ".cache" / "inspecthor"
        root.mkdir(parents=True, exist_ok=True)
        return root / f"sigma-{digest.hexdigest()[:16]}.json"
    except OSError:
        return None


def _cache_read(paths: list[Path]) -> list[dict] | None:
    import json

    target = _cache_path(paths)
    if target is None or not target.is_file():
        return None
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, list) else None


def _cache_write(paths: list[Path], rules: list[dict]) -> None:
    import json

    target = _cache_path(paths)
    if target is None:
        return
    try:
        tmp = target.with_suffix(".tmp")
        tmp.write_text(json.dumps(rules, default=str), encoding="utf-8")
        tmp.replace(target)
    except (OSError, TypeError, ValueError):
        # A cache that cannot be written is a slow run, not a failed one.
        try:
            target.with_suffix(".tmp").unlink(missing_ok=True)
        except OSError:
            pass


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

        cached = _cache_read(paths)
        if cached is not None:
            return cached

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
        _cache_write(paths, rules)
        return rules

    def evaluate(self, store, ctx: ParseContext) -> Iterator[Event]:
        rules = self._load_rules(ctx)
        if not rules:
            return

        compiled: list[tuple[dict, dict, _Condition, list[frozenset[str]]]] = []
        # Counted, not hinted one-per-rule: a SigmaHQ checkout skips rules in the
        # hundreds, and hundreds of hint lines is the same as no hint at all.
        skipped = {"foreign": 0, "aggregation": 0, "unusable": 0, "broken": 0}
        by_event_id: dict[str, list[int]] = {}
        by_channel_token: dict[str, list[int]] = {}
        by_source: dict[str, list[int]] = {}
        unscoped: list[int] = []

        for rule in rules:
            detection = dict(rule.get("detection") or {})
            condition = detection.pop("condition", None)
            detection.pop("timeframe", None)
            if not isinstance(condition, str) or not detection:
                skipped["unusable"] += 1
                continue
            if _UNSUPPORTED_CONDITION.search(condition):
                skipped["aggregation"] += 1
                continue
            verdict, event_ids, tokens = _rule_scope(rule)
            if verdict == "foreign":
                skipped["foreign"] += 1
                continue
            try:
                index = len(compiled)
                compiled.append((rule, detection, _Condition(condition, list(detection)),
                                 _rule_prefilter(detection, condition)))
            except Exception:
                skipped["unusable"] += 1
                continue

            # Exactly one bucket per rule, most selective first.
            if event_ids:
                for eid in event_ids:
                    by_event_id.setdefault(eid, []).append(index)
            elif verdict == "text":
                for source in tokens:
                    by_source.setdefault(source, []).append(index)
            elif tokens:
                for token in tokens:
                    by_channel_token.setdefault(token, []).append(index)
            else:
                unscoped.append(index)

        if not compiled:
            ctx.hint(f"sigma: no usable rules ({skipped})")
            return

        total = len(compiled)
        ctx.hint(
            f"sigma: {total} rule(s) active — {len(unscoped)} untargeted; skipped "
            f"{skipped['foreign']} non-Windows, {skipped['aggregation']} aggregation, "
            f"{skipped['unusable']} unparseable"
        )

        hits: dict[str, int] = {}
        broken: set[int] = set()
        # Channel -> candidate rule list. Resolving a channel means a substring test
        # per token, so it is done once per distinct channel rather than per event.
        channel_cache: dict[str, list[int]] = {}

        def candidates(row: dict) -> list[int]:
            eid = str(row.get("event_id") or "")
            channel = str(row.get("channel") or "").lower()
            if channel not in channel_cache:
                resolved: list[int] = []
                for token, indexes in by_channel_token.items():
                    if token in channel:
                        resolved.extend(indexes)
                channel_cache[channel] = resolved
            source = str(row.get("source_artifact") or "").split("/", 1)[0]
            return (by_event_id.get(eid, []) + channel_cache[channel]
                    + by_source.get(source, []) + unscoped)

        prefiltered = 0
        for row in store.iter_events():
            applicable = candidates(row)
            if not applicable:
                # Most events in a real collection belong to channels no rule targets.
                # Building a lowercase haystack for those is pure cost.
                continue
            haystack = _row_haystack(row)
            # One field cache per row, shared by every rule tested against it. 1,458
            # process_creation rules all resolve 'Image' on the same event.
            field_cache: dict[str, list[str]] = {}
            for index in applicable:
                if index in broken:
                    continue
                rule, detection, condition, groups = compiled[index]
                title = str(rule.get("title", "untitled"))
                if hits.get(title, 0) >= _MAX_HITS_PER_RULE:
                    continue
                # Substring test before any field resolution. This is what makes the
                # corpus usable at all: nearly every rule dies here in microseconds.
                if groups and not all(
                    any(lit in haystack for lit in group) for group in groups
                ):
                    prefiltered += 1
                    continue
                try:
                    if not condition.evaluate_lazy(
                        lambda name: _match_selection(
                            row, detection.get(name), field_cache
                        )
                    ):
                        continue
                except NotImplementedError:
                    broken.add(index)
                    skipped["broken"] += 1
                    continue
                except Exception:
                    broken.add(index)
                    skipped["broken"] += 1
                    continue

                hits[title] = hits.get(title, 0) + 1
                yield self._hit_event(rule, row, ctx)

        capped = [t for t, c in hits.items() if c >= _MAX_HITS_PER_RULE]
        if capped:
            ctx.hint(
                f"sigma: {len(capped)} rule(s) capped at {_MAX_HITS_PER_RULE} hits "
                f"({', '.join(sorted(capped)[:3])}{'...' if len(capped) > 3 else ''})"
            )
        if skipped["broken"]:
            ctx.hint(
                f"sigma: {skipped['broken']} rule(s) used an unsupported modifier "
                "and were dropped mid-run"
            )
        ctx.hint(f"sigma: {len(hits)} of {total} rule(s) matched at least once")

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
