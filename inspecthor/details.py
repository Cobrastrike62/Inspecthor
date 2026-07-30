"""Turning a record's fields into one line a human can read.

The output shape is ``Label: value ¦ Label: value``, borrowed from Hayabusa
because it works: the important fields inline, labelled, in one column.

CONSTRAINT: this can never return an empty string. The bug it exists to fix was
418,514 rows whose entire message was the words "windows event" — the parser used
an allow-list of ~30 field names, so for the 200+ providers in real evidence it
read the fields and threw them away. There is a three-tier build below and an
assert at the bottom; if a record has anything at all, something readable comes
out.

CONSTRAINT: label style is the honesty signal. A curated template uses short
labels (``SrcIP``, ``TgtUser``). Anything auto-dumped keeps the raw Windows field
names (``IpAddress``, ``TargetUserName``). An analyst can then tell at a glance
which rows the tool understands and which it is only transcribing — no extra
column, no prose. Do not "tidy" the auto-dump labels.
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Sequence

# Space, U+00A6 BROKEN BAR, space. Not a pipe: the markdown report escapes '|' to
# '\|', which would appear in every row; and U+00A6 exists in cp1252, so it also
# survives a Windows console whose UTF-8 reconfigure failed.
SEP = " ¦ "

DETAILS_MAX = 512          # rendered string
TEMPLATE_PAIRS = 12
AUTO_PAIRS = 10
VALUE_MAX = 200
AUTO_VALUE_MAX = 120
EXTRA_MAX = 512

# Fields that answer questions, so the auto-dump leads with them instead of
# alphabetical order. Everything else follows, naturally sorted.
AUTO_PRIORITY: tuple[str, ...] = (
    "SubjectUserName", "TargetUserName", "AccountName", "User", "UserName",
    "IpAddress", "ClientAddress", "SourceAddress", "Address", "WorkstationName",
    "Workstation", "CommandLine", "ProcessCommandLine", "Image", "NewProcessName",
    "ProcessName", "ImagePath", "ServiceFileName", "ServiceName", "TaskName",
    "TargetFilename", "TargetObject", "ObjectName", "ShareName",
    "RelativeTargetName", "QueryName", "QueryResults", "DestinationIp",
    "DestinationHostname", "DestinationPort", "SourcePort", "ScriptBlockText",
    "Payload", "HostApplication", "Status", "SubStatus", "LogonType",
    "AuthenticationPackageName", "LmPackageName", "PrivilegeList", "MemberName",
    "TargetSid", "Hashes", "ParentImage", "ParentCommandLine", "ThreatName",
)
_PRIORITY_INDEX = {name.lower(): i for i, name in enumerate(AUTO_PRIORITY)}

# Never worth a column: already promoted to their own event fields, or pure noise.
_AUTO_SKIP = frozenset({
    "event_id", "eventid", "channel", "provider", "computer", "_truncated",
    "keywords", "opcode", "version", "level", "task", "eventrecordid",
    "record_id", "processid", "threadid", "correlation", "execution",
    "guid", "eventsourcename",
})

_LOGON_TYPES = {
    "0": "System", "2": "Interactive", "3": "Network", "4": "Batch",
    "5": "Service", "7": "Unlock", "8": "NetworkCleartext",
    "9": "NewCredentials", "10": "RemoteInteractive", "11": "CachedInteractive",
    "12": "CachedRemoteInteractive", "13": "CachedUnlock",
}

# The status codes that actually tell you what happened on a failed logon.
_NTSTATUS = {
    "0xc000006a": "bad password", "0xc0000064": "user does not exist",
    "0xc0000234": "account locked out", "0xc0000072": "account disabled",
    "0xc0000070": "workstation restriction", "0xc000006f": "outside logon hours",
    "0xc0000193": "account expired", "0xc0000071": "password expired",
    "0xc0000224": "must change password", "0xc000015b": "logon type not granted",
    "0xc000006d": "bad username or password", "0xc000006e": "account restriction",
    "0xc0000133": "clock skew between DC and client", "0x0": "success",
}

# Kerberos failure codes. Dispatched separately from NTSTATUS: 0x18 is a Kerberos
# 'bad password' but would be nonsense read as an NTSTATUS.
_KERBEROS = {
    "0x6": "client not found in Kerberos database", "0x7": "server not found",
    "0x9": "password has not been set", "0xc": "policy restriction (workstation/time)",
    "0x12": "account disabled, expired or locked out", "0x17": "password expired",
    "0x18": "bad password (pre-auth failed)", "0x1b": "server must use user2user",
    "0x1f": "integrity check failed", "0x20": "ticket expired",
    "0x25": "clock skew too great", "0x0": "success",
}
_KERBEROS_IDS = frozenset({"4768", "4769", "4771", "4772", "4773", "4776"})

_TICKET_ENC = {
    "0x1": "DES-CBC-CRC (weak)", "0x3": "DES-CBC-MD5 (weak)",
    "0x11": "AES128-CTS-HMAC-SHA1", "0x12": "AES256-CTS-HMAC-SHA1",
    "0x17": "RC4-HMAC (downgrade)", "0x18": "RC4-HMAC-EXP (downgrade)",
    "0xffffffff": "unknown",
}

_SERVICE_START = {
    "0": "boot", "1": "system", "2": "auto", "3": "manual", "4": "disabled",
}

_NUM_RE = re.compile(r"(\d+)")


def _natkey(name: str) -> tuple:
    """Natural sort, so param2 comes before param10."""
    return tuple(
        int(part) if part.isdigit() else part.lower()
        for part in _NUM_RE.split(name)
    )


def _clean(value: Any) -> str:
    """One-line, whitespace-collapsed text."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return " ".join(str(value).split())


def _cap(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def decode(field: str, value: str, event_id: str = "") -> str:
    """Append the meaning of a coded value; never replace the raw value.

    ``"3"`` becomes ``"3 (Network)"``. An analyst who knows the codes loses
    nothing, and one who does not gains the answer.
    """
    low = field.lower()
    raw = value.strip()
    key = raw.lower()

    if low == "logontype":
        meaning = _LOGON_TYPES.get(raw)
    elif low in ("status", "substatus", "resultcode", "failurereason"):
        table = _KERBEROS if event_id in _KERBEROS_IDS else _NTSTATUS
        meaning = table.get(key)
    elif low == "ticketencryptiontype":
        meaning = _TICKET_ENC.get(key)
    elif low == "preauthtype":
        meaning = "none — AS-REP roastable" if raw == "0" else None
    elif low in ("starttype", "servicestarttype"):
        meaning = _SERVICE_START.get(raw)
    else:
        meaning = None
    return f"{raw} ({meaning})" if meaning else raw


def normalize_ip(value: str) -> str:
    """Make an address comparable, so IOC correlation actually matches.

    '-' is not an address, and an IPv4-mapped IPv6 form should read as the IPv4.
    """
    text = value.strip()
    if text in ("-", "::", ""):
        return ""
    if text.lower().startswith("::ffff:"):
        return text[7:]
    if text == "::1":
        return "127.0.0.1"
    return text


def render_pairs(pairs: Iterable[tuple[str, str]], limit: int = DETAILS_MAX) -> str:
    """Join label/value pairs, dropping empties and marking truncation."""
    parts: list[str] = []
    used = 0
    dropped = 0
    for label, value in pairs:
        if value in (None, ""):
            continue
        piece = f"{label}: {value}"
        if used + len(piece) + len(SEP) > limit:
            dropped += 1
            continue
        parts.append(piece)
        used += len(piece) + len(SEP)
    if dropped:
        parts.append(f"+{dropped} more")
    return SEP.join(parts)


def template_pairs(
    data: Mapping[str, Any],
    fields: Sequence[tuple[str, Sequence[str]]],
    event_id: str = "",
) -> tuple[list[tuple[str, str]], set[str]]:
    """Tier 1 pairs, plus the set of source keys consumed.

    Each template field lists candidate Windows names in order, so a field renamed
    between Windows versions still resolves.
    """
    pairs: list[tuple[str, str]] = []
    consumed: set[str] = set()
    lookup = {str(k).lower(): (k, v) for k, v in data.items()}

    for label, names in list(fields)[:TEMPLATE_PAIRS]:
        for name in names:
            hit = lookup.get(str(name).lower())
            if not hit:
                continue
            key, raw = hit
            text = _clean(raw)
            if not text:
                continue
            if "ip" in name.lower() or "address" in name.lower():
                text = normalize_ip(text)
                if not text:
                    consumed.add(key)
                    break
            pairs.append((label, _cap(decode(name, text, event_id), VALUE_MAX)))
            consumed.add(key)
            break
    return pairs, consumed


def auto_pairs(
    data: Mapping[str, Any],
    skip: Iterable[str] = (),
    limit: int = AUTO_PAIRS,
    event_id: str = "",
) -> list[tuple[str, str]]:
    """Tier 2: every remaining field, labelled with its RAW Windows name.

    Dumping them all is the point. A whitelist is what produced 418k unreadable
    rows, and there is no way to know in advance which field matters for a
    provider nobody has written a template for.
    """
    skipped = {str(s).lower() for s in skip} | _AUTO_SKIP
    candidates = [
        (str(k), _clean(v))
        for k, v in data.items()
        if str(k).lower() not in skipped and v not in (None, "")
    ]
    candidates.sort(
        key=lambda kv: (_PRIORITY_INDEX.get(kv[0].lower(), 999), _natkey(kv[0]))
    )
    out = [
        (key, _cap(decode(key, value, event_id), AUTO_VALUE_MAX))
        for key, value in candidates[:limit]
        if value
    ]
    remaining = max(0, len([c for c in candidates if c[1]]) - limit)
    if remaining:
        out.append(("+", f"{remaining} more fields"))
    return out


def build_details(
    data: Mapping[str, Any],
    fields: Sequence[tuple[str, Sequence[str]]] | None = None,
    *,
    provider: str = "",
    channel: str = "",
    event_id: str = "",
) -> tuple[str, str]:
    """``(details, extra)`` for one record.

    ``details`` is what a human reads; ``extra`` is whatever the template did not
    consume, in the same format, so the CSV stays scannable without a JSON blob.
    """
    pairs: list[tuple[str, str]] = []
    consumed: set[str] = set()

    if fields:
        pairs, consumed = template_pairs(data, fields, event_id)

    if pairs:
        details = render_pairs(pairs)
        extra = render_pairs(auto_pairs(data, skip=consumed, event_id=event_id), EXTRA_MAX)
    else:
        # Tier 2: no template, or the template matched nothing in this record.
        details = render_pairs(auto_pairs(data, event_id=event_id))
        extra = ""

    if not details:
        # Tier 3: the record genuinely carries no field data. Say so, with
        # provenance, rather than emitting a bare noun.
        details = render_pairs([
            ("Provider", _clean(provider)),
            ("Channel", _clean(channel)),
            ("EventID", _clean(event_id)),
            ("NoFieldData", "record carries no EventData"),
        ])

    # The regression guard for the bug this module exists to fix.
    assert details, "details must never be empty"
    return details, extra


def parse_details(text: str) -> dict[str, str]:
    """Reverse of :func:`render_pairs`, for tools reading a CSV back."""
    out: dict[str, str] = {}
    for piece in str(text or "").split(SEP):
        label, _, value = piece.partition(":")
        label = label.strip()
        if label:
            out[label] = value.strip()
    return out
