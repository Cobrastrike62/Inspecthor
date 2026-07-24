"""Indicator extraction.

CONSTRAINT: noisy indicators are TAGGED, never dropped. Private addresses and
allowlisted CDN domains stay in the store marked 'private'/'allowlisted' so the
analyst can filter them out in a view — because occasionally the answer really is
an internal pivot host or an abused legitimate service, and a discarded indicator
cannot be recovered without re-ingesting.

CONSTRAINT: silent library. Returns counts; the console renders them.
"""
from __future__ import annotations

import ipaddress
import re
from importlib.resources import files
from pathlib import Path
from typing import Iterable, Iterator

# Order matters: the longest hash first, so a SHA-256 is not reported as an MD5
# that happens to be a prefix of it.
_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("url", re.compile(r"\b(?:https?|ftps?)://[^\s\"'<>\\)\]}]+", re.I)),
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("sha256", re.compile(r"\b[A-Fa-f0-9]{64}\b")),
    ("sha1", re.compile(r"\b[A-Fa-f0-9]{40}\b")),
    ("md5", re.compile(r"\b[A-Fa-f0-9]{32}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("ipv6", re.compile(r"(?<![:.\w])(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}(?![:.\w])")),
    ("domain", re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")),
)

# Defanging styles seen in reports, tickets, and Sherlock task files.
_REFANG = (
    (re.compile(r"h[xX]{2}p(s?)://", re.I), r"http\1://"),
    (re.compile(r"\bf[xX]p://", re.I), "ftp://"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\s\.\s"), "."),
    (re.compile(r"\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]|\(:\)"), ":"),
    (re.compile(r"\[@\]|\(at\)|\[at\]", re.I), "@"),
    (re.compile(r"\[//\]"), "//"),
)

# File extensions that make a "domain" match actually a filename (evil.exe).
_FILE_TLDS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "py", "sh",
    "log", "txt", "csv", "json", "xml", "zip", "rar", "gz", "tar", "7z", "db",
    "dat", "tmp", "bak", "ini", "cfg", "conf", "yml", "yaml", "md", "png", "jpg",
    "jpeg", "gif", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "evtx",
    "pf", "hve", "lnk", "sqlite", "dmp", "raw", "img", "iso", "msi", "inf",
    "local", "internal", "lan", "home", "arpa", "invalid", "test", "localdomain",
}

_MAX_VALUE_LEN = 500


def refang(text: str) -> str:
    """Undo report-style defanging so indicators match their real form."""
    out = text
    for pattern, replacement in _REFANG:
        out = pattern.sub(replacement, out)
    return out


def _load_allowlist() -> set[str]:
    try:
        raw = files("inspecthor.data").joinpath("ioc_allowlist.txt").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return set()
    entries = set()
    for line in raw.splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            entries.add(line)
    return entries


def _ip_tags(value: str) -> list[str] | None:
    """Tags for an address, or None if it is not a valid address at all."""
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    tags = []
    if addr.is_private:
        tags.append("private")
    if addr.is_loopback:
        tags.append("loopback")
    if addr.is_multicast:
        tags.append("multicast")
    if addr.is_reserved or addr.is_unspecified:
        tags.append("reserved")
    return tags


def _domain_ok(value: str) -> bool:
    """Reject filenames and version strings masquerading as domains."""
    lowered = value.lower().rstrip(".")
    tld = lowered.rsplit(".", 1)[-1]
    if tld in _FILE_TLDS or tld.isdigit():
        return False
    if len(lowered) > 253 or lowered.startswith("-"):
        return False
    # "4.1.2" style version strings arrive as ipv4 misses, not domains, but
    # "1.2.foo" should still not count.
    first = lowered.split(".", 1)[0]
    return not first.isdigit()


def _allowlisted(value: str, allowlist: set[str]) -> bool:
    lowered = value.lower().rstrip(".")
    if lowered in allowlist:
        return True
    parts = lowered.split(".")
    for i in range(len(parts)):
        if "." + ".".join(parts[i:]) in allowlist:
            return True
    return False


def extract_iocs(text: str, allowlist: set[str] | None = None) -> list[tuple[str, str, list[str]]]:
    """Pull indicators from a blob of text.

    Returns ``[(type, canonical_value, tags), ...]``, deduped, refanged. Hashes
    are lowercased for storage consistency (the Sherlock formatter uppercases at
    display time, which is what HTB expects).
    """
    allowlist = allowlist if allowlist is not None else _load_allowlist()
    if not text:
        return []
    defanged_seen = text != refang(text)
    hay = refang(text)

    out: list[tuple[str, str, list[str]]] = []
    seen: set[tuple[str, str]] = set()
    # Track spans already claimed by a more specific pattern so a URL's host is
    # not also reported as a bare domain hit from the same characters.
    claimed: list[tuple[int, int]] = []

    for kind, pattern in _PATTERNS:
        for match in pattern.finditer(hay):
            start, end = match.span()
            value = match.group(0).strip().rstrip(".,;:)]}\"'")
            if not value or len(value) > _MAX_VALUE_LEN:
                continue
            if kind in ("domain",) and any(s <= start and end <= e for s, e in claimed):
                continue

            tags: list[str] = []
            if kind in ("ipv4", "ipv6"):
                ip_tags = _ip_tags(value)
                if ip_tags is None:
                    continue
                tags.extend(ip_tags)
            elif kind == "domain":
                if not _domain_ok(value):
                    continue
                value = value.lower().rstrip(".")
            elif kind in ("md5", "sha1", "sha256"):
                value = value.lower()
            elif kind == "email":
                value = value.lower()

            if kind in ("domain", "url", "email") and _allowlisted(
                value if kind == "domain" else _host_of(value), allowlist
            ):
                tags.append("allowlisted")
            if defanged_seen:
                tags.append("defanged")

            key = (kind, value)
            if key in seen:
                continue
            seen.add(key)
            claimed.append((start, end))
            out.append((kind, value, tags))
    return out


def _host_of(value: str) -> str:
    """Host portion of a URL or email, for allowlist checks."""
    text = value
    if "://" in text:
        text = text.split("://", 1)[1]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    for sep in ("/", ":", "?", "#"):
        text = text.split(sep, 1)[0]
    return text.lower().rstrip(".")


class IocSweeper:
    """Sweeps the case for indicators and links each back to its source event.

    CONSTRAINT: links, not just values. "Where did this IP come from" must be a
    join against ioc_hits, not a re-scan of the evidence.
    """

    def __init__(self, store, use_iocextract: bool | None = None) -> None:
        self.store = store
        self.allowlist = _load_allowlist()
        self._iocextract = None
        if use_iocextract is not False:
            try:
                # iocextract emits SyntaxWarnings on import under newer Pythons
                # (unescaped regex literals in its own source). Those are its
                # problem, not the analyst's, and they would otherwise land in the
                # middle of a report.
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SyntaxWarning)
                    import iocextract     # optional [ioc] extra
                self._iocextract = iocextract
            except ImportError:
                self._iocextract = None

    @property
    def enriched(self) -> bool:
        """True when the optional iocextract library is augmenting the regexes."""
        return self._iocextract is not None

    def _extra_from_iocextract(self, text: str) -> Iterator[tuple[str, str, list[str]]]:
        """URL/host shapes the stdlib patterns miss (obfuscated, nested)."""
        if self._iocextract is None:
            return
        try:
            for url in self._iocextract.extract_urls(text, refang=True):
                value = url.strip().rstrip(".,;:)]}\"'")
                if value and len(value) <= _MAX_VALUE_LEN:
                    yield "url", value, ["iocextract"]
        except Exception:
            return

    def sweep(self, include_raw: bool = True) -> dict[str, int]:
        """Scan every event's text, upsert indicators, link hits.

        Returns a per-type count of distinct indicators found.
        """
        tally: dict[str, int] = {}
        seen_links: set[tuple[int, int]] = set()

        for row in self.store.iter_events():
            parts = [str(row.get("message") or "")]
            data = row.get("data") or {}
            if isinstance(data, dict):
                parts.extend(str(v) for v in data.values() if v is not None)
            if include_raw and row.get("raw"):
                parts.append(str(row["raw"]))
            text = "\n".join(parts)
            if not text.strip():
                continue

            found = extract_iocs(text, self.allowlist)
            found.extend(self._extra_from_iocextract(text))

            for kind, value, tags in found:
                ioc_id = self.store.add_ioc(kind, value, tags=tags)
                link = (ioc_id, int(row["id"]))
                if link not in seen_links:
                    self.store.link_ioc(ioc_id, event_id=int(row["id"]),
                                        artifact_id=row.get("artifact_id"))
                    seen_links.add(link)
                tally[kind] = tally.get(kind, 0) + 1

        self.store.commit()
        # Report distinct counts, which is what an analyst means by "how many IPs".
        return {
            kind: len([i for i in self.store.get_iocs(kind)])
            for kind in sorted(tally)
        }
