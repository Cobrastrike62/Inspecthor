"""Evidence ingest: unpack, fingerprint, route, parse, persist.

CONSTRAINT: evidence is read-only. Files are opened 'rb', hashed, and never
written to. Archives are extracted to a separate working directory.

CONSTRAINT: every bound in this module exists because the input is hostile.
Sherlock packages and real incident evidence contain zip bombs, traversal paths,
truncated archives, and files that expand to gigabytes. Caps are module constants
so they are visible and adjustable rather than buried.

CONSTRAINT: one bad artifact never aborts a case. Each file is parsed inside its
own try/except and recorded as 'error' so the remaining evidence still lands.
"""
from __future__ import annotations

import hashlib
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from .models import ArtifactResult, Event, Fingerprint, ParseContext
from .parsers._loader import select_parser

# ---- bounds ----

_MAX_FILES = 5000                       # files walked per evidence set
_TEXT_READ_CAP = 64 * 1024 * 1024       # per-file text budget handed to parsers
_MAX_EVENTS_PER_ARTIFACT = 2_000_000    # a pathological artifact cannot hang a case
_HEADER_BYTES = 512                     # bytes read for magic sniffing
_ZIP_MAX_ENTRIES = 100_000
_ZIP_MAX_TOTAL = 16 * 1024 ** 3         # 16 GiB uncompressed ceiling (zip-bomb guard)
_HASH_CHUNK = 1024 * 1024

# HTB ships Sherlock evidence and challenge archives under fixed passwords.
# Trying them automatically removes the most tedious step of starting a case.
_HTB_PASSWORDS: tuple[Optional[bytes], ...] = (b"hacktheblue", b"hackthebox", None)

# ---- fingerprinting ----

# Magic-byte table. Extensions lie in collected evidence; headers do not.
# Order matters only in that the first prefix match wins.
_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"regf", "registry"),                  # NTUSER.DAT / SYSTEM / SOFTWARE / SAM / Amcache
    (b"ElfFile\x00", "evtx"),                # Windows event log
    (b"FILE0", "mft"),                       # $MFT file record
    (b"BAAD", "mft"),                        # ...corrupt record, still an MFT
    (b"SQLite format 3\x00", "sqlite"),      # browser history, app databases
    (b"MAM\x04", "prefetch"),                # Win10+ compressed prefetch
    (b"\xd4\xc3\xb2\xa1", "pcap"),
    (b"\xa1\xb2\xc3\xd4", "pcap"),
    (b"\x4d\x3c\xb2\xa1", "pcap"),
    (b"\xa1\xb2\x3c\x4d", "pcap"),
    (b"\x0a\x0d\x0d\x0a", "pcapng"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"PK\x03\x04", "zip"),
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (b"%PDF", "pdf"),
    (b"\xd0\xcf\x11\xe0", "ole"),            # legacy Office / MSI / some jumplists
)

# LNK is a fixed 76-byte header plus a known CLSID — checking both avoids
# claiming every file that happens to start with 0x4C.
_LNK_HEADER = b"\x4c\x00\x00\x00"
_LNK_CLSID = b"\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"

# Text content markers that make a plain file recognizably a syslog.
_SYSLOG_MARKERS = ("sshd[", "sudo:", "systemd[", "cron[", "kernel:", "CRON[")


def sha256_file(path: Path) -> str:
    """Streamed SHA-256 of a file. Empty string if unreadable."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def sniff(path: Path) -> Fingerprint:
    """Identify a file by content, falling back to a printable-ratio heuristic."""
    try:
        stat = path.stat()
        with path.open("rb") as handle:
            header = handle.read(_HEADER_BYTES)
    except OSError:
        return Fingerprint(path=path, kind="unreadable", confidence=0.0)

    fingerprint = Fingerprint(
        path=path,
        size=stat.st_size,
        mtime=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
        confidence=1.0,
    )

    for magic, kind in _MAGIC:
        if header.startswith(magic):
            fingerprint.kind = kind
            return fingerprint

    # Win7/8 prefetch keeps 'SCCA' at offset 4, not 0.
    if header[4:8] == b"SCCA":
        fingerprint.kind = "prefetch"
        return fingerprint

    if header.startswith(_LNK_HEADER) and _LNK_CLSID in header[:32]:
        fingerprint.kind = "lnk"
        return fingerprint

    if not header:
        fingerprint.kind = "empty"
        fingerprint.confidence = 0.0
        return fingerprint

    if b"\x00" not in header:
        printable = sum(1 for b in header if 9 <= b <= 13 or 32 <= b <= 126)
        if printable / len(header) > 0.85:
            text = header.decode("utf-8", "replace")
            fingerprint.kind = (
                "syslog" if any(m in text for m in _SYSLOG_MARKERS) else "text"
            )
            fingerprint.confidence = 0.85
            return fingerprint

    fingerprint.kind = "binary"
    fingerprint.confidence = 0.5
    return fingerprint


def discover(root: Path, max_files: int = _MAX_FILES) -> list[Path]:
    """Walk an evidence tree, skipping noise, bounded by ``max_files``."""
    found: list[Path] = []
    try:
        walker = sorted(root.rglob("*"))
    except OSError:
        return found
    for candidate in walker:
        if len(found) >= max_files:
            break
        try:
            if not candidate.is_file():
                continue
        except OSError:
            continue
        name = candidate.name
        if name.startswith(".") or name == ".gitkeep":
            continue
        if "__pycache__" in candidate.parts:
            continue
        found.append(candidate)
    return found


# ---- unpacking ----


def _zip_within_bounds(archive: zipfile.ZipFile) -> tuple[bool, str]:
    """Reject an archive before writing anything, not after."""
    infos = archive.infolist()
    if len(infos) > _ZIP_MAX_ENTRIES:
        return False, f"archive has {len(infos)} entries (cap {_ZIP_MAX_ENTRIES})"
    total = sum(max(info.file_size, 0) for info in infos)
    if total > _ZIP_MAX_TOTAL:
        return False, f"archive expands to {total} bytes (cap {_ZIP_MAX_TOTAL})"
    return True, ""


def _extract_zip(src: Path, dest: Path) -> tuple[bool, str]:
    """Extract a zip, trying the HTB passwords in turn.

    CPython sanitizes member paths in ``extractall``, so traversal is handled;
    the size/entry caps above are the part it does not do for us.
    """
    try:
        with zipfile.ZipFile(src) as archive:
            ok, why = _zip_within_bounds(archive)
            if not ok:
                return False, why
            last_error = ""
            for password in _HTB_PASSWORDS:
                try:
                    archive.extractall(dest, pwd=password)
                    return True, ""
                except RuntimeError as exc:      # wrong/needed password
                    last_error = str(exc)
                    continue
                except Exception as exc:
                    return False, f"{type(exc).__name__}: {exc}"
            return False, last_error or "could not extract (password?)"
    except zipfile.BadZipFile as exc:
        return False, f"bad zip: {exc}"
    except OSError as exc:
        return False, str(exc)


def _extract_tar(src: Path, dest: Path) -> tuple[bool, str]:
    """Extract a tarball with traversal filtering.

    ``filter="data"`` blocks absolute paths, '..' escapes, and special files. It
    landed in 3.12, so older interpreters fall back — the TypeError branch is the
    only way to stay compatible without losing the guard where it exists.
    """
    try:
        with tarfile.open(src) as archive:
            try:
                archive.extractall(dest, filter="data")
            except TypeError:
                archive.extractall(dest)
        return True, ""
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def open_evidence(src: Path, workdir: Path | None = None) -> tuple[Path, str]:
    """Resolve evidence to a directory to walk.

    Returns ``(root, note)``. A directory is used in place; an archive is
    extracted into ``workdir``. ``note`` carries anything the console should say
    (extraction failures, password used).
    """
    src = Path(src)
    if src.is_dir():
        return src, ""
    if not src.exists():
        return src, f"no such evidence path: {src}"

    dest = Path(workdir) if workdir else src.parent / f"{src.stem}_extracted"
    dest.mkdir(parents=True, exist_ok=True)

    fingerprint = sniff(src)
    if fingerprint.kind == "zip":
        ok, why = _extract_zip(src, dest)
        return (dest, "") if ok else (src, f"zip extract failed: {why}")
    if fingerprint.kind in ("gzip", "bzip2", "xz") or src.suffixes[-2:] == [".tar", ".gz"]:
        ok, why = _extract_tar(src, dest)
        if ok:
            return dest, ""
        return src, f"tar extract failed: {why}"
    # A single loose artifact: treat its parent as the evidence root but only
    # after copying nothing — the caller can still parse the one file.
    return src, ""


# ---- ingest ----


class Engine:
    """Drives fingerprint -> parser -> store for an evidence set.

    CONSTRAINT: returns ArtifactResult objects and never prints, so the same
    ingest serves the CLI, the autonomous analysis, and the tests.
    """

    def __init__(self, store, max_files: int = _MAX_FILES) -> None:
        self.store = store
        self.max_files = max_files

    def plan(self, root: Path) -> tuple[list[Path], list[Path]]:
        """Split evidence into ``(self_dating, needs_context)``.

        Formats that record absolute time go first so the case's timezone, year,
        and hostname can be derived from them; formats that omit those (classic
        syslog) are held back for the second pass.
        """
        root = Path(root)
        targets = [root] if root.is_file() else discover(root, self.max_files)
        first: list[Path] = []
        second: list[Path] = []
        for path in targets:
            if self._needs_context(path):
                second.append(path)
            else:
                first.append(path)
        return first, second

    def _needs_context(self, path: Path) -> bool:
        try:
            with path.open("rb") as handle:
                header = handle.read(_HEADER_BYTES)
        except OSError:
            return False
        chosen, _unavailable = select_parser(path, header, sniff(path).kind)
        return bool(chosen and getattr(chosen, "needs_time_context", False))

    def ingest(
        self,
        root: Path,
        host: str = "",
        tz=timezone.utc,
        year_hint: int | None = None,
        attack=None,
        detectors: list | None = None,
        paths: list[Path] | None = None,
        finalize: bool = True,
    ) -> Iterator[ArtifactResult]:
        """Ingest evidence, yielding one result per artifact.

        ``paths`` restricts the run to a specific set, which is how the two-pass
        flow works: pass the self-dating files, derive context, then pass the rest.
        """
        root = Path(root)
        if paths is None:
            paths = [root] if root.is_file() else discover(root, self.max_files)

        for path in paths:
            yield self._ingest_one(
                path, root, host, tz, year_hint, attack, detectors or []
            )

        if finalize:
            self.store.finalize()

    def _ingest_one(
        self, path: Path, root: Path, host: str, tz, year_hint, attack, detectors: list
    ) -> ArtifactResult:
        """Fingerprint, route, and parse one artifact. Never raises."""
        fingerprint = sniff(path)
        result = ArtifactResult(path=path, kind=fingerprint.kind)

        digest = sha256_file(path)
        artifact_id = self.store.add_artifact(
            path=str(path),
            sha256=digest,
            kind=fingerprint.kind,
            size=fingerprint.size,
            mtime=fingerprint.mtime.strftime("%Y-%m-%d %H:%M:%S") if fingerprint.mtime else "",
        )
        result.artifact_id = artifact_id

        try:
            with path.open("rb") as handle:
                header = handle.read(_HEADER_BYTES)
        except OSError as exc:
            result.status = "error"
            result.error = str(exc)
            self.store.set_artifact_status(artifact_id, "error", error=result.error)
            return result

        chosen, unavailable = select_parser(path, header, fingerprint.kind)

        if chosen is None:
            result.status = "unsupported"
            if unavailable is not None:
                _ok, hint = unavailable.dependency_ok()
                result.parser = unavailable.name
                result.hint = f"would parse with {unavailable.name} — {hint}"
            self.store.set_artifact_status(
                artifact_id, "unsupported", parser=result.parser or None, hint=result.hint or None
            )
            return result

        result.parser = chosen.name
        ctx = ParseContext(
            evidence_root=root if root.is_dir() else root.parent,
            host=host,
            tz=tz,
            year_hint=year_hint,
            artifact_sha256=digest,
            attack=attack,
            max_records=_MAX_EVENTS_PER_ARTIFACT,
            max_bytes=_TEXT_READ_CAP,
        )

        try:
            count = self.store.add_events_bulk(
                chosen.parse(path, ctx),
                artifact_id=artifact_id,
                max_events=_MAX_EVENTS_PER_ARTIFACT,
            )
        except Exception as exc:
            # This artifact is a loss; the case is not.
            result.status = "error"
            result.error = f"{type(exc).__name__}: {exc}"
            self.store.set_artifact_status(artifact_id, "error", parser=chosen.name, error=result.error)
            return result

        # Detectors scan the raw file regardless of which parser claimed it.
        for detector in detectors:
            try:
                for event in detector.scan(path, ctx):
                    self.store.add_events_bulk([event], artifact_id=artifact_id)
                    count += 1
            except Exception:
                continue

        result.event_count = count
        result.status = "parsed"
        if ctx.hints:
            result.hint = "; ".join(ctx.hints)
        self.store.set_artifact_status(
            artifact_id, "parsed", parser=chosen.name, event_count=count,
            hint=result.hint or None,
        )
        return result
