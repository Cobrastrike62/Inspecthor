"""Disk images and virtual disks as evidence.

KAPE writes its collections as a VHDX, which is a container holding an NTFS
volume holding the artifacts. That is the same shape as a zip — something to open
before there are files to parse — so it belongs beside the archive handling in
``engine.py`` rather than in a parser.

CONSTRAINT: extraction is SELECTIVE. A KAPE VHDX of 1500 files is mostly formats
this tool cannot parse yet, and a full disk image is worse; copying all of it out
would burn gigabytes to no purpose. Only files a registered parser would claim get
written, and what was skipped is reported by type so the analyst sees the coverage
gap rather than an empty case.

CONSTRAINT: never guess a container by extension. A ``.vhdx`` produced by
something else, or an image renamed by a collection script, is identified by its
signature like every other artifact.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional

# Signatures at offset 0. dissect can read more formats than this, but a
# signature is the honest way to know what we are looking at.
_IMAGE_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"vhdxfile", "vhdx"),          # Hyper-V VHDX — what KAPE writes
    (b"conectix", "vhd"),           # older VHD (dynamic; fixed has the cookie in the footer)
    (b"cxsparse", "vhd"),           # VHD sparse header
    (b"EVF\x09\x0d\x0a\xff\x00", "ewf"),   # EnCase E01
    (b"LVF\x09\x0d\x0a\xff\x00", "ewf"),   # logical evidence file
    (b"KDMV", "vmdk"),              # VMware sparse
    (b"QFI\xfb", "qcow2"),
    (b"<<< Oracle VM VirtualBox Disk Image >>>", "vdi"),
    (b"<<< Sun VirtualBox Disk Image >>>", "vdi"),
)

# A fixed VHD keeps its cookie in the last 512-byte footer, so the head tells you
# nothing. Checked separately.
_VHD_FOOTER_COOKIE = b"conectix"

IMAGE_KINDS = frozenset(label for _magic, label in _IMAGE_MAGIC)

# NTFS internals that are never the artifact you came for. $MFT and $Extend are
# deliberately absent: they are real evidence, so they go through the same parser
# test as everything else and will be picked up once a parser claims them.
_NTFS_INTERNALS = frozenset({
    "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", "$Bitmap", "$Boot",
    "$BadClus", "$Secure", "$UpCase", "$Quota", "$ObjId", "$Reparse",
})

_HEADER_BYTES = 512
_COPY_CHUNK = 1024 * 1024


@dataclass
class ExtractResult:
    """What came out of an image, and what did not."""

    root: Optional[Path] = None
    extracted: int = 0
    bytes_written: int = 0
    skipped: Counter = field(default_factory=Counter)   # extension -> count
    filesystems: int = 0
    notes: list[str] = field(default_factory=list)

    def skipped_summary(self, limit: int = 6) -> str:
        """'477 .lnk, 516 .pf' — the coverage gap, most common first."""
        if not self.skipped:
            return ""
        parts = [f"{count} {ext}" for ext, count in self.skipped.most_common(limit)]
        remaining = len(self.skipped) - limit
        if remaining > 0:
            parts.append(f"+{remaining} more types")
        return ", ".join(parts)


def sniff_image(path: Path) -> str:
    """Container label ('vhdx', 'ewf', …) or '' if this is not a disk image."""
    try:
        with path.open("rb") as handle:
            head = handle.read(64)
            for magic, label in _IMAGE_MAGIC:
                if head.startswith(magic):
                    return label
            # Fixed VHD: cookie lives in the trailing footer.
            try:
                handle.seek(-512, 2)
                if handle.read(8) == _VHD_FOOTER_COOKIE:
                    return "vhd"
            except OSError:
                pass
    except OSError:
        return ""
    return ""


def _open_container(path: Path):
    """dissect container for this image, or None with a reason."""
    from dissect.target import container

    return container.open(str(path))


def _iter_filesystems(stream) -> Iterator[tuple[str, object]]:
    """Every NTFS filesystem in the image.

    Handles both layouts KAPE and friends produce: a partitioned disk, and a bare
    volume with no partition table (a "superfloppy"), which is what some
    collection tools write.
    """
    from dissect.target import volume
    from dissect.target.filesystems.ntfs import NtfsFilesystem

    candidates: list[tuple[str, object]] = []
    try:
        vs = volume.open(stream)
        for index, vol in enumerate(vs.volumes):
            candidates.append((f"volume{index}", vol))
    except Exception:
        candidates = []
    if not candidates:
        candidates = [("image", stream)]

    for label, candidate in candidates:
        try:
            candidate.seek(0)
        except Exception:
            pass
        try:
            if not NtfsFilesystem.detect(candidate):
                continue
            yield label, NtfsFilesystem(candidate)
        except Exception:
            continue


def _safe_destination(dest_root: Path, image_path: str) -> Optional[Path]:
    """Map an in-image path under ``dest_root``, refusing to escape it.

    Paths inside an image are attacker-influenced in exactly the way archive
    members are, so they get the same treatment.
    """
    parts = [p for p in image_path.replace("\\", "/").split("/") if p and p not in (".", "..")]
    if not parts:
        return None
    target = dest_root.joinpath(*parts)
    try:
        target.resolve().relative_to(dest_root.resolve())
    except (ValueError, OSError):
        return None
    return target


def extract(
    path: Path,
    dest: Path,
    wanted: Callable[[Path, bytes, str], bool],
    max_files: int = 5000,
    max_bytes: int = 16 * 1024 ** 3,
    progress: Callable[[str], None] | None = None,
) -> ExtractResult:
    """Copy the parseable files out of a disk image.

    ``wanted(pseudo_path, header, name)`` decides — the engine passes a predicate
    backed by the parser registry, so this module needs no opinion about formats.
    """
    step = progress or (lambda _m: None)
    result = ExtractResult()

    try:
        stream = _open_container(path)
    except ImportError:
        result.notes.append(
            "disk images need the dissect libraries — pip install 'inspecthor[windows]'"
        )
        return result
    except Exception as exc:
        result.notes.append(f"could not open {path.name}: {type(exc).__name__}: {exc}")
        return result

    dest.mkdir(parents=True, exist_ok=True)
    result.root = dest

    for label, fs in _iter_filesystems(stream):
        result.filesystems += 1
        step(f"reading {label} in {path.name}")
        try:
            walker = fs.walk("/")
        except Exception as exc:
            result.notes.append(f"{label}: cannot walk ({type(exc).__name__})")
            continue

        for dirpath, _dirs, files in walker:
            for name in files:
                if result.extracted >= max_files:
                    result.notes.append(
                        f"stopped at the {max_files}-file cap; narrow the collection"
                    )
                    return result
                if name in _NTFS_INTERNALS:
                    continue

                image_path = f"{dirpath.rstrip('/')}/{name}"
                try:
                    entry = fs.get(image_path)
                    with entry.open() as handle:
                        header = handle.read(_HEADER_BYTES)
                except Exception:
                    # A file the image cannot produce is not worth failing over.
                    result.skipped["(unreadable)"] += 1
                    continue

                if not wanted(Path(image_path), header, name):
                    result.skipped[_ext_of(name)] += 1
                    continue

                target = _safe_destination(dest, image_path)
                if target is None:
                    result.skipped["(unsafe path)"] += 1
                    continue

                try:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    written = _copy_out(fs, image_path, target, header,
                                        max_bytes - result.bytes_written)
                except Exception as exc:
                    result.skipped["(copy failed)"] += 1
                    result.notes.append(
                        f"{image_path}: {type(exc).__name__}"
                    ) if len(result.notes) < 5 else None
                    continue

                result.extracted += 1
                result.bytes_written += written
                if result.bytes_written >= max_bytes:
                    result.notes.append(
                        f"stopped at the {max_bytes // 1024 ** 3} GiB extraction cap"
                    )
                    return result

    if result.filesystems == 0:
        result.notes.append(
            f"{path.name} opened as a {sniff_image(path) or 'disk'} image but held no "
            "NTFS filesystem this tool could read"
        )
    return result


def _ext_of(name: str) -> str:
    return ("." + name.rsplit(".", 1)[1].lower()) if "." in name else "(no extension)"


def _copy_out(fs, image_path: str, target: Path, header: bytes, budget: int) -> int:
    """Stream one file out of the image. Returns bytes written."""
    written = 0
    with fs.get(image_path).open() as source, target.open("wb") as sink:
        # The header was already consumed for sniffing; re-read from the start.
        source.seek(0)
        while True:
            if budget <= 0:
                break
            chunk = source.read(min(_COPY_CHUNK, budget))
            if not chunk:
                break
            sink.write(chunk)
            written += len(chunk)
            budget -= len(chunk)
    return written
