"""Bounded text reading with transparent decompression.

Not a Parser (no ``@register``) — just a helper shared by the text-oriented
plugins. Rotated logs arrive as ``auth.log.2.gz`` far more often than not, so
decompression belongs here rather than in every parser.
"""
from __future__ import annotations

import bz2
import gzip
import lzma
from pathlib import Path
from typing import IO, Iterator

# Compression is detected by magic, never by extension — a ``.log`` that is
# actually gzip is common in collected evidence.
_COMPRESSION = (
    (b"\x1f\x8b", gzip.open),
    (b"BZh", bz2.open),
    (b"\xfd7zXZ\x00", lzma.open),
)


def opener_for(path: Path) -> tuple[callable, str]:
    """Return ``(open_callable, label)`` appropriate for this file's real format."""
    try:
        with path.open("rb") as handle:
            header = handle.read(8)
    except OSError:
        return open, "plain"
    for magic, func in _COMPRESSION:
        if header.startswith(magic):
            return func, func.__module__
    return open, "plain"


def open_text(path: Path) -> IO[str]:
    """Open a possibly-compressed log as UTF-8 text, replacing bad bytes.

    ``errors="replace"`` rather than strict: evidence contains truncated writes
    and mixed encodings, and losing an entire log to one bad byte is worse than a
    replacement character in one message.
    """
    func, _label = opener_for(path)
    return func(path, "rt", encoding="utf-8", errors="replace")


def read_lines(path: Path, max_bytes: int = 64 * 1024 * 1024) -> Iterator[str]:
    """Yield lines, stopping once ``max_bytes`` of text has been consumed.

    The cap is on decompressed bytes, which is the number that matters: a 2 MB
    gzip can expand to gigabytes.
    """
    consumed = 0
    try:
        with open_text(path) as handle:
            for line in handle:
                consumed += len(line)
                if consumed > max_bytes:
                    return
                yield line.rstrip("\n\r")
    except (OSError, EOFError, gzip.BadGzipFile, lzma.LZMAError, ValueError):
        # A truncated or corrupt archive yields what it managed to decode.
        return
