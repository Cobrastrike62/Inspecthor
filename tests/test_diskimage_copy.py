"""Tests for copying files out of a disk image.

These cover one bug, because it was the expensive kind: silent. dissect's run-list
stream returns a short read at an extent boundary and an empty read straight after
it, and ``_copy_out`` used to take that empty read for end-of-file. On a KAPE
collection that truncated a 143,130,624-byte ``C/$MFT`` at 130,023,424 and threw
away 2,981 real FILE records. Nothing failed, nothing was logged, and the parser
downstream reported a clean run over a table with a piece missing.

The tell was that the result moved with the chunk size — 139,837,440 bytes read in
4 MiB chunks against 142,983,168 in 1 MiB chunks, from the same image — because the
stall lands mid-chunk. A truncation that is not even reproducible is one nobody
finds by looking at the output, so the fix is pinned here instead.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from inspecthor.diskimage import _copy_out


class StallingStream:
    """A stream that stops dead at an extent boundary until it is seeked.

    Modelled on the dissect behaviour: the read that crosses ``boundary`` comes
    back short, every read after it comes back empty, and a ``seek`` clears it.
    """

    def __init__(self, data: bytes, boundary: int):
        self._data = data
        self._boundary = boundary
        self._pos = 0
        self._stalled = False
        self.seeks = 0

    def read(self, n: int = -1) -> bytes:
        if self._pos >= len(self._data):
            return b""
        if self._stalled:
            return b""
        end = len(self._data) if n < 0 else self._pos + n
        if self._pos < self._boundary < end:
            end = self._boundary
            self._stalled = True            # the next read returns nothing
        chunk = self._data[self._pos:end]
        self._pos = end
        return chunk

    def seek(self, pos: int, whence: int = 0) -> int:
        self.seeks += 1
        self._pos = pos
        self._stalled = False
        return pos

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class ShortStream(StallingStream):
    """A stream that genuinely runs out early — the image really cannot produce
    the rest. Must be reported, not silently recovered."""

    def read(self, n: int = -1) -> bytes:
        if self._pos >= self._boundary:
            return b""
        end = min(self._boundary, self._pos + (len(self._data) if n < 0 else n))
        chunk = self._data[self._pos:end]
        self._pos = end
        return chunk


def _fs(stream, size: int):
    entry = SimpleNamespace(
        open=lambda: stream,
        stat=lambda: SimpleNamespace(st_size=size),
    )
    return SimpleNamespace(get=lambda _path: entry)


PAYLOAD = bytes(range(256)) * 8192          # 2 MiB, and every byte checkable


def test_a_stalled_extent_does_not_truncate_the_copy(tmp_path: Path):
    """The whole point. Before the fix this wrote 1,500,000 of 2,097,152 bytes."""
    stream = StallingStream(PAYLOAD, boundary=1_500_000)
    target = tmp_path / "$MFT"
    written, expected = _copy_out(_fs(stream, len(PAYLOAD)), "/C/$MFT", target,
                                  b"", budget=1 << 30)
    assert expected == len(PAYLOAD)
    assert written == len(PAYLOAD)
    assert target.read_bytes() == PAYLOAD


def test_the_recovery_seeks_rather_than_spinning(tmp_path: Path):
    """One stall, one extra seek. A retry loop that never moves the position would
    hit the stall cap and truncate just as badly, only slower."""
    stream = StallingStream(PAYLOAD, boundary=1_500_000)
    _copy_out(_fs(stream, len(PAYLOAD)), "/C/$MFT", tmp_path / "out",
              b"", budget=1 << 30)
    assert stream.seeks <= 3                 # the initial seek(0), plus the recovery


def test_a_genuinely_short_file_is_reported_not_padded(tmp_path: Path):
    """Recovery must not paper over real loss: the caller compares the two numbers
    and says so. Padding to the expected size would fabricate evidence."""
    stream = ShortStream(PAYLOAD, boundary=1_000_000)
    target = tmp_path / "out"
    written, expected = _copy_out(_fs(stream, len(PAYLOAD)), "/C/$MFT", target,
                                  b"", budget=1 << 30)
    assert written == 1_000_000
    assert expected == len(PAYLOAD)
    assert written < expected
    assert target.stat().st_size == 1_000_000


def test_an_unknown_size_still_copies(tmp_path: Path):
    """Not every container can stat. Without a size to aim for, an empty read is
    all there is to go on and the old behaviour is the right one."""
    entry = SimpleNamespace(
        open=lambda: StallingStream(PAYLOAD, boundary=len(PAYLOAD) + 1),
        stat=lambda: (_ for _ in ()).throw(OSError("no stat")),
    )
    fs = SimpleNamespace(get=lambda _p: entry)
    written, expected = _copy_out(fs, "/C/$MFT", tmp_path / "out", b"",
                                  budget=1 << 30)
    assert expected == -1
    assert written == len(PAYLOAD)


def test_the_budget_is_still_honoured(tmp_path: Path):
    """The extraction cap exists so one image cannot fill a disk."""
    stream = StallingStream(PAYLOAD, boundary=1_500_000)
    written, _expected = _copy_out(_fs(stream, len(PAYLOAD)), "/C/$MFT",
                                   tmp_path / "out", b"", budget=4096)
    assert written == 4096
