"""Tests for the shared path scorer.

This module exists because four parsers had four copies of the same two constants
and had already drifted: a double-extension lure scored ``high`` from the ``$MFT``
and ``info`` from Velociraptor, for the same file on the same host. The
consistency tests at the bottom are the point of the whole file — they assert the
property that the duplication broke, not just that each rule works.

The suppressions are measured, not guessed. On a real 139,533-segment ``$MFT``
the first version of these rules promoted 248,164 of 323,548 events, and every
"not promoted" test below corresponds to a block of that noise.
"""
from __future__ import annotations

import pytest

from inspecthor.parsers._pathscore import (
    DECOY_EXT, EXEC_EXT, LURE_EXT, double_extension, extension_of, in_temp,
    normalize, score_path,
)
from inspecthor.parsers.plugins.eztools import SPECS
from inspecthor.parsers.plugins.eztools import score_row as eztools_score
from inspecthor.parsers.plugins.plaso import score_entry as plaso_score
from inspecthor.parsers.plugins.velociraptor import score_row as velo_score


# ---- separators --------------------------------------------------------------


def test_forward_and_back_slashes_normalize_the_same():
    """Plaso writes Windows paths with forward slashes; Velociraptor writes
    either. The same file has to score the same from every source."""
    win = "C:\\Users\\b\\AppData\\Local\\Temp\\x.exe"
    nix = "C:/Users/b/AppData/Local/Temp/x.exe"
    assert normalize(win) == normalize(nix)
    assert in_temp(win) and in_temp(nix)
    assert score_path(win) == score_path(nix)


def test_the_extension_comes_from_the_last_segment():
    """A dot in a directory name is not the file's extension."""
    assert extension_of("C:\\a.b.c\\run") == ""
    assert extension_of("C:\\a.b.c\\run.exe") == ".exe"
    assert extension_of("plain") == ""


# ---- what is promoted ---------------------------------------------------------


def test_an_executable_in_a_temp_directory_is_high():
    severity, tags, _why = score_path("C:\\Users\\b\\AppData\\Local\\Temp\\u.exe")
    assert severity == "high"
    assert "unusual_exec_path" in tags


def test_a_unix_temp_executable_is_high():
    severity, _tags, _why = score_path("/tmp/payload.sh.exe")
    assert severity == "high"


def test_a_lure_is_high_wherever_it_sits():
    """The point of a double extension is that the directory looks innocent."""
    severity, tags, why = score_path("C:\\Users\\b\\Downloads\\invoice.pdf.exe")
    assert severity == "high"
    assert "double_extension" in tags
    assert ".pdf.exe" in why


# ---- what is not --------------------------------------------------------------


def test_an_ordinary_system_binary_is_not_promoted():
    """A ShimCache is every binary the OS ever saw."""
    severity, tags, _why = score_path("C:\\Windows\\System32\\svchost.exe")
    assert severity == "low"
    assert "suspicious" not in tags


def test_a_document_is_not_promoted():
    assert score_path("C:\\Users\\b\\Documents\\report.docx")[0] == "info"


def test_a_dotted_dotnet_assembly_is_not_a_lure():
    """Windows.Data.Pdf.dll reads as '.pdf' + '.dll' and produced six 'high'
    findings in \\Windows\\WinSxS before .dll left the lure set."""
    assert double_extension("C:\\Windows\\WinSxS\\Windows.Data.Pdf.dll") == ""
    assert score_path("C:\\Windows\\WinSxS\\Windows.Data.Pdf.dll")[0] == "low"


def test_dll_and_sys_are_runnable_but_never_lures():
    for ext in (".dll", ".sys", ".msi"):
        assert ext in EXEC_EXT
        assert ext not in LURE_EXT


def test_a_single_extension_is_not_a_double_extension():
    assert double_extension("C:\\x\\a.exe") == ""
    assert double_extension("C:\\x\\a") == ""


def test_an_archive_decoy_still_counts():
    assert double_extension("C:\\x\\photos.zip.scr") == ".zip.scr"


def test_an_empty_path_is_not_a_finding():
    assert score_path("") == ("info", [], "")


# ---- the property the duplication broke ---------------------------------------

LURE = "C:\\Users\\susan\\Downloads\\invoice.pdf.exe"
TEMP_EXE = "C:\\Users\\susan\\AppData\\Local\\Temp\\beacon.exe"
BORING = "C:\\Windows\\System32\\kernel32.dll"

_RBCMD = next(spec for spec in SPECS if spec.name == "rbcmd")
_SHIM = next(spec for spec in SPECS if spec.name == "appcompatcache")


@pytest.mark.parametrize("path,expected", [
    (LURE, "high"), (TEMP_EXE, "high"), (BORING, "low"),
])
def test_every_parser_agrees_on_the_same_path(path, expected):
    """The bug this module was written for: the same file scored differently
    depending on which tool happened to collect it."""
    assert score_path(path)[0] == expected
    assert plaso_score(path, "")[0] == expected
    assert velo_score(path)[0] == expected
    assert eztools_score(_SHIM, path, {})[0] == expected


def test_the_recycle_bin_keeps_its_own_signal():
    """Deletion is the one thing no path can tell you, so it stays in the
    EZTools parser rather than being flattened into the shared scorer."""
    severity, tags, why = eztools_score(_RBCMD, "C:\\Users\\b\\Desktop\\tool.exe", {})
    assert severity == "med"
    assert "deleted" in tags
    assert "recycle bin" in why


def test_the_recycle_bin_does_not_downgrade_a_real_finding():
    """A lure in the recycle bin is still a lure."""
    assert eztools_score(_RBCMD, LURE, {})[0] == "high"
