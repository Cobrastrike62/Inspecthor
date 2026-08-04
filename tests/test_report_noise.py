"""The report has to stay readable on a collection that sweeps up a whole /etc.

A real UAC triage collection produced a 4,467-line markdown report containing 996
entries reading "— unsupported", nearly all of them ``/etc/alternatives`` symlinks,
``/etc/ssl/certs/*.0`` hash links, ``rc*.d`` init links and gzipped man pages. None of
those were ever parser gaps, and listing them buried the four that were: a 13 MB
bodyfile, wtmp/btmp, and the systemd journals.

Two separate sections were each listing everything — the Artifacts table and Not
parsed — so fixing one halved nothing.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from inspecthor.reporter import _is_not_evidence, markdown_report
from inspecthor.store.store import CaseStore

# Verbatim shapes from the real collection.
SWEEPINGS = [
    "/ev/uac/[root]/etc/alternatives/arptables",
    "/ev/uac/[root]/etc/alternatives/vi.ru.1.gz",
    "/ev/uac/[root]/etc/ssl/certs/653b494a.0",
    "/ev/uac/[root]/etc/rc2.d/S01cron",
    "/ev/uac/[root]/etc/rcS.d/S01kmod",
    "/ev/uac/[root]/etc/apparmor.d/local/usr.bin.man",
    "/ev/uac/[root]/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg",
    "/ev/uac/[root]/usr/lib/systemd/system/mongod.service",
    "/ev/uac/[root]/etc/console-setup/Uni2-Fixed16.psf.gz",
]

REAL_GAPS = [
    ("/ev/uac/bodyfile/bodyfile.txt", 12_857_621),
    ("/ev/uac/[root]/var/log/journal/abc/system.journal", 8_388_608),
    ("/ev/uac/[root]/var/log/wtmp", 42_000),
    ("/ev/uac/[root]/var/log/btmp", 1_920),
]


@pytest.mark.parametrize("path", SWEEPINGS)
def test_collector_sweepings_are_recognized(path):
    assert _is_not_evidence(path), path


@pytest.mark.parametrize("path,_size", REAL_GAPS)
def test_real_gaps_are_not_dismissed_as_sweepings(path, _size):
    """The whole point: a 13 MB bodyfile must not be filed with the man pages."""
    assert not _is_not_evidence(path), path


def _case(tmp_path: Path) -> CaseStore:
    store = CaseStore(str(tmp_path / "case.db"), case_name="uac")
    # 540 sweepings, the order of magnitude a real UAC run produces. Uniqueness comes
    # from an intermediate directory, not a suffix: appending '.{index}' to the
    # filename would turn 'mongod.service' into 'mongod.service.7' and defeat every
    # extension rule, which is a property of the fixture rather than of the code.
    for index, path in enumerate(SWEEPINGS * 60):
        head, _, tail = path.rpartition("/")
        artifact_id = store.add_artifact(
            path=f"{head}/n{index}/{tail}", sha256=f"{index:064x}", kind="text",
            size=2048,
        )
        store.set_artifact_status(artifact_id, "unsupported")
    for path, size in REAL_GAPS:
        artifact_id = store.add_artifact(path=path, kind="data", size=size)
        store.set_artifact_status(artifact_id, "unsupported")
    artifact_id = store.add_artifact(
        path="/ev/uac/[root]/var/log/auth.log", kind="syslog", size=32_000,
    )
    store.set_artifact_status(artifact_id, "parsed", parser="linux_syslog",
                              event_count=52)
    store.finalize()
    return store


def test_report_does_not_list_every_swept_up_config_file(tmp_path: Path):
    store = _case(tmp_path)
    try:
        text = markdown_report(store)
    finally:
        store.close()

    lines = text.splitlines()
    assert len(lines) < 400, f"report is {len(lines)} lines"
    # The individual sweepings must not appear at all.
    assert text.count("/etc/alternatives/") <= 1, "sweepings are being listed"
    assert "arptables" not in text


def test_report_names_the_gaps_that_matter_with_their_size(tmp_path: Path):
    """A 13 MB unparsed file is worth a parser, and that judgement needs the size in
    front of the reader."""
    store = _case(tmp_path)
    try:
        text = markdown_report(store)
    finally:
        store.close()

    assert "bodyfile.txt" in text
    assert "12.9 MB" in text or "12.8 MB" in text, text[-2000:]
    assert "system.journal" in text
    assert "540 collector sweepings" in text


def test_artifacts_table_does_not_relist_the_unparsed(tmp_path: Path):
    """Two sections were each listing everything, so fixing one halved nothing."""
    store = _case(tmp_path)
    try:
        text = markdown_report(store)
    finally:
        store.close()

    artifacts = text.split("## Artifacts", 1)[1].split("### Not parsed", 1)[0]
    assert "unsupported" not in artifacts, artifacts[:600]
    assert "auth.log" in artifacts, "parsed artifacts must still be listed"
    # 540 sweepings + the 4 real gaps.
    assert "544 with no parser" in artifacts, artifacts[:300]
