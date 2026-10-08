"""Does the repository actually contain the package?

This exists because of a bug that shipped. ``.gitignore`` carried an unanchored
``_*.py`` meant for local scratch helpers, and git applied it at every level, so
``inspecthor/parsers/plugins/_evtx_ids.py`` was never committed. ``evtx.py``
imports it at module scope, the plugin loader catches ImportError per module, and
the result was that **a fresh clone silently lost the EVTX parser** — the
highest-value one in the tool. Nothing failed. No warning. Windows Event Logs
simply went unparsed, and the only way to notice was to clone the published repo
and count the registry.

That is the same shape the project keeps writing tests against: no error, and
output that reads as "nothing here". So the guard is structural rather than one
assertion about one file.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
PACKAGE = REPO / "inspecthor"


def _git(*args: str) -> str | None:
    """Run git in the repo, or None when this is not a usable checkout."""
    try:
        done = subprocess.run(
            ("git", *args), cwd=REPO, capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


requires_git = pytest.mark.skipif(
    _git("rev-parse", "--is-inside-work-tree") is None,
    reason="not a git checkout (sdist, wheel, or git unavailable)",
)


@requires_git
def test_every_python_file_in_the_package_is_tracked():
    """An untracked module is invisible to everyone who clones."""
    tracked = {
        (REPO / line).resolve()
        for line in (_git("ls-files", "inspecthor") or "").splitlines()
        if line.strip()
    }
    on_disk = {
        path.resolve()
        for path in PACKAGE.rglob("*.py")
        if "__pycache__" not in path.parts
    }
    missing = sorted(str(p.relative_to(REPO)) for p in on_disk - tracked)
    assert not missing, (
        "these modules exist locally but are not in the repository, so a clone "
        f"would not have them: {missing}"
    )


@requires_git
def test_no_package_file_is_gitignored():
    """Catches the rule before it costs a parser.

    ``git check-ignore`` reports the ignored paths it was given, so an empty
    result is the passing case.
    """
    candidates = [
        str(p.relative_to(REPO))
        for p in PACKAGE.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    ]
    out = _git("check-ignore", *candidates)
    ignored = sorted(line for line in (out or "").splitlines() if line.strip())
    assert not ignored, (
        f"these package files match a .gitignore rule: {ignored}"
    )


def test_the_parsers_a_clone_needs_are_all_importable():
    """The symptom the packaging bug produced, asserted directly.

    If a module goes missing again, the loader swallows the ImportError and the
    parser silently disappears from the registry rather than failing. Naming the
    ones that must exist turns that back into a test failure.
    """
    from inspecthor.parsers._loader import all_parsers

    registered = {parser.name for parser in all_parsers()}
    expected = {
        "evtx",            # the one that actually went missing
        "registry", "mft", "usnjrnl", "bodyfile", "generic_text",
        "eztools", "plaso", "velociraptor", "detections",
        "linux_syslog", "linux_config", "shell_history", "mongodb",
    }
    assert expected <= registered, f"missing from the registry: {sorted(expected - registered)}"


def test_the_evtx_template_table_is_present_and_populated():
    """evtx.py imports this at module scope; an empty one would load fine and
    strip every event of its meaning."""
    from inspecthor.parsers.plugins._evtx_ids import EVENT_TEMPLATES

    assert isinstance(EVENT_TEMPLATES, dict)
    assert len(EVENT_TEMPLATES) > 50, "the template table looks truncated"
