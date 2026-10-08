"""Path-based severity, in one place.

Four parsers arrived at the same question independently — EZTools CSVs, Plaso
timelines, Velociraptor results and the NTFS pair all end up holding a path and
needing to say how interesting it is. They had four copies of the same two
constants, and they had already drifted: a double-extension lure was ``high`` from
``$MFT`` and ``info`` from Velociraptor, for the same file on the same host. An
analyst cannot reason about a severity that depends on which tool happened to
collect the artifact.

CONSTRAINT: this stays conservative, and the reason is measured. On a real
139,533-segment ``$MFT`` the first version of these rules promoted 248,164 of
323,548 events. Everything here fires on *location and shape*, never on "an
executable exists" — a ShimCache or a super-timeline is a whole-system inventory,
and any rule that matches ordinary software promotes tens of thousands of rows and
empties triage of meaning.

Format-specific signals stay in their own parsers: ``$SI``/``$FN`` disagreement
belongs to ``mft.py`` because only an MFT has both, and USN reason flags belong to
``usnjrnl.py``. This module is only the part that is genuinely about the path.
"""
from __future__ import annotations

# Directories that exist to hold transient files. An executable here is worth
# interrupting an analyst for; \ProgramData\ and \AppData\Roaming\ are not on the
# list because stock software lives in them in bulk.
TEMP_STAGING: tuple[str, ...] = (
    "\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\",
    "\\$recycle.bin\\", "\\perflogs\\", "\\windows\\tasks\\",
    "/tmp/", "/var/tmp/", "/dev/shm/", "/var/spool/",
)

# Anything that runs.
EXEC_EXT = frozenset({
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".psm1", ".dll", ".sys", ".msi",
    ".msp", ".jar", ".cpl", ".ocx", ".lnk",
})

# What a lure actually ends in. Narrower than EXEC_EXT on purpose: .dll, .sys and
# .msi are absent because dotted naming is the .NET convention, and including them
# reported stock Microsoft components -- Windows.Data.Pdf.dll reads as ".pdf" plus
# ".dll" and produced six 'high' findings in \Windows\WinSxS on a real collection.
LURE_EXT = frozenset({
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".ps1",
})

# Extensions that look like a document to a user but sit in front of the real one.
DECOY_EXT = frozenset({
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg",
    ".jpeg", ".png", ".gif", ".rtf", ".csv", ".zip", ".htm", ".html",
})


def normalize(path: str) -> str:
    """Lowercased, backslash-separated. Plaso writes forward slashes on Windows
    paths and Velociraptor writes either, so comparing on one separator is the
    only way the same file scores the same from every source."""
    return (path or "").lower().replace("/", "\\")


def extension_of(path: str) -> str:
    name = normalize(path).rsplit("\\", 1)[-1]
    return name[name.rindex("."):] if "." in name else ""


def in_temp(path: str) -> bool:
    return any(marker.replace("/", "\\") in normalize(path)
               for marker in TEMP_STAGING)


def double_extension(path: str) -> str:
    """``invoice.pdf.exe`` -> ``.pdf.exe``, or '' when it is not a lure."""
    name = normalize(path).rsplit("\\", 1)[-1]
    parts = name.split(".")
    if len(parts) < 3:
        return ""
    real, decoy = f".{parts[-1]}", f".{parts[-2]}"
    if real in LURE_EXT and decoy in DECOY_EXT:
        return f"{decoy}{real}"
    return ""


def score_path(path: str) -> tuple[str, list[str], str]:
    """``(severity, tags, why)`` for a path, from location and shape alone."""
    if not path:
        return "info", [], ""
    extension = extension_of(path)
    executable = extension in EXEC_EXT
    temp = in_temp(path)

    lure = double_extension(path)
    if lure:
        return "high", ["double_extension", "suspicious"], f"double extension: {lure}"

    if executable and temp:
        return "high", ["unusual_exec_path", "suspicious"], (
            "executable in a temporary directory"
        )
    if temp:
        return "low", ["staging_dir"], "in a temporary directory"
    if executable:
        return "low", ["executable"], ""
    return "info", [], ""
