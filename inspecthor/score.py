"""Severity scoring for execution, services, autoruns and scheduled tasks.

This module exists because of a measured miss. On a real collection with a
confirmed intrusion, every event in the attack chain came out ``info`` or ``med``:

    16:55:58  obfuscated .ps1 in AppData\\Local\\h2cgEzNCsypd\\        med
    16:56:17  node.exe from that directory, parent powershell.exe     info
    16:56:18  NitSSMjZ.exe, parent node.exe                           info
    16:56:25  ...root/SecurityCenter2 AntivirusProduct                med
    17:00:16  npm.cmd install ws        (WebSocket C2)                info
    17:14:33  powershell -ExecutionPolicy Bypass, parent NitSSMjZ     med

while the same day's ``high`` tier was 41 events, all of them false: 25 per-user
svchost services, the Realtek audio autorun, and Office's updater task.

Two failures, and they are the same failure twice.

**The escalation list was a LOLBin blocklist.** It matched ``mshta``, ``certutil``,
``iex`` — attacker tooling by name. This attacker shipped their own runtime, so
nothing matched. A name-based blocklist only catches adversaries who use the names
already in it, which is the ones you were already going to catch.

**The high tier had no allow-list.** ``service_installed`` was high for every
per-user svchost instance Windows creates at logon.

So scoring here is about **where code lives and what it does**, not what it is
called. ``node.exe`` is signed by a real vendor and appears in no blocklist; the
finding is that it ran from ``AppData\\Local\\h2cgEzNCsypd\\lk9vAU\\``, spawned by
PowerShell, and immediately enumerated the installed antivirus.

Every function returns its reasons. A level with no stated reason is unauditable,
and an analyst who cannot see why a row is ``high`` learns to ignore the column.
"""
from __future__ import annotations

import re
from typing import Iterable

# ---------------------------------------------------------------------------
# where code lives
# ---------------------------------------------------------------------------

# Plain strings, not raw: every path here needs ONE trailing backslash, and in a raw
# string "\\" is two characters, so the raw spelling silently matched nothing.
#
# User-writable by design. Legitimate software does run from here — Teams, Chrome's
# updater, Squirrel installers — so this raises suspicion rather than settling it.
_USER_WRITABLE = (
    "\\appdata\\", "\\local\\temp\\", "\\windows\\temp\\",
    "\\programdata\\", "\\users\\public\\", "\\$recycle.bin", "\\perflogs\\",
)

# Trusted install roots. Not proof of anything — a DLL sideload lives here too —
# but enough to stop Program Files binaries dominating the high tier.
_TRUSTED_ROOTS = (
    "c:\\program files\\", "c:\\program files (x86)\\", "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\", "c:\\windows\\servicing\\", "c:\\windows\\winsxs\\",
    "c:\\windows\\explorer.exe", "c:\\windows\\immersivecontrolpanel\\",
    "c:\\windows\\microsoft.net\\", "c:\\windows\\system32\\",
)

# Software that legitimately installs and runs under a user profile. Anchored on the
# vendor directory, not the executable name, so dropping evil.exe into
# AppData\Local\Microsoft\Teams does not inherit the exemption.
_KNOWN_USER_APPS = (
    # Defender lives in ProgramData and updates its own versioned platform
    # directory, so its CLI looked like a payload dropped into a writable path.
    "\\programdata\\microsoft\\windows defender\\",
    "\\programdata\\microsoft\\windows\\",
    "\\programdata\\package cache\\",
    # Windows Installer and InstallShield extract to a GUID directory under
    # Windows\Temp. A year of one workstation's installer history was ~300 of the
    # false positives this scorer produced on its first real run.
    "\\windows\\temp\\{",
    "\\appdata\\local\\microsoft\\teams\\", "\\appdata\\local\\microsoft\\onedrive\\",
    "\\appdata\\local\\google\\chrome\\", "\\appdata\\local\\google\\update\\",
    "\\appdata\\local\\slack\\", "\\appdata\\local\\discord\\",
    "\\appdata\\local\\programs\\microsoft vs code\\",
    "\\appdata\\local\\microsoft\\edgeupdate\\", "\\appdata\\local\\zoom\\",
    "\\appdata\\local\\clickshare\\", "\\appdata\\roaming\\zoom\\",
    "\\appdata\\local\\citrix\\", "\\appdata\\local\\gotomeeting\\",
    "\\appdata\\local\\microsoft\\edgewebview\\",
)


def _norm(path: str) -> str:
    return (path or "").strip().strip('"').replace("/", "\\").lower()


def in_user_writable(path: str) -> bool:
    p = _norm(path)
    return any(marker in p for marker in _USER_WRITABLE)


def in_trusted_root(path: str) -> bool:
    p = _norm(path)
    return any(p.startswith(root) or root in p for root in _TRUSTED_ROOTS)


def is_known_user_app(path: str) -> bool:
    p = _norm(path)
    return any(marker in p for marker in _KNOWN_USER_APPS)


# ---------------------------------------------------------------------------
# names that a human did not choose
# ---------------------------------------------------------------------------

_VOWELS = set("aeiouy")
# Consonant runs a pronounceable name would not contain. 'y' is excluded because it
# acts as a vowel in exactly the names this must not flag (systray, sync).
_CONSONANT_RUN = re.compile(r"[bcdfghjklmnpqrstvwxz]{4,}", re.I)
# A digit with letters on both sides. Real software versions its tail — WINWORD,
# msedgewebview2, RtkAudUService64, python3 — so a digit in the middle is a much
# stronger signal than merely containing one.
_DIGIT_INFIX = re.compile(r"[A-Za-z][0-9]+[A-Za-z]")

# Words that show up in names a human chose. This is the discriminator that matters:
# RtkAudUService64 and NitSSMjZ score identically on every statistical measure worth
# computing on 8 characters, and the only real difference is that one contains
# 'Service'. Cheaper, more accurate, and easier to audit than an entropy threshold.
_NAME_WORDS = frozenset("""
agent app assist audio auth back boot broker cache cast client cloud cmd com config
connect console core crash create data defend deploy desk detect device diag disk
display driver edge engine enroll event experience explorer export firewall font
frame graphic group health helper host hyper icon image index input install intel
java job kernel launch layout lib license load local locate log login mail maint
manage media memory menu message micro mode monitor mount move net network node
note notify office onedrive open package pair panel pdf perf photo pick play plugin
policy power present print process product profile provider proxy push query queue
reader ready realtek recovery reg registry remote render repair report resolve
restore run runtime sample scan schedule search secure security sense sentinel
server service session setting setup share shell signal snap sound speech spell
spool start state status store stream support sync sys system systray task team
telemetry text theme thread time tool trace tray trust update updater upgrade user
util vault video view virtual voice watch web widget window word work worker write
zoom program files folder common apps appup soft software credential enroll
enrollment platform defender roaming public driver drivers repository feature
current native shared package version amd64 nvidia google chrome microsoft adobe
cisco razer mimecast onedrive winsxs servicing wbem assembly framework runtimes
""".split())

# Short tokens worth matching even though a 3-character substring is a blunter
# instrument. Each one earned its place by causing a false positive on real
# evidence: 'sys' + 'wow' for SysWOW64, 'cmd' + 'run' for Defender's MpCmdRun.exe.
_SHORT_WORDS = frozenset("""
sys wow cmd run net log svc app exe dll msi x64 x86 reg api usb gpu ini tmp bin
lib com job pnp wmi rpc dns win pro dev srv aud mgr
""".split())


def _contains_a_real_word(stem: str) -> bool:
    lowered = stem.lower()
    if any(word in lowered for word in _NAME_WORDS if len(word) >= 4):
        return True
    return any(word in lowered for word in _SHORT_WORDS)


def looks_machine_generated(name: str) -> bool:
    """True for names like h2cgEzNCsypd, lk9vAU, NitSSMjZ, nXYPsIui5G, AjsSJkUI.

    Deliberately conservative: this promotes events, so a false positive costs an
    analyst's attention. A name containing any recognizable software word is treated
    as human-chosen outright, and the statistical signals only decide the rest.
    """
    stem = re.sub(r"\.[a-z0-9]{1,4}$", "", (name or "").strip())
    if len(stem) < 6 or len(stem) > 40:
        return False
    if not stem.isascii() or not re.fullmatch(r"[A-Za-z0-9_.-]+", stem):
        return False
    # A GUID is machine-generated but ubiquitous and almost always benign.
    if re.fullmatch(r"[{(]?[0-9a-f-]{8,}[)}]?", stem, re.I):
        return False
    if _contains_a_real_word(stem):
        return False

    # Five letters, not four. InstallShield extracts to
    # C:\Windows\Temp\{GUID}\_isF830.exe and those stems have exactly four, which
    # produced ~300 false 'high' rows on one workstation's installer history. Every
    # real generated name measured has five or more (lk9vAU is the shortest).
    letters = [c for c in stem if c.isalpha()]
    if len(letters) < 5:
        return False

    signals = 0
    if sum(1 for c in letters if c.lower() in _VOWELS) / len(letters) < 0.34:
        signals += 1
    if _CONSONANT_RUN.search(stem):
        signals += 1
    if _DIGIT_INFIX.search(stem):
        signals += 1
    has_upper = any(c.isupper() for c in stem)
    has_lower = any(c.islower() for c in stem)
    if has_upper and has_lower and any(c.isdigit() for c in stem):
        signals += 1
    # Case flipping mid-word: NitSSMjZ, nXYPsIui5G, AjsSJkUI.
    if has_upper and has_lower and len(re.findall(r"[a-z][A-Z]|[A-Z][a-z]", stem)) >= 3:
        signals += 1
    return signals >= 2


def random_segments(path: str) -> list[str]:
    """Path components that look machine-generated, directories included.

    The directory matters as much as the file: ``node.exe`` is unremarkable until
    you notice its parent directory is ``h2cgEzNCsypd\\lk9vAU``.
    """
    # Original casing, not _norm: case flipping is one of the signals and lowering
    # the string destroys it.
    original = (path or "").strip().strip('"').replace("/", "\\").split("\\")
    return [p for p in original if p and ":" not in p and looks_machine_generated(p)]


# ---------------------------------------------------------------------------
# what the command is doing
# ---------------------------------------------------------------------------

# Host reconnaissance. Individually mundane and run by legitimate software; the
# signal is a burst of them from one parent, which correlate() handles. Each alone
# is worth 'low' context, not an alert.
RECON_PATTERNS: tuple[tuple[re.Pattern, str, str], ...] = (
    (re.compile(r"securitycenter2|antivirusproduct", re.I), "T1518.001", "AV enumeration"),
    (re.compile(r"\bmachineguid\b", re.I), "T1082", "host fingerprint"),
    (re.compile(r"\bnet\d?\b\s+session\b", re.I), "T1049", "session enumeration"),
    (re.compile(r"win32_videocontroller|win32_computersystemproduct",
                re.I), "T1497.001", "VM/sandbox check"),
    (re.compile(r"\bpartofdomain\b|win32_computersystem\)\.domain", re.I), "T1482",
     "domain membership"),
    (re.compile(r"\bwhoami\b|\bnltest\b|\bnet\d?\b\s+group\b", re.I), "T1087",
     "account enumeration"),
    (re.compile(r"\bipconfig\b|\barp\b\s+-a|\broute\b\s+print", re.I), "T1016",
     "network config"),
    (re.compile(r"installeduiculture|getsystemdefault", re.I), "T1614", "locale check"),
)

# A package manager pulling a network transport is how a scripted implant builds its
# C2 without shipping one. 'ws' is the WebSocket client used in the measured case.
_PKG_NETWORK_INSTALL = re.compile(
    r"\b(?:npm|npx|pnpm|yarn)(?:\.cmd|\.exe)?\b[^\n]{0,120}?\b(?:install|add|i)\b"
    r"[^\n]{0,120}?\b(?:ws|websocket|socket\.io|node-fetch|axios|got|request|"
    r"puppeteer|playwright|socks|http-proxy|tunnel|ngrok)\b", re.I,
)

# Interpreters and script hosts. Not suspicious in themselves — suspicious as the
# parent of something in a user-writable path, or as the child of one.
SCRIPT_HOSTS = (
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "node.exe", "python.exe", "python3.exe", "ruby.exe", "perl.exe",
    "java.exe", "javaw.exe", "deno.exe", "bun.exe", "php.exe",
)


def basename(path: str) -> str:
    return _norm(path).rsplit("\\", 1)[-1]


# ---------------------------------------------------------------------------
# process creation
# ---------------------------------------------------------------------------

def score_process(image: str, cmdline: str = "", parent: str = "",
                  base: str = "info") -> tuple[str, list[str], list[str], list[str]]:
    """Score a process creation. Returns (level, tags, attck, reasons).

    ``base`` is the level the curated map already assigned, and is never lowered —
    this only promotes.
    """
    reasons: list[str] = []
    tags: list[str] = []
    attck: list[str] = []
    level = base

    def raise_to(candidate: str, why: str, tag: str = "", technique: str = "") -> None:
        nonlocal level
        reasons.append(why)
        if tag and tag not in tags:
            tags.append(tag)
        if technique and technique not in attck:
            attck.append(technique)
        if _RANK.get(candidate, 0) > _RANK.get(level, 0):
            level = candidate

    img_writable = in_user_writable(image) and not is_known_user_app(image)
    parent_writable = in_user_writable(parent) and not is_known_user_app(parent)
    # Kept apart, not or'd together. Reporting a segment of the *parent* path as the
    # reason the *image* is suspicious sent an analyst looking for 'SysWOW64' in a
    # path that never contained it.
    img_randoms = random_segments(image)
    parent_randoms = random_segments(parent)

    # The core signal, and the one that would have caught the measured case: code
    # running from a directory any user can write, under a name nobody chose.
    if img_writable and img_randoms:
        raise_to("high", f"runs from a user-writable path under a machine-generated "
                         f"name ({', '.join(img_randoms[:2])})",
                 "unusual_exec_path", "T1036")
    elif img_writable:
        raise_to("med", "runs from a user-writable path", "unusual_exec_path")
    elif img_randoms:
        raise_to("med", f"machine-generated name in image path ({img_randoms[0]})",
                 "random_name")
    elif parent_randoms:
        raise_to("med", f"machine-generated name in parent path ({parent_randoms[0]})",
                 "random_name")

    # A script host launching something out of a user-writable path is the shape of
    # a dropper handing off to its payload.
    if parent_writable and not img_writable:
        raise_to("med", f"parent runs from a user-writable path ({basename(parent)})",
                 "unusual_parent")
    if basename(parent) in SCRIPT_HOSTS and img_writable:
        raise_to("high", f"{basename(parent)} launched a binary from a user-writable path",
                 "script_host_dropper", "T1059")

    if _PKG_NETWORK_INSTALL.search(cmdline or ""):
        raise_to("high", "package manager installing a network transport "
                         "(implant building its own C2)", "pkg_network_install", "T1105")

    haystack = " ".join(filter(None, (cmdline, image)))
    for pattern, technique, label in RECON_PATTERNS:
        if pattern.search(haystack):
            # Recon alone stays low: legitimate inventory software does all of this.
            # Its value is as corroboration once something else is already suspect.
            raise_to("low", f"host recon: {label}", "recon", technique)

    return level, tags, attck, reasons


_RANK = {"info": 0, "low": 1, "med": 2, "high": 3, "crit": 4}


# ---------------------------------------------------------------------------
# services
# ---------------------------------------------------------------------------

# Windows creates one of these per user session at logon: the name is a template
# plus the session's hex id, and the image is always a shared svchost. 25 of the 41
# false 'high' events in the measured case were exactly this.
_PER_USER_SVC = re.compile(r"^(?P<stem>[A-Za-z0-9]+)_[0-9a-f]{4,8}$")
# Just 'svchost.exe -k <group>', wherever it is spelled from. The earlier version
# anchored the whole path and so failed on the %SystemRoot%\system32\... form,
# leaving the very events it existed to demote sitting at 'high'.
_SVCHOST_K = re.compile(r"svchost\.exe\"?\s+-k\s+\S+", re.I)

# Vendors whose service installs are routine on a managed fleet. Matched against the
# image path's install directory, so the name alone cannot claim the exemption.
_ROUTINE_SVC_VENDORS = (
    "\\program files\\windowsapps\\", "\\program files\\google\\",
    "\\program files (x86)\\google\\", "\\program files\\microsoft\\",
    "\\program files (x86)\\microsoft\\", "\\program files\\dell\\",
    "\\program files (x86)\\dell\\", "\\program files\\sentinelone\\",
    "\\program files\\mimecast\\", "\\program files\\cisco\\",
    "\\program files (x86)\\cisco\\", "\\program files\\intel\\",
    "\\program files\\realtek\\", "\\program files\\nvidia corporation\\",
    "\\program files\\common files\\microsoft shared\\",
    "\\windows\\system32\\drivers\\", "\\windows\\microsoft.net\\",
    "\\windows\\system32\\driverstore\\",
)


def score_service(name: str, image: str,
                  base: str = "high") -> tuple[str, list[str], list[str]]:
    """Score a service installation. Returns (level, tags, reasons).

    Unlike ``score_process`` this may LOWER the level. A service install is
    genuinely high-signal, so the curated map is right to start it there — but the
    OS installs dozens of its own, and leaving those at high is what made the tier
    worthless.
    """
    reasons: list[str] = []
    tags: list[str] = []
    img = _norm(image)

    per_user = _PER_USER_SVC.match((name or "").strip())
    if per_user and _SVCHOST_K.search(img):
        return "info", ["os_churn"], [
            "per-user svchost instance Windows creates at every logon "
            f"({per_user.group('stem')}_*)"
        ]

    if in_user_writable(image) and not is_known_user_app(image):
        pass  # fall through to the user-writable branch below, which outranks this
    elif per_user and in_trusted_root(image):
        # Same per-session convention, different binary:
        # CredentialEnrollmentManagerUserSvc_26b8fd runs system32's own exe, not a
        # shared svchost, so the svchost test above never saw it.
        return "low", ["os_churn"], [
            "per-session service instance from a system directory "
            f"({per_user.group('stem')}_*)"
        ]

    if in_user_writable(image) and not is_known_user_app(image):
        reasons.append("service image is in a user-writable path")
        tags.append("unusual_exec_path")
        return "crit", tags, reasons

    randoms = random_segments(image)
    if randoms:
        reasons.append(f"machine-generated name in service image ({randoms[0]})")
        tags.append("random_name")
        return "crit", tags, reasons

    if any(vendor in img for vendor in _ROUTINE_SVC_VENDORS):
        return "low", ["routine_vendor"], [
            "service image is under a routine vendor install directory"
        ]

    if img and not in_trusted_root(image):
        reasons.append("service image is outside the usual install roots")
        tags.append("unusual_exec_path")
        return "high", tags, reasons

    # Trusted root but no recognized vendor. A new service is one of the strongest
    # persistence signals there is, so this stays where the curated map put it — but
    # the reason has to say that, not "installed from a trusted root", which reads
    # like an explanation for why it is fine while sitting on a 'high'.
    return base, tags, reasons or ["service install from a path with no known vendor"]


# ---------------------------------------------------------------------------
# autoruns
# ---------------------------------------------------------------------------

def score_autorun(name: str, value: str,
                  base: str = "high") -> tuple[str, list[str], list[str]]:
    """Score a Run-key entry. Returns (level, tags, reasons)."""
    reasons: list[str] = []
    tags: list[str] = []
    val = _norm(value)

    if in_user_writable(value) and not is_known_user_app(value):
        randoms = random_segments(value)
        reasons.append("autorun target is in a user-writable path")
        tags.append("unusual_exec_path")
        if randoms:
            reasons.append(f"machine-generated name ({randoms[0]})")
            tags.append("random_name")
            return "crit", tags, reasons
        return "high", tags, reasons

    if in_trusted_root(value) or val.startswith("%windir%") or val.startswith("%systemroot%"):
        # A trusted path is not a free pass: an installer cleanup that shells out to
        # `cmd /c del` is normal, but the same shape with a download is not.
        return "low", ["routine_vendor"], [
            "autorun target is under a trusted install root"
        ]

    if not val:
        return "info", [], ["empty autorun value"]
    return base, tags, reasons or ["autorun target is outside the usual install roots"]


# ---------------------------------------------------------------------------
# scheduled tasks
# ---------------------------------------------------------------------------

# Microsoft's own task tree plus the updaters every managed endpoint runs. Anchored
# on the full task path so \Microsoft\Office\... is exempt while \MicrosoftEvil is
# not.
_ROUTINE_TASK_PREFIXES = (
    "\\microsoft\\windows\\", "\\microsoft\\office\\", "\\microsoft\\edge",
    "\\microsoft\\onedrive", "\\onedrive standalone update task",
    "\\onedrive per-machine standalone update task", "\\googleupdatetask",
    "\\googlesystem", "\\dell\\", "\\intel\\", "\\nvidia", "\\adobe acrobat update",
    "\\meecpolicy", "\\opera scheduled", "\\mozilla\\", "\\cisco\\",
)


def score_task(task_name: str, xml: str = "",
               base: str = "high") -> tuple[str, list[str], list[str]]:
    """Score a scheduled-task creation. Returns (level, tags, reasons)."""
    reasons: list[str] = []
    tags: list[str] = []
    name = _norm(task_name)

    # The action matters more than the name: a task under \Microsoft\Windows\ that
    # launches something out of AppData is worse than an oddly-named one that runs a
    # signed updater.
    if xml and in_user_writable(xml) and not is_known_user_app(xml):
        reasons.append("task action runs from a user-writable path")
        tags.append("unusual_exec_path")
        randoms = random_segments(xml)
        if randoms:
            reasons.append(f"machine-generated name ({randoms[0]})")
            tags.append("random_name")
            return "crit", tags, reasons
        return "high", tags, reasons

    if any(name.startswith(p) or p in name for p in _ROUTINE_TASK_PREFIXES):
        return "low", ["routine_vendor"], [
            "task is in a vendor or Microsoft task path"
        ]

    if looks_machine_generated(task_name.strip("\\").split("\\")[-1] if task_name else ""):
        reasons.append("machine-generated task name")
        tags.append("random_name")
        return "high", tags, reasons

    return base, tags, reasons or ["task created outside the known vendor paths"]


def summarize(reasons: Iterable[str]) -> str:
    """Reasons as one field, so a row can always say why it scored what it did."""
    seen: list[str] = []
    for reason in reasons:
        if reason and reason not in seen:
            seen.append(reason)
    return "; ".join(seen[:4])
