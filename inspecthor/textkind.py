"""What is in this text file, when nothing in it is timestamped?

Reported: *"there were several txt files that were not parsed. While this is ok,
inspecthor should be able to flag txt files that may be of interest such as auth
logs."*

Measured on a UAC collection: **1,326 of 1,331 ``.txt`` files produced exactly one event
each**, because command output has no per-line timestamps and so no timeline can be
built from it. That single event read ``lsof_-nPl.txt: 1834 lines, no parseable
timestamps`` — a 753 KB inventory of every open file and socket on the host, described
by its line count.

The content was never lost: the generic parser stores a 16 KB preview in ``raw``, which
is FTS-indexed, so ``find`` reaches it. What was missing is any statement of **what the
file is**, so an analyst scanning the case has no reason to open it.

Two signals, and the first is much stronger than the second:

**The filename.** UAC names every output file after the command that produced it —
``lsof_-nPl.txt``, ``ss_-anp.txt``, ``dpkg_-l.txt``, ``utmpdump_var_log_wtmp.txt``. That
is not a heuristic, it is the collector's naming convention, and these names were taken
from a real collection.

**The content.** For arbitrary files — a log copied to the desktop, an operator's notes,
the ``auth.log`` the report asked about — the filename says nothing, so distinctive
strings decide. Only patterns worth trusting are used: sshd and PAM authentication
records are fixed strings, private key headers are fixed strings. Column layouts are
not, because exact header spacing varies by version and platform and this module was
written without a copy of every one to check against.

**Classifying is not alerting.** A file containing a process list is not a finding, and
the last four rounds of false positives in this project all came from treating the
existence of something as evidence of wrongdoing. Everything here is ``info`` except
credential material, which is ``med``.
"""
from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# by filename — UAC names its output after the command
# ---------------------------------------------------------------------------

# (filename substring, label, what an analyst gets from it)
_BY_NAME: tuple[tuple[str, str, str], ...] = (
    ("utmpdump", "Login records (utmpdump of wtmp/btmp)",
     "successful and failed logins with times, terminals and source addresses"),
    ("last", "Login history (last)", "who logged in, when, and from where"),
    ("lastlog", "Last login per account (lastlog)", "per-account most recent login"),
    ("lsof", "Open files and sockets (lsof)",
     "every open file and network socket with its owning process"),
    ("netstat", "Network connections (netstat)",
     "connections and listeners with owning process"),
    ("ss_", "Network connections (ss)",
     "connections and listeners with owning process"),
    ("ps_", "Process list (ps)", "what was running, with command lines"),
    ("pstree", "Process tree (pstree)", "parent/child relationships between processes"),
    ("top", "Process snapshot (top)", "running processes by resource use"),
    ("dpkg_-l", "Installed packages (dpkg)", "what software was installed"),
    ("rpm_-qa", "Installed packages (rpm)", "what software was installed"),
    ("apt_list", "Installed packages (apt)", "what software was installed"),
    ("snap_list", "Installed snaps", "what snap software was installed"),
    ("systemctl_list-unit", "Systemd units", "services present and their enablement"),
    ("systemctl_list-timers", "Systemd timers", "scheduled activity via timers"),
    ("crontab", "Cron jobs", "scheduled commands"),
    ("iptables", "Firewall rules (iptables)", "what was allowed in and out"),
    ("nft", "Firewall rules (nftables)", "what was allowed in and out"),
    ("ufw", "Firewall rules (ufw)", "what was allowed in and out"),
    ("mount", "Mounted filesystems", "what was mounted, from where, with what options"),
    ("suid", "SUID binaries", "binaries that run as their owner"),
    ("sgid", "SGID binaries", "binaries that run as their group"),
    ("world_writable", "World-writable paths", "where any user could write"),
    ("hidden_file", "Hidden files", "dotfiles outside the usual places"),
    ("hidden_director", "Hidden directories", "dot-directories outside the usual places"),
    ("user_name_unknown", "Files with no owning user",
     "files whose UID has no passwd entry — often left by a deleted account"),
    ("group_name_unknown", "Files with no owning group", "files whose GID has no entry"),
    ("getcap", "File capabilities", "binaries granted capabilities without SUID"),
    ("arp", "ARP cache", "hosts recently talked to on the local segment"),
    ("ip_a", "Network interfaces", "addresses configured on the host"),
    ("ifconfig", "Network interfaces", "addresses configured on the host"),
    ("route", "Routing table", "where traffic was sent"),
    ("resolv", "DNS configuration", "which resolvers were used"),
    ("dmesg", "Kernel ring buffer (dmesg)", "kernel messages, including module loads"),
    ("lsmod", "Loaded kernel modules", "modules present in the running kernel"),
    ("sysctl", "Kernel parameters", "runtime kernel configuration"),
    ("env", "Environment variables", "environment of the collecting shell"),
    ("docker_ps", "Containers (docker)", "running and stopped containers"),
    ("lxc_", "Containers (lxc)", "container inventory"),
    ("who", "Logged-in users", "sessions active at collection time"),
    ("w_", "Logged-in users", "sessions active at collection time"),
)

# ---------------------------------------------------------------------------
# by content — only patterns that are fixed strings, not column layouts
# ---------------------------------------------------------------------------

# sshd and PAM emit these verbatim; they do not vary by column width.
_AUTH = re.compile(
    r"Failed password for|Accepted password for|Accepted publickey for|"
    r"authentication failure|session opened for user|session closed for user|"
    r"Invalid user |invalid user |pam_unix\(|sudo:.{0,80}COMMAND=|"
    r"Failed keyboard-interactive|Connection closed by authenticating user",
)

_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY")
_CLOUD_SECRET = re.compile(
    r"AKIA[0-9A-Z]{16}|aws_secret_access_key|ASIA[0-9A-Z]{16}|"
    r"(?:mongodb|postgres(?:ql)?|mysql|redis|amqp)(?:\+srv)?://[^\s:@/]+:[^\s@/]+@|"
    r"xox[baprs]-[0-9A-Za-z-]{10,}|gh[pousr]_[0-9A-Za-z]{30,}",
)
_WEB_ACCESS = re.compile(r'"(?:GET|POST|HEAD|PUT|DELETE|OPTIONS) [^"]+ HTTP/\d')
_SHELL_PROMPT_HISTORY = re.compile(
    r"^(?:sudo |cd |ls|cat |curl |wget |vi |nano |apt |systemctl |mongo)", re.M,
)


def classify(name: str, sample: str) -> tuple[str, str, str, str]:
    """Return ``(kind, label, severity, why)`` for a text file.

    ``name`` is the filename, ``sample`` the first few KB of content. Filename first —
    it is the collector's own statement of what it ran.
    """
    lowered = (name or "").lower()

    # Credentials outrank everything: a private key inside a collected text file is
    # worth an analyst's attention regardless of which file it is.
    if _PRIVATE_KEY.search(sample):
        return ("credentials", "Contains a PRIVATE KEY", "med",
                "a private key is in this file — check whose it is and whether it moved")
    if _CLOUD_SECRET.search(sample):
        return ("credentials", "Contains a credential or connection secret", "med",
                "an access key or a URI with an embedded password is in this file")

    if _AUTH.search(sample):
        return ("auth", "Authentication records", "info",
                "logins, failures and sudo use — read this for who got in and when")

    for marker, label, why in _BY_NAME:
        if marker in lowered:
            return (_kind_for(label), label, "info", why)

    if _WEB_ACCESS.search(sample):
        return ("web_access", "Web server access log", "info",
                "requests with source addresses and user agents")

    stripped = [line for line in sample.splitlines() if line.strip()]
    if stripped and all(line.startswith("/") and " " not in line.strip()
                        for line in stripped[:20]):
        return ("path_list", "List of filesystem paths", "info",
                "a list of paths — check what produced it")

    if len(stripped) > 3 and len(_SHELL_PROMPT_HISTORY.findall(sample)) >= 3:
        return ("commands", "Looks like a list of shell commands", "info",
                "reads as commands someone ran — worth reading in full")

    return ("", "", "info", "")


def _kind_for(label: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
    return slug[:40] or "text"


def describe(name: str, sample: str, lines: int) -> tuple[str, str, str, str]:
    """``(title, details, severity, why)`` for the one event an untimed file produces.

    Falls back to the old line-count wording only when nothing is recognized, so a row
    never becomes *less* informative than it was.
    """
    kind, label, severity, why = classify(name, sample)
    if label:
        return (label, f"File: {name} ¦ Lines: {lines:,} ¦ {why}", severity, why)
    return (
        "Text file with no timestamps",
        f"File: {name} ¦ Lines: {lines:,} ¦ no per-line timestamps, "
        "content is searchable",
        "info",
        "",
    )
