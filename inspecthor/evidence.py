"""Is a collected file worth parsing?

A triage collector takes everything. A UAC run over one Ubuntu host produced 4,171
files, of which **3,183 were "parsed"** — and nearly all of that was
``/etc/apparmor.d/abstractions/*``, ``/etc/alternatives/README`` and XML schemas, each
turned into a one-event row by the generic text parser. The timeline, the case file and
the report all carried that weight for nothing.

The tempting fix is to skip ``/etc`` wholesale, and it is wrong. On the collection that
prompted this module the entire answer was in ``/etc/mongod.conf``: a commented-out
``#security:`` line meant MongoDB accepted unauthenticated connections from any
address. Configuration *is* evidence.

So the question is not "config or not" but "could an intruder's actions be visible
here". A sudoers file, an authorized_keys file and a service config can all answer
that. An AppArmor abstraction that ships identically on every Ubuntu host cannot.

One definition, imported by both the parser that would otherwise consume these and the
reporter that would otherwise list them. Two copies of this judgement would drift, and
the drift would show up as a file quietly parsed one way and reported another.
"""
from __future__ import annotations

import re
from pathlib import Path

# Directories whose contents ship identically on every host of the same distribution.
# Anything an intruder changed here would be invisible against the package baseline
# anyway, which is a different problem than this tool solves.
_NOISE_DIRS = (
    "/etc/alternatives/",
    "/etc/apparmor.d/abstractions/",
    "/etc/apparmor.d/abi/",
    "/etc/apparmor.d/local/",
    "/etc/apparmor.d/tunables/",
    "/etc/ssl/certs/",
    "/usr/share/ca-certificates/",
    "/etc/ca-certificates/",
    "/etc/console-setup/",
    "/etc/dpkg/origins/",
    "/etc/sgml/",
    "/etc/newt/",
    "/etc/terminfo/",
    "/etc/logcheck/",
    "/etc/apt/trusted.gpg.d/",
    "/etc/apt/apt.conf.d/",
    "/etc/dbus-1/system.d/",
    "/etc/X11/Xsession.d/",
    "/etc/vmware-tools/vgauth/schemas/",
    "/etc/rc0.d/", "/etc/rc1.d/", "/etc/rc2.d/", "/etc/rc3.d/", "/etc/rc4.d/",
    "/etc/rc5.d/", "/etc/rc6.d/", "/etc/rcs.d/",
    # Package-shipped systemd units. /etc/systemd/system/ is deliberately NOT here:
    # that is where an admin — or an attacker establishing persistence — puts a unit,
    # and it is listed as evidence below.
    "/usr/lib/systemd/system/",
    "/lib/systemd/system/",
    "/usr/lib/systemd/user/",
    "/etc/emacs/", "/etc/vim/", "/etc/nanorc.d/",
    "/etc/bash_completion.d/",
    "/etc/kernel/",
    "/etc/modprobe.d/",
    "/etc/sysctl.d/",
    "/etc/udev/hwdb.d/",
)

# Extensions that are never a timeline, whatever directory they live in.
_NOISE_SUFFIXES = (
    ".1.gz", ".2.gz", ".3.gz", ".4.gz", ".5.gz", ".6.gz", ".7.gz", ".8.gz",
    ".psf.gz", ".acm.gz", ".kmap.gz",
    ".gpg", ".pem", ".crt", ".cer", ".der", ".pub.asc",
    ".efi.signed", ".xsd", ".dtd", ".xsl",
    ".ttf", ".otf", ".woff", ".woff2", ".pyc", ".pyo", ".so", ".a", ".o",
    ".mo", ".pot", ".ico", ".png", ".jpg", ".gif", ".svg",
)

# Systemd units and udev rules. Enormous in number, identical across hosts, and the
# handful that matter (a unit pointing at a dropped binary) are better caught by the
# service and autorun scoring than by parsing 659 of them as text.
_NOISE_UNIT_SUFFIXES = (
    ".service", ".target", ".socket", ".mount", ".automount", ".timer", ".path",
    ".slice", ".scope", ".device", ".swap", ".rules", ".preset", ".link", ".netdev",
)

# A certificate hash link: /etc/ssl/certs/653b494a.0
_CERT_LINK = re.compile(r".*/[0-9a-f]{8}\.\d+$")

# Files that ARE evidence even though they sit among the noise, checked first. The
# whole point of the module: an exclusion list with no exceptions would have thrown
# away the answer to a real case.
_ALWAYS_EVIDENCE_NAMES = frozenset({
    "passwd", "shadow", "group", "gshadow", "sudoers", "hosts", "hosts.allow",
    "hosts.deny", "crontab", "fstab", "resolv.conf", "nsswitch.conf", "hostname",
    "machine-id", "os-release", "issue", "motd", "shells", "securetty",
    "sshd_config", "ssh_config", "authorized_keys", "authorized_keys2",
    "known_hosts", "mongod.conf", "mongodb.conf", "my.cnf", "postgresql.conf",
    "pg_hba.conf", "redis.conf", "smb.conf", "nginx.conf", "httpd.conf",
    "apache2.conf", "php.ini", "docker-compose.yml", "daemon.json",
    "authorized_hosts", "netplan.yaml", "rsyslog.conf", "sysctl.conf",
    "ld.so.preload", "profile", "bashrc", "bash_history", "zsh_history",
    "mysql_history", "dbshell", "psql_history", "viminfo", "netrc", "rhosts",
})

_ALWAYS_EVIDENCE_DIRS = (
    "/etc/sudoers.d/",
    "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.hourly/", "/etc/cron.weekly/",
    "/etc/cron.monthly/", "/var/spool/cron/",
    "/etc/ssh/",
    "/root/.ssh/", "/.ssh/",
    # Locally-installed units and their enablement symlinks. A malicious unit dropped
    # here is standard Linux persistence (T1543.002), so this directory outranks the
    # blanket ``.service`` suffix rule.
    "/etc/systemd/system/",
    "/etc/init.d/",
    "/etc/rc.local",
    "/etc/profile.d/",
)


def _posix(path: Path | str) -> str:
    return str(path).replace("\\", "/").lower()


def is_evidence_config(path: Path | str) -> bool:
    """True for configuration files where an intruder's changes would be visible."""
    posix = _posix(path)
    name = posix.rsplit("/", 1)[-1]
    if name in _ALWAYS_EVIDENCE_NAMES:
        return True
    if name.startswith(".") and name[1:] in _ALWAYS_EVIDENCE_NAMES:
        return True          # .bash_history, .netrc, .rhosts
    return any(marker in posix for marker in _ALWAYS_EVIDENCE_DIRS)


def is_collector_noise(path: Path | str) -> bool:
    """True for files a collector swept up that cannot carry an intruder's trace.

    Evidence wins: a file named in the evidence list is never noise, however deep in a
    noisy directory it sits. ``/etc/apparmor.d/local/usr.sbin.sshd`` is noise;
    ``/etc/ssh/sshd_config`` is not, even though both are configuration.
    """
    if is_evidence_config(path):
        return False
    posix = _posix(path)
    name = posix.rsplit("/", 1)[-1]
    if any(marker in posix for marker in _NOISE_DIRS):
        return True
    if name.endswith(_NOISE_SUFFIXES) or name.endswith(_NOISE_UNIT_SUFFIXES):
        return True
    if _CERT_LINK.match(posix):
        return True
    # A manual page or locale file anywhere.
    return "/man/man" in posix or "/locale/" in posix
