"""Tests for severity scoring, built from one real intrusion.

Every string here is copied from a KAPE collection with a confirmed compromise. The
tool's own output on that collection was the bug report: the entire attack chain came
out ``info`` or ``med``, and the same day's ``high`` tier held 41 events of which all
41 were the operating system's own housekeeping.

Both halves are asserted, because fixing either one alone leaves the tier useless —
promoting the real chain into a tier that already cries wolf changes nothing an
analyst would notice.
"""
from __future__ import annotations

import pytest

from inspecthor import score
from inspecthor.models import LEVEL_RANK

MAL = r"C:\Users\kimv\AppData\Local\h2cgEzNCsypd\lk9vAU"
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def _at_least(level: str, floor: str) -> bool:
    return LEVEL_RANK[level] >= LEVEL_RANK[floor]


# ---- the chain that was missed -----------------------------------------------


def test_node_from_random_appdata_dir_is_high():
    """The event that mattered most, and it was rated info.

    node.exe is signed by a real vendor and appears in no blocklist. The finding is
    the directory it ran from.
    """
    level, tags, _attck, reasons = score.score_process(
        rf"{MAL}\node.exe",
        rf'"{MAL}\node.exe" C:\Users\kimv\AppData\Local\h2cgEzNCsypd\nXYPsIui5G.dat',
        PS,
    )
    assert _at_least(level, "high"), (level, reasons)
    assert "unusual_exec_path" in tags
    assert reasons, "a high with no stated reason is unauditable"


def test_random_named_binary_spawned_by_node_is_high():
    level, _tags, _attck, reasons = score.score_process(
        rf"{MAL}\NitSSMjZ.exe", rf"{MAL}\NitSSMjZ.exe -", rf"{MAL}\node.exe",
    )
    assert _at_least(level, "high"), (level, reasons)


def test_npm_installing_a_websocket_library_is_high():
    """An implant building its own C2 out of a package registry."""
    level, tags, attck, reasons = score.score_process(
        r"C:\Windows\System32\cmd.exe",
        rf'C:\Windows\system32\cmd.exe /d /s /c "{MAL}\npm.cmd install ws '
        r'--no-save --omit=dev --no-audit --no-fund"',
        rf"{MAL}\NitSSMjZ.exe",
    )
    assert _at_least(level, "high"), (level, reasons)
    assert "pkg_network_install" in tags
    assert "T1105" in attck


@pytest.mark.parametrize("cmdline,label", [
    (r'powershell -NoProfile -Command "(Get-CimInstance -Namespace root/SecurityCenter2 '
     r'-ClassName AntivirusProduct).displayName"', "AV enumeration"),
    (r'cmd.exe /d /s /c "reg query "HKLM\SOFTWARE\Microsoft\Cryptography" /v MachineGuid"',
     "host fingerprint"),
    (r'cmd.exe /d /s /c "net session"', "session enumeration"),
    (r'powershell -Command "(Get-WmiObject Win32_VideoController).Name"', "VM/sandbox check"),
])
def test_recon_commands_are_recognized_and_named(cmdline, label):
    level, tags, _attck, reasons = score.score_process(
        r"C:\Windows\System32\cmd.exe", cmdline, rf"{MAL}\NitSSMjZ.exe",
    )
    assert "recon" in tags
    assert any(label in r for r in reasons), reasons
    # Recon alone must not alert: legitimate inventory software does all of this.
    # Here the parent is in a user-writable path, which is what lifts it.
    assert _at_least(level, "med")


def test_recon_from_a_trusted_parent_stays_low():
    """Inventory and management software runs these constantly."""
    level, tags, _attck, _reasons = score.score_process(
        r"C:\Windows\System32\cmd.exe",
        r'cmd.exe /c "reg query HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid"',
        r"C:\Program Files\Dell\DellClientManagementService\service.exe",
    )
    assert "recon" in tags
    assert level == "low", level


def test_script_host_dropping_to_a_user_writable_path_is_high():
    level, tags, _attck, _r = score.score_process(
        rf"{MAL}\node.exe", "", r"C:\Windows\System32\wscript.exe",
    )
    assert _at_least(level, "high")
    assert "unusual_exec_path" in tags


# ---- the 41 false positives --------------------------------------------------


@pytest.mark.parametrize("name", [
    "AarSvc_26b8fd", "CDPUserSvc_26b8fd", "cbdhsvc_26b8fd", "OneSyncSvc_26b8fd",
    "BluetoothUserService_26b8fd", "WpnUserService_26b8fd",
])
def test_per_user_svchost_services_are_not_findings(name):
    """25 of the 41. Windows creates one per session at every logon."""
    level, tags, reasons = score.score_service(
        name, r"C:\Windows\system32\svchost.exe -k UnistackSvcGroup",
    )
    assert level == "info", (level, reasons)
    assert "os_churn" in tags
    assert reasons and "logon" in reasons[0]


def test_a_service_whose_name_merely_looks_per_user_is_not_exempt():
    """The exemption needs the svchost image too, or it is a free pass for any
    attacker who appends an underscore and six hex digits."""
    level, _tags, _reasons = score.score_service(
        "Evil_26b8fd", r"C:\Users\kimv\AppData\Local\x\evil.exe",
    )
    assert _at_least(level, "high")


@pytest.mark.parametrize("name,value", [
    ("SecurityHealth", r"%windir%\system32\SecurityHealthSystray.exe"),
    ("RtkAudUService", r'"C:\Windows\System32\DriverStore\FileRepository\rtk\RtkAudUService64.exe"'),
    ("Sentinel Agent", r'"C:\Program Files\SentinelOne\Sentinel Agent 25.2.5.437\SentinelUI.exe" /minimized'),
    ("Delete Cached Update Binary",
     r'C:\Windows\system32\cmd.exe /q /c del /q "C:\Program Files\Microsoft OneDrive\x.exe"'),
])
def test_routine_autoruns_are_not_findings(name, value):
    """8 of the 41, all of them shipped software."""
    level, _tags, reasons = score.score_autorun(name, value)
    assert LEVEL_RANK[level] <= LEVEL_RANK["low"], (level, reasons)


def test_an_autorun_into_a_random_appdata_dir_is_critical():
    level, tags, _reasons = score.score_autorun("Updater", rf"{MAL}\NitSSMjZ.exe")
    assert level == "crit"
    assert "random_name" in tags


@pytest.mark.parametrize("task", [
    r"\Microsoft\Office\Office Serviceability Manager",
    r"\OneDrive Per-Machine Standalone Update Task",
    r"\MEECPolicy",
    r"\Microsoft\Windows\UpdateOrchestrator\Reboot",
])
def test_routine_scheduled_tasks_are_not_findings(task):
    """8 of the 41."""
    level, _tags, reasons = score.score_task(task)
    assert LEVEL_RANK[level] <= LEVEL_RANK["low"], (level, reasons)


def test_a_microsoft_named_task_running_from_appdata_is_still_critical():
    """The action outranks the name, or the allow-list becomes the evasion."""
    level, tags, _reasons = score.score_task(
        r"\Microsoft\Windows\Maintenance\Cleanup",
        f'<Exec><Command>{MAL}\\NitSSMjZ.exe</Command></Exec>',
    )
    assert level == "crit"
    assert "unusual_exec_path" in tags


# ---- ordinary activity must stay quiet ---------------------------------------


@pytest.mark.parametrize("image,parent", [
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", r"C:\Windows\explorer.exe"),
    (r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Windows\explorer.exe"),
    (r"C:\Windows\System32\conhost.exe", r"C:\Windows\System32\cmd.exe"),
    (r"C:\Users\ita\AppData\Local\Microsoft\Teams\current\Teams.exe",
     r"C:\Users\ita\AppData\Local\Microsoft\Teams\Update.exe"),
    (r"C:\Users\ita\AppData\Local\Microsoft\Teams\Update.exe", r"C:\Windows\explorer.exe"),
])
def test_normal_software_is_not_promoted(image, parent):
    level, _tags, _attck, reasons = score.score_process(image, "", parent)
    assert level == "info", (image, level, reasons)


def test_known_user_app_exemption_is_anchored_on_the_vendor_directory():
    """Teams is exempt; something dropped beside Teams is not."""
    assert score.is_known_user_app(
        r"C:\Users\ita\AppData\Local\Microsoft\Teams\current\Teams.exe")
    assert not score.is_known_user_app(
        r"C:\Users\ita\AppData\Local\Microsoft\TeamsEvil\payload.exe")


# ---- the name heuristic ------------------------------------------------------


@pytest.mark.parametrize("name", [
    "h2cgEzNCsypd", "lk9vAU", "NitSSMjZ", "nXYPsIui5G", "AjsSJkUI",
])
def test_real_generated_names_are_detected(name):
    assert score.looks_machine_generated(name), name


@pytest.mark.parametrize("name", [
    "node", "node.exe", "chrome", "svchost", "powershell", "WINWORD", "Teams",
    "SecurityHealthSystray", "RtkAudUService64", "msedgewebview2", "conhost",
    "RazerAppEngine", "DellPairService", "SentinelUI", "npm", "explorer",
    "{ADD06C87-F202-4584-AA60-B2F9A35670EA}", "update", "setup", "installer",
])
def test_real_software_names_are_not_flagged(name):
    """This heuristic promotes events, so a false positive costs attention."""
    assert not score.looks_machine_generated(name), name


def test_the_directory_is_scored_not_only_the_filename():
    """node.exe is unremarkable until you notice its parent directory."""
    found = score.random_segments(rf"{MAL}\node.exe")
    assert "h2cgEzNCsypd" in found or "lk9vAU" in found, found
    assert not score.random_segments(
        r"C:\Program Files\Google\Chrome\Application\chrome.exe")


# ---- scoring never silently lowers a curated verdict ------------------------


# ---- regressions from the first run of this scorer on real evidence ----------
#
# The retuned model was measured before it was trusted. It cut 2026-07-27's high
# tier from 41 false to 8, and surfaced the real chain — and introduced 327 new
# false positives of its own, every one of them below.


@pytest.mark.parametrize("name", [
    "SysWOW64",         # flagged, then named as the reason an unrelated path was bad
    "MpCmdRun",         # Defender's own CLI, in ProgramData
    "ProgramFilesX64",
    "_isF830", "_is1BF3", "_isAE81", "_isC8B1",   # InstallShield temp extractors
    "AppUp", "IntelArcSoftware", "CredentialEnrollmentManager",
])
def test_names_that_caused_false_positives_are_not_flagged(name):
    assert not score.looks_machine_generated(name), name


def test_installshield_temp_extractors_are_not_findings():
    """~300 of the 327 false positives: a year of this workstation's installers."""
    level, _tags, _attck, reasons = score.score_process(
        r"C:\Windows\Temp\{BDCB8E4F-C1DC-4042-8C70-52514E6AD5FF}\{9862D0FD}\_isF5E5.exe",
        "", r"C:\Windows\SysWOW64\msiexec.exe",
    )
    assert LEVEL_RANK[level] <= LEVEL_RANK["med"], (level, reasons)
    assert not any("machine-generated" in r for r in reasons), reasons


def test_defender_platform_binary_is_not_a_finding():
    level, _tags, _attck, reasons = score.score_process(
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25050.5-0\MpCmdRun.exe",
        "", r"C:\Windows\System32\services.exe",
    )
    assert LEVEL_RANK[level] <= LEVEL_RANK["med"], (level, reasons)
    assert not any("machine-generated" in r for r in reasons), reasons


def test_a_reason_never_names_a_segment_from_a_different_path():
    """It reported 'SysWOW64' as the machine-generated name in an image path that
    never contained it, because image and parent were or'd into one list."""
    _level, _tags, _attck, reasons = score.score_process(
        r"C:\Windows\Temp\{F3ED97FF-5A0A-4A3E-A26A-75AF4CB98F42}\payload.exe",
        "", r"C:\Users\kimv\AppData\Local\h2cgEzNCsypd\lk9vAU\NitSSMjZ.exe",
    )
    for reason in reasons:
        if "image path" in reason:
            assert "h2cgEzNCsypd" not in reason and "lk9vAU" not in reason, reason


@pytest.mark.parametrize("image", [
    "%SystemRoot%\\system32\\svchost.exe -k UnistackSvcGroup",
    "%systemroot%\\System32\\svchost.exe -k DevicesFlow",
    'C:\\Windows\\system32\\svchost.exe -k PrintWorkflow',
])
def test_per_user_svchost_matches_every_spelling_of_the_path(image):
    """The first regex anchored the full path, so the %SystemRoot% form escaped the
    demotion entirely and stayed at high."""
    level, tags, _reasons = score.score_service("CDPUserSvc_26b8fd", image)
    assert level == "info", (image, level)
    assert "os_churn" in tags


def test_per_session_service_running_its_own_binary_is_demoted():
    """CredentialEnrollmentManagerUserSvc_26b8fd is per-session churn but runs
    system32's own exe, not a shared svchost, so the svchost test never saw it."""
    level, tags, reasons = score.score_service(
        "CredentialEnrollmentManagerUserSvc_26b8fd",
        r"C:\Windows\system32\CredentialEnrollmentManager.exe",
    )
    assert LEVEL_RANK[level] <= LEVEL_RANK["low"], (level, reasons)
    assert "os_churn" in tags


def test_a_per_session_name_does_not_excuse_a_user_writable_image():
    """The user-writable check has to outrank the per-session demotion, or the
    naming convention becomes the evasion."""
    level, _tags, _reasons = score.score_service(
        "EvilUserSvc_26b8fd", rf"{MAL}\NitSSMjZ.exe",
    )
    assert level == "crit"


def test_high_service_reason_does_not_read_as_an_all_clear():
    """It said 'service installed from a trusted root' on a high finding, which
    reads as an explanation for why the row is fine."""
    level, _tags, reasons = score.score_service(
        "RocketAgent Kernel Driver", r"C:\Program Files\RocketAgent\rocketagent-x64.sys",
    )
    assert LEVEL_RANK[level] >= LEVEL_RANK["high"]
    assert not any("trusted root" in r for r in reasons), reasons


def test_windowsapps_service_is_routine():
    """Intel Graphics Software came out 'crit' off a misread path segment."""
    level, _tags, reasons = score.score_service(
        "Intel® Graphics Software",
        r'"C:\Program Files\WindowsApps\AppUp.IntelArcSoftware_26.18.2353.0_x64__8j3eq9eme6ctt\GraphicsSoftware.exe"',
    )
    assert LEVEL_RANK[level] <= LEVEL_RANK["low"], (level, reasons)


def test_process_scoring_only_promotes():
    """score_process must not talk a curated 'high' back down."""
    level, _tags, _attck, _r = score.score_process(
        r"C:\Windows\System32\cmd.exe", "cmd /c dir", r"C:\Windows\explorer.exe",
        base="high",
    )
    assert level == "high"
