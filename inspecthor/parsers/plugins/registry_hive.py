"""Windows registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, UsrClass.dat, Amcache).

Registry evidence answers three recurring questions: what persists, what ran, and
what the machine's own context was (hostname, timezone, network, attached USB).
That last group matters more than it looks — the timezone key is what tells you
whether the rest of your timeline needs shifting.

Note on timestamps: the registry records a last-write time per KEY, not per value.
Every event here therefore carries the key's write time and says so in
``timestamp_desc``, so nobody mistakes it for the moment a specific value changed.
"""
from __future__ import annotations

import codecs
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from ...capabilities import hint as cap_hint
from ...models import Event, ParseContext
from ..base import Parser, register

# (key path, event_type, [attck], severity, note)
_RUN_KEYS = (
    r"Microsoft\Windows\CurrentVersion\Run",
    r"Microsoft\Windows\CurrentVersion\RunOnce",
    r"Microsoft\Windows\CurrentVersion\RunServices",
    r"Microsoft\Windows\CurrentVersion\RunServicesOnce",
    r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
)

# Per-hive interesting keys. Paths are relative to the hive root, which is how
# dissect.regf's open() expects them.
_HIVE_KEYS: dict[str, tuple[tuple[str, str, tuple[str, ...], str], ...]] = {
    "software": tuple(
        (path, "autostart_run_key", ("T1547.001",), "high") for path in _RUN_KEYS
    ) + (
        (r"Microsoft\Windows NT\CurrentVersion\Winlogon", "winlogon_config",
         ("T1547.004",), "med"),
        (r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
         "ifeo_hijack", ("T1546.012",), "high"),
        (r"Microsoft\Windows\CurrentVersion\Explorer\FileExts", "file_assoc", (), "info"),
        (r"Microsoft\Windows Defender\Exclusions\Paths", "defender_exclusion",
         ("T1562.001",), "high"),
        (r"Microsoft\Windows Defender\Exclusions\Extensions", "defender_exclusion",
         ("T1562.001",), "high"),
    ),
    "system": (
        (r"Select", "hive_select", (), "info"),
        (r"ControlSet001\Control\ComputerName\ComputerName", "computer_name", (), "info"),
        (r"ControlSet001\Control\TimeZoneInformation", "system_timezone", (), "info"),
        (r"ControlSet001\Services", "service_list", ("T1543.003",), "med"),
        (r"ControlSet001\Enum\USBSTOR", "usb_device", ("T1091",), "med"),
        (r"MountedDevices", "mounted_device", ("T1091",), "info"),
        (r"ControlSet001\Control\Session Manager\Memory Management",
         "memory_config", (), "info"),
        (r"ControlSet001\Control\Terminal Server", "rdp_config", ("T1021.001",), "med"),
        (r"ControlSet001\Control\Lsa", "lsa_config", ("T1003.001",), "med"),
    ),
    "ntuser": tuple(
        (path, "autostart_run_key", ("T1547.001",), "high") for path in _RUN_KEYS
    ) + (
        (r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
         "typed_path", (), "info"),
        (r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
         "run_mru", ("T1059",), "med"),
        (r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
         "recent_doc", (), "info"),
        (r"Software\Microsoft\Terminal Server Client\Servers",
         "rdp_client_history", ("T1021.001",), "med"),
        (r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
         "userassist_exec", ("T1204.002",), "info"),
        (r"Environment", "user_environment", (), "info"),
    ),
    "usrclass": (
        (r"Local Settings\Software\Microsoft\Windows\Shell\BagMRU", "shellbag", (), "info"),
    ),
    "sam": (
        (r"SAM\Domains\Account\Users\Names", "local_account", ("T1087.001",), "info"),
    ),
    "amcache": (
        (r"Root\InventoryApplicationFile", "amcache_exec", ("T1204",), "med"),
        (r"Root\File", "amcache_exec", ("T1204",), "med"),
    ),
}

# Service subkeys worth flagging: a service whose ImagePath is a script, a temp
# path, or a bare cmd is far more likely to be attacker-installed.
_SUSPECT_IMAGE = re.compile(
    r"(?:\\temp\\|\\tmp\\|\\users\\public\\|\\appdata\\|\.ps1|\.vbs|\.bat|\.cmd|"
    r"powershell|cmd\.exe\s*/c|rundll32|mshta|regsvr32)", re.I
)

_MAX_SUBKEYS = 2000        # a Services or USBSTOR tree can be large
_MAX_VALUE_TEXT = 1000
_ROT13 = "rot13"


def _hive_type(path: Path, root_names: set[str]) -> str:
    """Classify a hive from its filename, falling back to its root subkeys.

    Filenames in collected evidence are frequently renamed or lowercased, so the
    content check is the reliable one.
    """
    name = path.name.lower()
    if name.startswith("ntuser"):
        return "ntuser"
    if name.startswith("usrclass"):
        return "usrclass"
    if "amcache" in name:
        return "amcache"
    if name in ("sam", "sam.hve"):
        return "sam"
    if name in ("system", "system.hve"):
        return "system"
    if name in ("software", "software.hve"):
        return "software"
    if name in ("security", "security.hve"):
        return "security"

    lowered = {n.lower() for n in root_names}
    if "select" in lowered or "controlset001" in lowered:
        return "system"
    if "microsoft" in lowered and "classes" not in lowered:
        return "software"
    if "sam" in lowered:
        return "sam"
    if any(n.startswith("root") for n in lowered):
        return "amcache"
    if "local settings" in lowered:
        return "usrclass"
    if "environment" in lowered or "volatile environment" in lowered:
        return "ntuser"
    return "unknown"


class _Hive:
    """Adapter over dissect.regf with a regipy fallback.

    Both libraries model the same thing with different names; normalizing here
    keeps the emit loop free of backend conditionals.
    """

    def __init__(self, backend: str, handle: Any, fh: Any = None) -> None:
        self.backend = backend
        self.handle = handle
        self._fh = fh

    @classmethod
    def open(cls, path: Path, ctx: ParseContext) -> "_Hive | None":
        try:
            from dissect.regf import RegistryHive
            fh = path.open("rb")
            try:
                return cls("regf", RegistryHive(fh), fh)
            except Exception:
                fh.close()
                raise
        except ImportError:
            pass
        except Exception as exc:
            ctx.hint(f"{path.name}: dissect.regf could not open this hive ({exc})")
            return None
        try:
            from regipy.registry import RegistryHive as RegipyHive
            return cls("regipy", RegipyHive(str(path)))
        except ImportError:
            ctx.hint(cap_hint("registry"))
            return None
        except Exception as exc:
            ctx.hint(f"{path.name}: regipy could not open this hive ({exc})")
            return None

    def close(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass

    def root_names(self) -> list[str]:
        try:
            if self.backend == "regf":
                return [k.name for k in self.handle.root().subkeys()]
            return [k.name for k in self.handle.get_key("\\").iter_subkeys()]
        except Exception:
            return []

    def key(self, keypath: str):
        """Return an opaque key object or None if absent."""
        try:
            if self.backend == "regf":
                return self.handle.open(keypath)
            return self.handle.get_key(keypath)
        except Exception:
            return None

    def key_time(self, key) -> datetime | None:
        try:
            if self.backend == "regf":
                return key.timestamp
            from regipy.utils import convert_wintime
            return convert_wintime(key.header.last_modified, as_json=False)
        except Exception:
            return None

    def values(self, key) -> list[tuple[str, Any]]:
        out: list[tuple[str, Any]] = []
        try:
            if self.backend == "regf":
                for value in key.values():
                    out.append((getattr(value, "name", "") or "(Default)",
                                getattr(value, "value", None)))
            else:
                for value in key.get_values(as_json=True):
                    if isinstance(value, dict):
                        out.append((value.get("name") or "(Default)", value.get("value")))
                    else:
                        out.append((getattr(value, "name", "") or "(Default)",
                                    getattr(value, "value", None)))
        except Exception:
            return out
        return out

    def subkeys(self, key) -> Iterator[Any]:
        try:
            if self.backend == "regf":
                yield from key.subkeys()
            else:
                yield from key.iter_subkeys()
        except Exception:
            return


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        # Registry binary values are frequently UTF-16LE strings.
        try:
            decoded = value.decode("utf-16-le", "ignore").strip("\x00")
            if decoded and decoded.isprintable():
                return decoded[:_MAX_VALUE_TEXT]
        except Exception:
            pass
        return value[:64].hex()
    if isinstance(value, (list, tuple)):
        return ", ".join(_text(v) for v in value)[:_MAX_VALUE_TEXT]
    return str(value)[:_MAX_VALUE_TEXT]


def _userassist_name(name: str) -> str:
    """UserAssist value names are ROT13-encoded paths."""
    try:
        return codecs.decode(name, _ROT13)
    except Exception:
        return name


def _tz_bias_minutes(raw: Any) -> str:
    """TimeZoneInformation ActiveTimeBias is a little-endian DWORD of minutes."""
    if isinstance(raw, int):
        bias = raw
    elif isinstance(raw, bytes) and len(raw) >= 4:
        bias = struct.unpack("<i", raw[:4])[0]
    else:
        return ""
    # Bias is minutes to ADD to local time to reach UTC, so invert for display.
    sign = "-" if bias > 0 else "+"
    total = abs(int(bias))
    return f"UTC{sign}{total // 60:02d}:{total % 60:02d}"


@register
class RegistryHiveParser(Parser):
    """Windows registry hive parser."""

    name = "registry"
    display = "Windows Registry"
    category = "windows"
    magic = (b"regf",)
    kinds = ("registry",)
    path_globs = (
        "NTUSER.DAT", "ntuser.dat", "UsrClass.dat", "usrclass.dat",
        "SYSTEM", "SOFTWARE", "SAM", "SECURITY", "Amcache.hve", "*.hve",
    )
    requires = "dissect.regf"
    install_hint = cap_hint("registry")

    def dependency_ok(self) -> tuple[bool, str]:
        import importlib.util
        for module in ("dissect.regf", "regipy"):
            try:
                if importlib.util.find_spec(module) is not None:
                    return True, ""
            except (ImportError, ValueError):
                continue
        return False, self.install_hint

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        hive = _Hive.open(path, ctx)
        if hive is None:
            return
        try:
            hive_type = _hive_type(path, set(hive.root_names()))
            if hive_type == "unknown":
                ctx.hint(f"{path.name}: unrecognized hive layout; parsed generically")
            targets = _HIVE_KEYS.get(hive_type, ())
            if not targets:
                # Still record that the hive exists and when it was last written.
                yield from self._hive_summary(path, hive, hive_type, ctx)
                return

            yield from self._hive_summary(path, hive, hive_type, ctx)
            for keypath, event_type, attck, severity in targets:
                key = hive.key(keypath)
                if key is None:
                    continue
                try:
                    yield from self._events_for_key(
                        path, hive, hive_type, keypath, key,
                        event_type, list(attck), severity, ctx,
                    )
                except Exception:
                    # A malformed subtree should not cost the whole hive.
                    continue
        finally:
            hive.close()

    def _hive_summary(
        self, path: Path, hive: "_Hive", hive_type: str, ctx: ParseContext
    ) -> Iterator[Event]:
        root = hive.key("") or (hive.handle.root() if hive.backend == "regf" else None)
        when = hive.key_time(root) if root is not None else None
        if when is None:
            try:
                when = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
            except OSError:
                return
        yield ctx.event(
            timestamp=when,
            timestamp_desc="Hive root last write",
            event_type="registry_hive",
            message=f"{path.name}: {hive_type} hive ingested ({hive.backend})",
            data={"hive_type": hive_type, "backend": hive.backend},
            source_artifact=f"{self.name}/{hive_type}",
            artifact_path=str(path),
            parser=self.name,
        )

    def _events_for_key(
        self,
        path: Path,
        hive: "_Hive",
        hive_type: str,
        keypath: str,
        key: Any,
        event_type: str,
        attck: list[str],
        severity: str,
        ctx: ParseContext,
    ) -> Iterator[Event]:
        when = hive.key_time(key) or datetime.fromtimestamp(
            path.stat().st_mtime, tz=timezone.utc
        )
        common = dict(
            source_artifact=f"{self.name}/{hive_type}",
            artifact_path=str(path),
            parser=self.name,
            timestamp_desc="Registry key last write",
        )

        # Container keys: iterate subkeys (each service / USB device / account).
        if event_type in ("service_list", "usb_device", "local_account", "amcache_exec",
                          "rdp_client_history", "shellbag", "file_assoc"):
            count = 0
            for sub in hive.subkeys(key):
                if count >= _MAX_SUBKEYS:
                    ctx.hint(f"{path.name}: {keypath} truncated at {_MAX_SUBKEYS} subkeys")
                    break
                count += 1
                sub_when = hive.key_time(sub) or when
                values = dict(hive.values(sub))
                sub_name = getattr(sub, "name", "") or "?"
                yield from self._subkey_event(
                    event_type, keypath, sub_name, values, sub_when, attck, severity,
                    common, ctx,
                )
            return

        # Leaf keys: one event per value.
        for name, value in hive.values(key):
            text = _text(value)
            display_name = name
            data = {"key": keypath, "name": name, "value": text}
            local_attck = list(attck)
            local_sev = severity

            if event_type == "system_timezone":
                if name.lower() in ("activetimebias", "bias"):
                    data["utc_offset"] = _tz_bias_minutes(value)
                elif name.lower() not in ("timezonekeyname", "standardname", "daylightname"):
                    continue
            elif event_type == "userassist_exec":
                display_name = _userassist_name(name)
                data["program"] = display_name
            elif event_type == "autostart_run_key" and _SUSPECT_IMAGE.search(text):
                data["suspicious"] = True
                local_sev = "high"
            elif event_type == "defender_exclusion":
                local_sev = "high"

            if not text and event_type not in ("system_timezone", "computer_name"):
                continue

            yield ctx.event(
                timestamp=when,
                event_type=event_type,
                message=f"{event_type.replace('_', ' ')}: {display_name} = {text}"[:400],
                data=data,
                attck=local_attck,
                severity=local_sev,
                **common,
            )

    def _subkey_event(
        self,
        event_type: str,
        keypath: str,
        sub_name: str,
        values: dict,
        when: datetime,
        attck: list[str],
        severity: str,
        common: dict,
        ctx: ParseContext,
    ) -> Iterator[Event]:
        """One event per container subkey, shaped by what the container means."""
        data: dict[str, Any] = {"key": f"{keypath}\\{sub_name}", "name": sub_name}
        local_attck = list(attck)
        local_sev = severity
        message = f"{event_type.replace('_', ' ')}: {sub_name}"

        if event_type == "service_list":
            image = _text(values.get("ImagePath"))
            if not image:
                return
            data.update({
                "service_name": sub_name,
                "image_path": image,
                "start": _text(values.get("Start")),
                "type": _text(values.get("Type")),
                "display_name": _text(values.get("DisplayName")),
            })
            if _SUSPECT_IMAGE.search(image):
                data["suspicious"] = True
                local_sev = "high"
                message = f"suspicious service: {sub_name} -> {image}"
            else:
                local_sev = "info"
                message = f"service: {sub_name} -> {image}"
        elif event_type == "usb_device":
            data["device"] = sub_name
            message = f"USB device: {sub_name}"
        elif event_type == "local_account":
            data["account"] = sub_name
            message = f"local account: {sub_name}"
        elif event_type == "amcache_exec":
            path_val = _text(values.get("LowerCaseLongPath") or values.get("15") or "")
            sha1 = _text(values.get("FileId") or values.get("101") or "")
            if sha1.startswith("0000"):
                sha1 = sha1[4:]          # Amcache prefixes SHA-1 with four zeros
            data.update({"program_path": path_val, "sha1": sha1.lower()})
            message = f"amcache: {path_val or sub_name}"
        elif event_type == "rdp_client_history":
            data["server"] = sub_name
            data["username_hint"] = _text(values.get("UsernameHint"))
            message = f"RDP client target: {sub_name}"
        else:
            if values:
                data["values"] = {k: _text(v) for k, v in list(values.items())[:20]}

        yield ctx.event(
            timestamp=when,
            event_type=event_type,
            message=message[:400],
            data=data,
            attck=local_attck,
            severity=local_sev,
            **common,
        )
