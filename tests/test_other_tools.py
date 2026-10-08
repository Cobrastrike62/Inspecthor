"""Tests for the non-KAPE forensic tools: Plaso, Velociraptor, Hayabusa, Chainsaw.

These three parsers added two new claimants for ``*.csv`` and two for ``*.json``,
on top of the EZTools family and generic_text. **Most of this file is about which
parser wins**, because the failure mode is not a crash: a Plaso super-timeline
read as an EZTools export, or a Velociraptor result read as text, parses fine and
produces wrong or empty events that nobody notices.

The rest covers the formats' sharp edges: l2tcsv splits one timestamp across three
columns, Velociraptor has no fixed schema at all, and both detection tools carry a
severity that must be mapped rather than recomputed.
"""
from __future__ import annotations

import json
from datetime import timezone
from pathlib import Path

import pytest

from inspecthor.models import ParseContext
from inspecthor.parsers._loader import select_parser
from inspecthor.parsers.plugins.detections import (
    DetectionCsvParser, map_level, match_shape,
)
from inspecthor.parsers.plugins.detections import parse_time as det_time
from inspecthor.parsers.plugins.plaso import (
    L2T_COLUMNS, PlasoParser, macb_description, parse_json_time, parse_l2t_time,
)
from inspecthor.parsers.plugins.velociraptor import (
    VelociraptorParser, artifact_name, looks_like_results, parse_time, subject_of,
)

L2T_HEADER = ",".join(L2T_COLUMNS)

HAYABUSA = ("Timestamp,RuleTitle,Level,Computer,Channel,EventID,RecordID,Details,"
            "RuleFile,MitreTactics")

CHAINSAW = "timestamp,detections,path,Event ID,computer,channel,record_id"


def write(tmp_path: Path, name: str, lines: list[str]) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def run(parser, path: Path, **kw):
    ctx = ParseContext(evidence_root=path.parent, **kw)
    return list(parser.parse(path, ctx)), ctx


def body(events):
    return [e for e in events if e.event_type != "artifact_summary"]


# ---- who claims what ---------------------------------------------------------


def test_an_l2tcsv_goes_to_plaso_not_eztools(tmp_path: Path):
    """Both claim *.csv. A super-timeline read as an EZTools export would parse
    and produce nothing, which is the failure nobody sees."""
    path = write(tmp_path, "timeline.csv", [
        L2T_HEADER,
        "10/15/2025,08:47:30,UTC,M...,FILE,NTFS $MFT,Content Modification Time,-,"
        "WS01,evil.exe,C:/Windows/Temp/evil.exe modified,2,"
        "C:/Windows/Temp/evil.exe,1234,-,-,-",
    ])
    chosen, _unavailable = select_parser(path, b"date,time,timezone", "text")
    assert chosen is not None and chosen.name == "plaso"


def test_a_hayabusa_csv_goes_to_detections_not_eztools(tmp_path: Path):
    path = write(tmp_path, "hits.csv", [
        HAYABUSA,
        "2025-09-01 08:47:30.123 +00:00,Suspicious PowerShell,high,WS01,"
        "Microsoft-Windows-Sysmon/Operational,1,55,enc command,rule.yml,Execution",
    ])
    chosen, _ = select_parser(path, b"Timestamp,RuleTitle", "text")
    assert chosen is not None and chosen.name == "detections"


def test_an_eztools_csv_still_goes_to_eztools(tmp_path: Path):
    """The regression guard for the two parsers added above it."""
    path = write(tmp_path, "rb.csv", [
        "SourceName,FileType,FileName,FileSize,DeletedOn",
        "$IA1,File,C:\\x\\a.exe,100,2025-09-01 08:00:00",
    ])
    chosen, _ = select_parser(path, b"SourceName,FileType", "text")
    assert chosen is not None and chosen.name == "eztools"


def test_a_velociraptor_result_goes_to_velociraptor(tmp_path: Path):
    path = write(tmp_path, "results/Windows.System.Pslist.json", [
        json.dumps({"Timestamp": "2025-09-01T08:47:30Z", "Exe": "C:\\W\\a.exe"}),
        json.dumps({"Timestamp": "2025-09-01T08:48:00Z", "Exe": "C:\\W\\b.exe"}),
    ])
    chosen, _ = select_parser(path, b'{"Timestamp"', "binary")
    assert chosen is not None and chosen.name == "velociraptor"


def test_a_psort_json_goes_to_plaso(tmp_path: Path):
    """Plaso and Velociraptor both claim *.json. data_type is Plaso's own
    discriminator and appears on every event it writes."""
    path = write(tmp_path, "out.json", [
        json.dumps({"data_type": "fs:stat", "timestamp": 1757000000000000,
                    "timestamp_desc": "Content Modification Time",
                    "filename": "/tmp/x.sh", "message": "x.sh modified"}),
    ])
    chosen, _ = select_parser(path, b'{"data_type"', "binary")
    assert chosen is not None and chosen.name == "plaso"


def test_an_unrelated_json_is_claimed_by_neither(tmp_path: Path):
    path = write(tmp_path, "config.json", [json.dumps({"setting": "value"})])
    assert PlasoParser().sniff(path, b"", "") == 0.0
    assert VelociraptorParser().sniff(path, b"", "") == 0.0


# ---- plaso l2tcsv ------------------------------------------------------------


def test_the_three_timestamp_columns_combine():
    """l2tcsv is the reason this is not another EZTools spec: date, time and
    timezone are separate columns."""
    when = parse_l2t_time("10/15/2025", "08:47:30", "UTC")
    assert when is not None
    assert (when.year, when.month, when.day, when.hour) == (2025, 10, 15, 8)
    assert when.tzinfo is not None


def test_a_named_timezone_is_applied():
    utc = parse_l2t_time("10/15/2025", "08:47:30", "UTC")
    chicago = parse_l2t_time("10/15/2025", "08:47:30", "America/Chicago")
    assert chicago is not None
    assert chicago.utcoffset() != utc.utcoffset()


def test_an_unresolvable_timezone_falls_back_rather_than_dropping_the_row():
    """The time is still the time. A per-row warning on a million-row timeline
    would be noise, so it degrades quietly to UTC."""
    when = parse_l2t_time("10/15/2025", "08:47:30", "Mars/Olympus")
    assert when is not None
    assert when.utcoffset().total_seconds() == 0


def test_an_empty_date_is_not_a_timestamp():
    assert parse_l2t_time("", "08:47:30", "UTC") is None
    assert parse_l2t_time("10/15/2025", "", "UTC") is None


def test_macb_uses_the_same_notation_as_the_bodyfile_parser():
    assert macb_description("M...") == "Modified"
    assert macb_description("MACB") == "Modified/Accessed/Changed/Created"
    assert macb_description("") == "Timeline entry"


def test_an_l2tcsv_row_becomes_an_event(tmp_path: Path):
    path = write(tmp_path, "timeline.csv", [
        L2T_HEADER,
        "10/15/2025,08:47:30,UTC,M...,FILE,NTFS $MFT,Content Modification Time,-,"
        "WS01,evil,C:/Users/b/AppData/Local/Temp/evil.exe modified,2,"
        "C:/Users/b/AppData/Local/Temp/evil.exe,1234,-,-,-",
    ])
    events = body(run(PlasoParser(), path)[0])
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "timeline_entry"
    assert event.host == "WS01"
    assert event.severity == "high", "an exe under AppData\\Local\\Temp is promoted"
    assert "Modified" in event.timestamp_desc


def test_psort_json_microseconds_parse():
    """Plaso stores microseconds since epoch, which read as seconds would be 1970."""
    when = parse_json_time(1757000000000000)
    assert when is not None and when.year == 2025


def test_psort_json_iso_parses():
    assert parse_json_time("2025-09-01T08:47:30+00:00").year == 2025


def test_a_psort_json_file_parses(tmp_path: Path):
    path = write(tmp_path, "events.json", [
        json.dumps({"data_type": "fs:stat", "timestamp": 1757000000000000,
                    "timestamp_desc": "Content Modification Time",
                    "filename": "/tmp/x.sh", "message": "x.sh modified",
                    "hostname": "web01"}),
        json.dumps({"data_type": "syslog:line", "timestamp": 1757000100000000,
                    "timestamp_desc": "Written Time", "message": "sshd started"}),
    ])
    events, _ctx = run(PlasoParser(), path)
    rows = body(events)
    assert len(rows) == 2
    assert rows[0].host == "web01"
    assert any(e.event_type == "artifact_summary" for e in events)


# ---- velociraptor ------------------------------------------------------------


def test_the_artifact_name_becomes_the_source(tmp_path: Path):
    """An analyst filters on the Velociraptor artifact name, so that is what
    source_artifact has to be."""
    path = write(tmp_path, "results/Windows.KapeFiles.Targets.json", [
        json.dumps({"Mtime": "2025-09-01T08:47:30Z", "OSPath": "C:\\W\\a.txt"}),
    ])
    events = body(run(VelociraptorParser(), path)[0])
    assert events
    assert events[0].source_artifact == "velociraptor/Windows.KapeFiles.Targets"


def test_artifact_name_strips_a_results_suffix():
    assert artifact_name(Path("x/Windows.System.Pslist_results.json")) \
        == "Windows.System.Pslist"


def test_rfc3339_nano_parses():
    """Go writes more fractional digits than strptime accepts."""
    assert parse_time("2025-09-01T08:47:30.123456789Z").year == 2025


def test_the_go_zero_time_is_not_a_timestamp():
    assert parse_time("0001-01-01T00:00:00Z") is None


def test_booleans_are_never_timestamps():
    assert parse_time(True) is None
    assert parse_time(False) is None


def test_the_subject_comes_from_the_first_path_like_column():
    assert subject_of({"OSPath": "C:\\a.exe", "Name": "a.exe"}) == "C:\\a.exe"
    assert subject_of({"Name": "a.exe"}) == "a.exe"
    assert subject_of({"Unrelated": 1}) == ""


def test_an_inventory_artifact_says_it_had_no_timestamps(tmp_path: Path):
    """Pslist is a snapshot. The analyst has to know the rows were seen and
    skipped, not that the artifact was empty."""
    path = write(tmp_path, "results/Windows.System.Pslist.json", [
        json.dumps({"Pid": 4, "Name": "System"}),
        json.dumps({"Pid": 8, "Name": "smss.exe"}),
    ])
    events, ctx = run(VelociraptorParser(), path)
    assert body(events) == []
    assert any("inventory" in h for h in ctx.hints)


def test_a_bare_json_outside_results_needs_a_timestamp_to_be_claimed(tmp_path: Path):
    """Otherwise this claims every JSON file on the system."""
    without = write(tmp_path, "data.json", [
        json.dumps({"a": 1}), json.dumps({"a": 2})])
    with_time = write(tmp_path, "data2.json", [
        json.dumps({"Timestamp": "2025-09-01T08:47:30Z", "a": 1}),
        json.dumps({"Timestamp": "2025-09-01T08:48:30Z", "a": 2})])
    assert not looks_like_results(without)
    assert looks_like_results(with_time)


# ---- detections --------------------------------------------------------------


def test_both_detection_tools_are_recognised():
    assert match_shape([c.lower() for c in HAYABUSA.split(",")]).name == "hayabusa"
    assert match_shape(
        [c.lower().replace(" ", "") for c in CHAINSAW.split(",")]).name == "chainsaw"


def test_their_severity_is_mapped_not_recomputed():
    """The rule author had the rule; this has one row. Mapping is honest."""
    assert map_level("critical") == "high"
    assert map_level("high") == "high"
    assert map_level("medium") == "med"
    assert map_level("low") == "low"
    assert map_level("informational") == "info"


def test_an_unknown_level_does_not_become_a_finding():
    assert map_level("spicy") == "info"
    assert map_level("") == "info"


def test_hayabusa_timestamps_parse():
    assert det_time("2025-09-01 08:47:30.123 +00:00").year == 2025
    assert det_time("2025-09-01T08:47:30Z").year == 2025
    assert det_time("") is None


def test_a_detection_is_tagged_as_third_party(tmp_path: Path):
    """A rule firing is not the same as something happening. These must be
    filterable, and must not quietly outrank artifacts the analyst can verify."""
    path = write(tmp_path, "hits.csv", [
        HAYABUSA,
        "2025-09-01 08:47:30.123 +00:00,Suspicious PowerShell,high,WS01,"
        "Microsoft-Windows-Sysmon/Operational,1,55,enc command,rule.yml,Execution",
    ])
    events = body(run(DetectionCsvParser(), path)[0])
    assert len(events) == 1
    event = events[0]
    assert event.severity == "high"
    assert "third_party_detection" in event.tags
    assert "hayabusa" in event.tags
    assert event.event_id == "1"
    assert "Sysmon" in event.channel
    assert event.event_type == "detection"


def test_a_chainsaw_export_parses(tmp_path: Path):
    path = write(tmp_path, "cs.csv", [
        CHAINSAW,
        "2025-09-01T08:47:30+00:00,Suspicious Service,C:\\evt\\System.evtx,7045,"
        "WS01,System,99",
    ])
    events = body(run(DetectionCsvParser(), path)[0])
    assert len(events) == 1
    assert "chainsaw" in events[0].tags
    assert "Suspicious Service" in events[0].title


def test_the_summary_breaks_down_by_level(tmp_path: Path):
    path = write(tmp_path, "hits.csv", [
        HAYABUSA,
        "2025-09-01 08:47:30 +00:00,A,high,WS01,Sec,1,1,x,r.yml,Execution",
        "2025-09-01 08:48:30 +00:00,B,low,WS01,Sec,2,2,y,r.yml,Execution",
    ])
    events, _ctx = run(DetectionCsvParser(), path)
    summary = [e for e in events if e.event_type == "artifact_summary"]
    assert len(summary) == 1
    assert summary[0].data["levels"] == {"high": 1, "low": 1}


def test_the_record_cap_is_honoured(tmp_path: Path):
    rows = [f"2025-09-01 08:4{i % 10}:30 +00:00,R{i},low,WS01,Sec,1,{i},d,r.yml,T"
            for i in range(40)]
    path = write(tmp_path, "hits.csv", [HAYABUSA, *rows])
    events, ctx = run(DetectionCsvParser(), path, max_records=5)
    assert len(body(events)) <= 6
    assert any("record cap" in h for h in ctx.hints)
