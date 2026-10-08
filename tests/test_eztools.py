"""Tests for the EZTools CSV family — what KAPE's modules write.

Headers here are the real column rows from EZTools output, not invented ones,
because the whole parser hangs off them: these CSVs are claimed on their columns
and never on their filenames, so a wrong column name means a silently unparsed
artifact rather than a failure.

The disambiguation tests are the ones that matter. LECmd and JLECmd's
AutomaticDestinations export share most of their columns, and PECmd's main output
and its Timeline variant both describe program execution — if the wrong spec wins,
the rows still parse and the events are simply wrong, which is the failure mode
nobody notices.
"""
from __future__ import annotations

from datetime import timezone
from pathlib import Path

import pytest

from inspecthor.models import ParseContext
from inspecthor.parsers.plugins.eztools import (
    EZToolsCsvParser, flatten_payload, group_times, match_spec, parse_timestamp,
    score_row, subject_of,
)

# ---- real EZTools headers ----------------------------------------------------

MFT = ("EntryNumber,SequenceNumber,InUse,ParentEntryNumber,ParentSequenceNumber,"
       "ParentPath,FileName,Extension,FileSize,ReferenceCount,ReparseTarget,"
       "IsDirectory,HasAds,IsAds,SI<FN,uSecZeros,Copied,SiFlags,NameType,"
       "Created0x10,Created0x30,LastModified0x10,LastModified0x30,"
       "LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,LastAccess0x30,"
       "UpdateSequenceNumber,LogfileSequenceNumber,SecurityId,ObjectIdFileDroid,"
       "LoggedUtilStream,ZoneIdContents")

USN = ("Name,Extension,EntryNumber,SequenceNumber,ParentEntryNumber,"
       "ParentSequenceNumber,ParentPath,UpdateSequenceNumber,UpdateTimestamp,"
       "UpdateReasons,FileAttributes,OffsetToData,SourceFile")

PECMD = ("Note,SourceFilename,SourceCreated,SourceModified,SourceAccessed,"
         "ExecutableName,Hash,Size,Version,RunCount,LastRun,PreviousRun0,"
         "PreviousRun1,PreviousRun2,PreviousRun3,PreviousRun4,PreviousRun5,"
         "PreviousRun6,Volume0Name,Volume0Serial,Volume0Created,Directories,"
         "FilesLoaded,ParsingError")

PECMD_TL = "RunTime,ExecutableName"

LECMD = ("SourceFile,SourceCreated,SourceModified,SourceAccessed,TargetCreated,"
         "TargetModified,TargetAccessed,FileSize,RelativePath,WorkingDirectory,"
         "FileAttributes,HeaderFlags,DriveType,DriveSerialNumber,VolumeLabel,"
         "LocalPath,CommonPath,TargetIDAbsolutePath,TargetMFTEntryNumber,"
         "TargetMFTSequenceNumber,MachineID,MachineMACAddress,TrackerCreatedOn,"
         "ExtraBlocksPresent,Arguments")

JLECMD_AUTO = ("SourceFile,SourceCreated,SourceModified,SourceAccessed,AppId,"
               "AppIdDescription,DestListVersion,LastUsedEntryNumber,EntryNumber,"
               "CreationTime,LastModified,Hostname,MacAddress,Path,"
               "InteractionCount,PinStatus,TargetCreated,TargetModified,"
               "TargetAccessed,FileSize,RelativePath,WorkingDirectory,LocalPath,"
               "CommonPath,TargetIDAbsolutePath,MachineID,Arguments,Notes")

EVTXECMD = ("RecordNumber,EventRecordId,TimeCreated,EventId,Level,Provider,"
            "Channel,ProcessId,ThreadId,Computer,ChunkNumber,UserId,"
            "MapDescription,UserName,RemoteHost,PayloadData1,PayloadData2,"
            "PayloadData3,PayloadData4,PayloadData5,PayloadData6,ExecutableInfo,"
            "HiddenRecord,SourceFile,Keywords,ExtraDataOffset,Payload")

SHIMCACHE = ("ControlSet,CacheEntryPosition,Path,LastModifiedTimeUTC,Executed,"
             "Duplicate,SourceFile")

AMCACHE = ("ApplicationName,ProgramId,FileKeyLastWriteTimestamp,SHA1,"
           "IsOsComponent,FullPath,Name,FileExtension,LinkDate,ProductName,Size,"
           "Version,ProductVersion,LongPathHash,BinaryType,IsPeFile,"
           "BinFileVersion,BinProductVersion,Usn,Language,Description")

RBCMD = "SourceName,FileType,FileName,FileSize,DeletedOn"

SBECMD = ("BagPath,Slot,NodeSlot,MRUPosition,AbsolutePath,ShellType,Value,"
          "ChildBags,CreatedOn,ModifiedOn,AccessedOn,LastWriteTime,MFTEntry,"
          "MFTSequenceNumber,ExtensionBlockCount,FirstInteracted,LastInteracted,"
          "HasExplored,Miscellaneous")

RECMD = ("HivePath,HiveType,Description,Category,KeyPath,ValueName,ValueType,"
         "ValueData,ValueData2,ValueData3,Comment,Recursive,Deleted,"
         "LastWriteTimestamp,PluginDetailFile")

WXTCMD = ("Id,Executable,DisplayText,ContentInfo,Payload,ClipboardPayload,"
          "StartTime,EndTime,Duration,LastModifiedTime,ExpirationTime,"
          "CreatedInCloud,ActivityType,IsLocalOnly,ETag,PackageIdHash")


def cols(header: str) -> list[str]:
    return header.split(",")


def write(tmp_path: Path, header: str, rows: list[str], name="out.csv") -> Path:
    path = tmp_path / name
    path.write_text("\n".join([header, *rows]) + "\n", encoding="utf-8")
    return path


def run(path: Path, **kw):
    ctx = ParseContext(evidence_root=path.parent, **kw)
    return list(EZToolsCsvParser().parse(path, ctx)), ctx


def payload_events(events):
    return [e for e in events if e.event_type != "artifact_summary"]


# ---- which spec wins ---------------------------------------------------------


@pytest.mark.parametrize("header,expected", [
    (MFT, "mftecmd_mft"), (USN, "mftecmd_j"), (PECMD, "pecmd"),
    (PECMD_TL, "pecmd_timeline"), (LECMD, "lecmd"), (JLECMD_AUTO, "jlecmd_auto"),
    (EVTXECMD, "evtxecmd"), (SHIMCACHE, "appcompatcache"),
    (AMCACHE, "amcache_files"), (RBCMD, "rbcmd"), (SBECMD, "sbecmd"),
    (RECMD, "recmd"), (WXTCMD, "wxtcmd_activity"),
])
def test_every_real_header_matches_its_own_spec(header, expected):
    matched = match_spec(cols(header))
    assert matched is not None, f"{expected} header matched nothing"
    assert matched[0].name == expected


def test_jumplists_are_not_mistaken_for_lnk_files():
    """They share most of their columns. AppId and DestListVersion are the only
    separation, and getting it wrong mislabels every row without failing."""
    assert match_spec(cols(JLECMD_AUTO))[0].name == "jlecmd_auto"
    assert match_spec(cols(LECMD))[0].name == "lecmd"


def test_the_pecmd_timeline_does_not_outrank_the_full_export():
    """Both describe execution; the full export carries RunCount and the hash."""
    assert match_spec(cols(PECMD))[0].name == "pecmd"


def test_an_unrelated_csv_matches_nothing():
    """KAPE's own copy log is a CSV. So is half the evidence on a real case."""
    header = ("CopiedTimestamp,SourceFile,DestinationFile,FileSize,"
              "SourceFileSha1,DeferredCopy")
    assert match_spec(cols(header)) is None


def test_the_parser_claims_only_recognised_exports(tmp_path: Path):
    known = write(tmp_path, RBCMD, ["$IA1B2C3,File,C:\\x\\a.exe,100,2025-09-01 08:00:00"])
    other = write(tmp_path, "a,b,c", ["1,2,3"], name="other.csv")
    parser = EZToolsCsvParser()
    assert parser.sniff(known, b"", "text") == parser.CONF_MAGIC
    assert parser.sniff(other, b"", "text") == 0.0


def test_a_non_csv_is_never_claimed(tmp_path: Path):
    path = tmp_path / "notes.txt"
    path.write_text(RBCMD + "\n")
    assert EZToolsCsvParser().sniff(path, b"", "text") == 0.0


# ---- timestamps --------------------------------------------------------------


def test_dotnet_seven_digit_fractions_parse():
    """EZTools writes 7 fractional digits; strptime accepts at most 6."""
    parsed = parse_timestamp("2025-09-01 08:47:30.9732590")
    assert parsed is not None
    assert parsed.year == 2025 and parsed.second == 30
    assert parsed.tzinfo is not None


def test_a_naive_timestamp_is_read_as_utc():
    assert parse_timestamp("2025-09-01 08:47:30").tzinfo == timezone.utc


def test_an_explicit_offset_is_honoured():
    parsed = parse_timestamp("2025-09-01T08:47:30+02:00")
    assert parsed.utcoffset().total_seconds() == 7200


def test_empty_and_placeholder_values_are_not_timestamps():
    for value in ("", "   ", "-", "0"):
        assert parse_timestamp(value) is None


def test_the_ntfs_epoch_is_rejected():
    """An unset $SI time comes through as 1601 and is not evidence."""
    assert parse_timestamp("1601-01-01 00:00:00") is None


# ---- event volume ------------------------------------------------------------


def test_identical_timestamps_collapse_into_one_event():
    """An MFTECmd row has eight time columns. A file written once has the same
    value in several of them, and emitting each turns 139,000 rows into a
    million events, three quarters of them repeats."""
    spec = match_spec(cols(MFT))[0]
    same = "2025-09-01 08:00:00"
    row = {"created0x10": same, "lastmodified0x10": same,
           "lastrecordchange0x10": same, "lastaccess0x10": "2025-09-02 09:00:00"}
    grouped = group_times(row, spec)
    assert len(grouped) == 2
    assert "/" in grouped[0][1], "collapsed times must say what they all mean"


def test_a_row_with_no_usable_time_is_counted_not_dropped_silently(tmp_path: Path):
    path = write(tmp_path, RBCMD, ["$IX,File,C:\\a.txt,10,"])
    events, ctx = run(path)
    assert payload_events(events) == []
    assert any("no usable timestamp" in h for h in ctx.hints)


# ---- EvtxECmd ----------------------------------------------------------------


def test_an_evtxecmd_row_lands_in_the_shape_sigma_matches(tmp_path: Path):
    """Sigma addresses event_id, channel and data keys. A row that keeps its
    payload as one opaque string is invisible to every rule in the corpus."""
    payload = ('"{""EventData"":{""Data"":[{""@Name"":""Image"",""#text"":'
               '""C:\\\\Windows\\\\Temp\\\\evil.exe""},{""@Name"":""CommandLine"",'
               '""#text"":""evil.exe -enc AAA""}]}}"')
    row = ("1,4688,2025-09-01 08:47:30,4688,Information,Microsoft-Windows-Sysmon,"
           "Microsoft-Windows-Sysmon/Operational,100,200,WS01,1,S-1-5-18,"
           "Process created,admin,,,,,,,,,False,Sysmon.evtx,,0," + payload)
    path = write(tmp_path, EVTXECMD, [row])
    events = payload_events(run(path)[0])
    assert len(events) == 1
    event = events[0]
    assert event.event_id == "4688"
    assert "Sysmon" in event.channel
    assert event.data.get("Image", "").endswith("evil.exe")
    assert "-enc" in event.data.get("CommandLine", "")
    assert event.host == "WS01"
    assert event.user == "admin"


def test_payload_flattening_survives_junk():
    assert flatten_payload("") == {}
    assert flatten_payload("not json") == {}
    assert flatten_payload("{bad") == {}


def test_payload_flattening_pulls_named_data_items():
    raw = ('{"EventData":{"Data":[{"@Name":"TargetUserName","#text":"backdoor"},'
           '{"@Name":"LogonType","#text":"3"}]}}')
    flat = flatten_payload(raw)
    assert flat["TargetUserName"] == "backdoor"
    assert flat["LogonType"] == "3"


# ---- scoring -----------------------------------------------------------------


def test_an_executable_in_a_temp_directory_is_promoted():
    spec = match_spec(cols(SHIMCACHE))[0]
    severity, tags, _why = score_row(
        spec, "C:\\Users\\bob\\AppData\\Local\\Temp\\update.exe", {})
    assert severity == "high"
    assert "unusual_exec_path" in tags


def test_an_ordinary_system_binary_is_not_promoted():
    """A ShimCache is every binary the OS ever saw. If this promotes, triage is
    tens of thousands of rows of Windows."""
    spec = match_spec(cols(SHIMCACHE))[0]
    severity, tags, _why = score_row(spec, "C:\\Windows\\System32\\svchost.exe", {})
    assert severity == "low"
    assert "suspicious" not in tags


def test_a_document_is_not_promoted():
    spec = match_spec(cols(SHIMCACHE))[0]
    assert score_row(spec, "C:\\Users\\bob\\Documents\\report.docx", {})[0] == "info"


def test_a_recycled_executable_is_promoted():
    spec = match_spec(cols(RBCMD))[0]
    severity, tags, _why = score_row(spec, "C:\\Users\\bob\\Desktop\\tool.exe", {})
    assert severity == "med"
    assert "deleted" in tags


# ---- end to end --------------------------------------------------------------


def test_a_prefetch_export_yields_one_event_per_run(tmp_path: Path):
    row = (",C:\\Windows\\Prefetch\\EVIL.EXE-1234.pf,2025-09-01 08:00:00,"
           "2025-09-02 09:00:00,,EVIL.EXE,1234ABCD,100,30,3,2025-09-02 09:00:00,"
           "2025-09-01 10:00:00,2025-09-01 09:00:00,,,,,,C:\\VOL,ABCD,"
           "2025-08-01 00:00:00,,,")
    path = write(tmp_path, PECMD, [row])
    events = payload_events(run(path)[0])
    runs = [e for e in events if e.timestamp_desc.startswith("Program executed")]
    assert len(runs) == 3, [e.timestamp_desc for e in events]
    assert all(e.event_type == "process_exec" for e in runs)
    assert any("EVIL.EXE" in e.details for e in runs)


def test_a_shimcache_export_parses_and_summarises(tmp_path: Path):
    rows = [
        "ControlSet001,0,C:\\Windows\\System32\\cmd.exe,2025-09-01 08:00:00,True,False,SYSTEM",
        "ControlSet001,1,C:\\Users\\b\\AppData\\Local\\Temp\\x.exe,2025-09-01 09:00:00,True,False,SYSTEM",
    ]
    path = write(tmp_path, SHIMCACHE, rows)
    events, _ctx = run(path)
    body = payload_events(events)
    assert len(body) == 2
    assert {e.severity for e in body} == {"low", "high"}
    summary = [e for e in events if e.event_type == "artifact_summary"]
    assert len(summary) == 1
    assert "Rows: 2" in summary[0].details


def test_the_record_cap_is_honoured(tmp_path: Path):
    rows = [f"ControlSet001,{i},C:\\W\\a{i}.dll,2025-09-0{i % 9 + 1} 08:00:00,True,False,S"
            for i in range(50)]
    path = write(tmp_path, SHIMCACHE, rows)
    events, ctx = run(path, max_records=5)
    assert len(payload_events(events)) <= 6
    assert any("record cap" in h for h in ctx.hints)


def test_an_empty_export_degrades_instead_of_raising(tmp_path: Path):
    path = write(tmp_path, RBCMD, [])
    events, ctx = run(path)
    assert events == []
    assert ctx.hints


def test_subject_joins_a_parent_path_and_a_name():
    spec = match_spec(cols(MFT))[0]
    assert subject_of({"parentpath": ".\\Users\\bob", "filename": "a.exe"}, spec) \
        == ".\\Users\\bob\\a.exe"
    assert subject_of({"parentpath": "", "filename": "a.exe"}, spec) == "a.exe"
