# Design

Notes for anyone changing the code. The README covers using it.

## The shape

```
evidence/  ·  sherlock.zip  ·  KAPE .vhdx
      |
   analyze.py ── the only orchestration; one call does the whole case
      |
      +-- engine.py    fingerprint by magic bytes, route to a parser, stream events
      +-- diskimage.py open VHDX/E01/VMDK, pull out the parseable files
      +-- infer.py     derive timezone / year / host FROM the evidence
      +-- detect/      YARA over bytes, Sigma over normalized events
      +-- ioc.py       indicators, linked back to the events they came from
      +-- sherlock.py  question -> ranked candidate answers
      +-- store/       per-case SQLite + FTS5
      |
   cli.py ── renders it. The only module allowed to print.
```

Everything under `cli.py` returns typed objects. That is what makes the whole
pipeline usable from a script or a test without capturing stdout.

## Event: the one currency

Every parser emits `Event` (see `models.py`). Nothing else crosses the boundary.
That is what makes a cross-artifact timeline and a single search index possible,
and why adding a format never touches the engine.

Times are stored twice: `ts` as UTC ISO8601 for reading, `ts_epoch` as
microseconds for sorting. `(ts_epoch, id)` is the canonical order, so "the *first*
such event" is answerable — which matters because half the Sherlock questions are
phrased that way.

## Two-pass ingest, and why

Classic syslog records neither the year nor the UTC offset. Asking the analyst for
both is what the tool used to do, and it was lazy: the same evidence set usually
answers the question itself.

So `Engine.plan()` splits the evidence in two. Formats that date themselves are
parsed first. `infer.derive()` then reads the store — registry
`TimeZoneInformation` for the offset, `ComputerName` for the host, the newest
absolute event timestamp for the year — and only then are the ambiguous files
parsed with that context.

A parser opts into the second pass with `needs_time_context = True`.

Two rules this depends on:

- The year anchor excludes `linux_syslog` (it would feed on its own output) and
  excludes `yara`/`sigma` and anything timestamped from a file's mtime, because
  those record when the *tool* ran, not when anything happened. Getting this wrong
  once stretched the reported activity window to "today".
- Every inferred value carries a human-readable source string, and the CLI prints
  it. An invisible inference that shifts a timeline is worse than a wrong one you
  can see.

## Disk images

`diskimage.py` handles VHDX/VHD/E01/VMDK/QCOW2. These belong beside the archive
handling in `open_evidence()`, not in a parser: a container yields *files*, and a
parser yields events.

`dissect.target.container.open()` identifies the container, `volume.open()` finds
partitions (falling back to treating the stream as one bare volume, which is what
some collection tools write), and `NtfsFilesystem` walks it.

Extraction is **selective**. A real KAPE VHDX held 1482 files of which 258 had a
parser; copying the rest out would have burned gigabytes for nothing. What was
skipped is counted by extension and reported, so the analyst sees the coverage gap
instead of an unexplained gap in the timeline. In-image paths get the same
traversal check as archive members, and NTFS internals (`$LogFile`, `$Bitmap`, …)
are skipped by name — but `$MFT` and `$Extend` are not, because they are real
evidence and will be picked up as soon as a parser claims them.

## An event ID means nothing without its provider

`EVTX_MAP` is keyed on `(family, EventID)` and `_family()` returns `"other"` for
anything it does not recognize. That matters more than it looks.

It used to fall back to `"system"`. On a real collection, 215 distinct providers
landed in that bucket, so every one of them emitting EventID 104 was reported as a
high-severity "audit log cleared" — 9,726 false positives, none of them from the
Eventlog service. The real sources were StateRepository, an EDR agent, and a
handful of storage drivers, all of which use 104 for something else entirely.

Nine thousand confident falsehoods is worse than no detection: it teaches the
analyst to ignore the tool. So the families are closed sets, `_SYSTEM_PROVIDERS`
lists who legitimately owns the System-channel IDs, and unmapped providers get a
neutral `windows_event` label with their channel preserved in `data`.

## Parser contract

`sniff -> parse -> yield`, and that is all. See `parsers/base.py`.

- `sniff()` runs for every parser on every file, so it must be cheap and import
  nothing optional. Magic bytes beat the engine's sniffed kind, which beats a
  filename pattern.
- `parse()` is a generator. A single Security.evtx holds well over a million
  records; it must stream.
- **Import optional dependencies lazily, inside `parse()`.** Every plugin module
  is imported so its `@register` runs, so a top-level `import dissect...` breaks
  discovery on a stdlib-only install.
- A missing dependency calls `ctx.hint()` and returns. It never raises. The
  analyst gets the pip command and the rest of the case still lands.

Adding a parser is one file in `parsers/plugins/`. The loader auto-imports it.

## Store

One SQLite database per case, and evidence is never written to — artifacts are
opened `rb` and hashed.

The performance shape that matters: bulk `executemany` against a bare table, then
`finalize()` builds the indexes and the FTS index once. Maintaining them across a
100k-row insert dominates the cost otherwise. FTS5 is probed at startup and
degrades to a bounded `LIKE` scan on builds that lack it.

Queries are parameterized, always. Filter values come out of the evidence —
usernames, paths, hostnames found inside artifacts — so interpolation would be an
injection path from the artifacts themselves.

## Hostile input

Sherlock packages and real incident evidence contain zip bombs, traversal paths,
truncated archives, and files that expand to gigabytes. So: caps on file count,
read size and events per artifact, all module constants in `engine.py` rather than
buried; entry and size limits checked *before* extraction writes anything;
`filter="data"` on tarballs with a fallback for pre-3.12; and per-artifact
isolation so one bad file is recorded as `error` and the case continues.

Evidence-derived text is wrapped in `rich.text.Text` before display. A command
line containing `[...]` would otherwise be parsed as a style tag — mangling the
value and letting the artifact influence terminal rendering.

## Detections

YARA scans artifact bytes. Sigma runs as a post-ingest analytic over normalized
events.

Sigma support is a **documented subset**: field/value maps, the common modifiers
(`contains`, `startswith`, `endswith`, `re`, `all`, `base64`, `windash`, `cased`),
and `and`/`or`/`not`/`1 of`/`all of` conditions. Aggregations are not supported and
such rules are **skipped with a hint**. That is deliberate — a silently
mis-evaluated detection rule reads as "no hits" on a compromised host, which is
the worst possible failure mode.

Adding detections means adding rule files, not code.

## Answers

`sherlock.py` maps a question to the field that probably holds the answer, then
formats it the way HTB expects: UTC `YYYY-MM-DD HH:MM:SS`, uppercase hashes, bare
integers, exact paths. Wrong formatting fails a correct answer.

Each rule lists *several* candidate field names, because the same fact lands under
different keys depending on the parser — a command line is `cmdline` from EVTX but
`cmd` from sudo, and a rule that knows only one of them silently answers nothing.

Ranking is by how unambiguous the evidence is: one distinct value scores higher
than one of forty. Nothing is ever submitted.

## Not here on purpose

- **No interactive REPL.** Four commands, one of which does everything.
- **No integration with other tools.** It bundles its own ATT&CK data and owns its
  own formats.
- **Few flags.** Anything the tool can derive from the evidence, it derives. A flag
  is an admission that it could not.

## Roadmap

Parsers, in rough order of value: `$MFT` and `$J`, prefetch, shimcache, LNK and
jump lists, SRUM (exfil byte counts), browser history, PCAP, scheduled-task XML,
memory via Volatility 3, cloud logs (CloudTrail, M365 UAL), WMI, email.

Each is one file in `parsers/plugins/`.

Prefetch and LNK are the highest-value next two: a KAPE collection is largely
made of them (516 and 477 files in the one measured), and today they are
extracted-and-skipped rather than parsed.
