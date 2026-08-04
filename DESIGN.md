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

## An event has to say what happened

`title` is the noun phrase, `details` is the evidence, `extra_fields` is whatever
the template did not claim. That split exists because the alternative was measured:
one `message` string, 418,514 rows of which read `windows event` and nothing more.

The cause was a capture allow-list. `evtx.py` read every field out of each record
and kept 25 names, then built its message from a second hardcoded list of ten. Real
evidence has 200+ providers, so for most of them the parser did the work and threw
the result away. **A parser must never discard a field it already parsed** — bound
it (`_MAX_DATA_KEYS`, `_MAX_VALUE_CHARS`) and mark `_truncated`, but do not filter
by name.

`details.py` renders in three tiers and `build_details` asserts that none of them
returns empty:

1. a curated `EVENT_TEMPLATES` entry — labels chosen by a human
2. no template — every field, labelled with its **raw Windows name**
3. no fields at all — provenance and the reason, never a bare noun

Tier 2's raw labels are deliberate, not a shortcut. The label style is how the
analyst tells the two apart: `TgtUser:` means the tool understood the event,
`TargetUserName:` means it is only transcribing one. A tool that dresses tier 2 up
as tier 1 is claiming coverage it does not have.

The separator is `¦` (U+00A6), not `|`, because `markdown_report` escapes pipes and
would put a backslash in every row of the writeup.

Levels are `crit/high/med/low/info`, with `sev_rank` denormalized so a min-level
filter is indexable. Five, not three, because `low` (recognized and routine) and
`info` (noise or unrecognized) answer different questions — `count(level > info)` is
a free measure of how much was actually understood. The three older names kept their
spellings so every existing filter and test survived the change.

Only `EVTX_MAP` may assign `high` or `crit`. `EVENT_TEMPLATES` is researched rather
than reviewed, and it carries 74 entries marked high or critical; applying those
verbatim is the same mistake as the `_family()` fallback below, so
`_RESEARCH_TO_LEVEL` caps the whole table at `med`.

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

## A collector takes everything; not all of it is evidence

`evidence.py` answers one question: could an intruder's trace be in this file?

A UAC run over one Ubuntu host produced 4,171 files of which **3,183 were "parsed"** —
nearly all `/etc/apparmor.d/abstractions/*`, `/etc/alternatives/README` and XML
schemas, each turned into a one-event row by the text parser.

Skipping `/etc` wholesale would have been wrong, and the case that prompted this proves
it: the entire answer was a commented-out `#security:` line in `/etc/mongod.conf`.
Configuration *is* evidence. The workable distinction is whether a change would be
visible against the package baseline — `/usr/lib/systemd/system` ships identically on
every host, `/etc/systemd/system` is where an attacker drops a unit.

Evidence outranks noise unconditionally. `/etc/apparmor.d/local/usr.sbin.sshd` is
noise; `/etc/ssh/sshd_config` is not, though both are configuration under a noisy
directory.

**One definition, two consumers.** The parser that would otherwise consume these files
and the reporter that would otherwise list them import the same predicate. They briefly
had separate copies, and the reporter's listed `/etc/cron.d/` as noise — which would
have hidden cron persistence. Two copies of a judgement drift, and the drift shows up
as a file quietly parsed one way and reported another.

## Aggregate the flood, not its droplets

Three parsers now face the same shape, and it is worth naming because getting it wrong
is the failure this project keeps repeating.

A MongoDB log held 37,630 `Connection accepted` records from one address in 74 seconds —
75,260 of 75,597 records were connection churn. The finding is the burst; no single
connection is one. So connections are emitted at `info` for timeline completeness and
the flood becomes **one** `high` event carrying the rate. Rating each connection would
bury the finding under its own evidence, which is exactly how a `high` tier of 41 events
came to be 41 false positives.

The same reasoning drives `rarity.py`'s burst detection and the registry parser's
handling of RunMRU. **Emit the components at `info`; synthesize the finding once.**

A bodyfile is the inverse case and gets the opposite treatment. It is mostly the
operating system, so almost everything stays `info` — but nothing is filtered out,
because `timeline.csv` is complete by contract. Volume is managed by *grouping the four
MACB timestamps by value* rather than by dropping rows: one event per distinct time
instead of four per entry, which on 145,000 entries is the difference between ~290,000
rows and 580,000 of which three quarters are duplicates.

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

The FTS index covers `message`, `extra_fields` and `raw`, deliberately **not**
`data`. `data` is a JSON re-encoding of text those three already cover, and
indexing it cost 336 MB of duplicate index on one real case.

There are two CSV exports, not one filtered one:

- `<case>-triage.csv` at `min_severity="med"` — what gets opened
- `<case>-timeline.csv` — everything

Filtering a file named `timeline.csv` would be the more elegant design and the wrong
one. An analyst greps that file expecting it to be complete; if it silently omits
`low` and `info` they find nothing and conclude the activity never happened. On the
real KAPE case the two files are 31,362 and 797,969 rows, which is exactly why
neither one alone works. Export streams rather than materializing rows, and the raw
`data` JSON is not a CSV column — Excel truncates a cell at 32,767 characters, and
losslessness lives in the JSONL export and the database.

`coverage()` and `top_unrecognized()` back a per-channel recognition rate printed
every run. A channel at 0% is a missing template, and saying so is the difference
between a coverage gap and an apparent absence of activity.

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

A registry key holds several values and usually only one of them is the answer, so
`value_names` restricts which may answer, best first — `TimeZoneInformation` also
carries `StandardName` and `DaylightName`, unresolved MUI references on a real host,
and the `ComputerName` key has a `(Default)` value that held `mnmsrvc`. Without that
restriction the tool offered `@tzres.dll,-161` as the timezone and `mnmsrvc` as the
hostname, both at the same confidence as the truth, and the real timezone answer was
pushed off the end of the list.

`exclude` drops values that are never the answer whatever the tally says. Loopback is
the case that matters: 61 local logons from `::1` outvoted 2 real remote failures
under `prefer="most_common"`, so the attacker's IP was reported as the victim's own
machine at 0.70.

The rule behind both: **a confident wrong answer is worse than no answer.** The
analyst has nothing to tell it apart from a right one, which is the same reasoning
that closed the `_family()` fallback above.

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

On the Linux side, `wtmp`/`btmp`/`lastlog` and systemd journals are the gap. Both are
binary formats and both answer "who logged in", which currently has to come from
`auth.log` alone.

**Validation is the standing debt.** Every measurement in this file except the UAC
numbers comes from one Windows collection whose heuristics were tuned against it, with
the incident time supplied. `tests/test_score.py` asserts that incident's literal strings
and is a regression guard, not evidence. The one held-out test so far — a Linux Sherlock
nobody had finished — found two real misconfigurations unprompted, and also exposed that
three of the four "fixes" made for it were treating symptoms. That ratio is the argument
for scoring against HTB Sherlocks with published answers and Atomic Red Team's command
corpus, neither of which this has been run against.

Templates are the other axis, and the coverage block says where to spend the
effort — it ranks the unrecognized event IDs by volume, so the next template to
write is the top line of it rather than a guess. `SentinelOne/Operational`,
`StorageManagement`, `Application` and `SmbClient` measured 0.0% on the real case.
