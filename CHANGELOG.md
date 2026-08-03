# Changelog

## v0.6.0 — alerts worth reading, and a real rule corpus

v0.5.0 made the timeline readable. It did not make it *prioritised*, and on a real
collection with a confirmed intrusion that difference was everything:

- all **41** events rated `high` on the incident day were false — 25 per-user svchost
  instances Windows creates at every logon, the Realtek audio and SentinelOne tray
  autoruns, Office's updater task
- the entire attack chain sat at `info` and `med`

### Use `--rules`

**inspecthor bundles 6 Sigma rules. SigmaHQ publishes ~3,300.** That gap was the main
reason another tool's alert view looked better, and no amount of severity tuning
closes it:

```bash
mkdir -p ~/sigma-rules && cd ~/sigma-rules
curl -LO https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip
unzip -q sigma_all_rules.zip && rm sigma_all_rules.zip

inspecthor evidence.vhdx --rules ~/sigma-rules
```

Not vendored: the rules are DRL-licensed and change constantly. Keep them off `/mnt/c`
under WSL — 9p charges ~2.4 ms per file for metadata, about 8 seconds of pure `stat`.

### The Sigma engine could not have used that corpus

Three defects, each fatal alone, found by reading the loader against the spec:

- **`Image` did not map to `new_process_name`.** Security 4688 stores the executable
  as `NewProcessName`, Sysmon 1 as `Image`, and **1,299 corpus rules** are
  `category: process_creation` keyed on `Image`. Without Sysmon — most fleets — that
  entire set loaded, evaluated, and reported nothing. Silently, which reads as a clean
  host.
- **`logsource` was parsed, attached to hits, and never consulted.** AWS, Okta, Zeek
  and macOS rules were tested against Windows events, and nothing was constrained to
  its own category or channel.
- **The loop was O(events × rules)** — 2.4 billion selection evaluations.

**184 minutes → 313 seconds** on 797,972 events against 2,935 applicable rules, each
step measured rather than guessed:

| Fix | Why |
|---|---|
| conditions compile once into closures | `eval()` on a string ran **741,328 times** |
| lazy evaluation | `selection and not filter` stopped computing all three |
| per-row field cache | `Image` was resolved 1,458× per event |
| literal prefilter | most rules now die on one substring test; **verified lossless by diffing hits with it disabled** |
| JSON rule cache | 17 s of YAML per run → ~0.1 s. JSON not pickle: a cache must not execute code |
| logsource routing | untargeted rules 185 → 11 |

On the confirmed intrusion the corpus found what the built-in scoring did not:
`nltest /dclist:` domain enumeration 50 seconds before the remote logon, that logon
identified as **NTLMv1** rather than merely NTLM, CodeIntegrity blocking a load into a
protected process, and WebDAV via `rundll32 davclnt.dll,DavSetCookie` to a DC-shaped
host extending the window to 17:58.

### `score.py` — where code lives, not what it is called

The old escalation list was a LOLBin blocklist (`mshta`, `certutil`, `iex`). It
matched nothing, because the implant shipped its own signed `node.exe`. A name
blocklist only catches adversaries whose names are already in it.

Promotes: execution from a user-writable path under a machine-generated directory
name; a script host launching a binary out of one; a package manager pulling a network
transport (`npm install ws` — an implant building its own C2). Host recon
(SecurityCenter2 AV enumeration, MachineGuid, `net session`, `Win32_VideoController`)
scores `low` alone, because inventory software does all of it.

Demotes: per-user svchost services, vendor task paths, routine autoruns. Both
directions matter — promoting real findings into a tier that already cries wolf
changes nothing an analyst notices. A task named `\Microsoft\Windows\…` whose *action*
runs from AppData is still `crit`; the action outranks the name, or the allow-list
becomes the evasion.

Every scored row carries a `why`. A `high` with no stated reason is unauditable.

Result on the incident day: `high` 41 → 5, and those 5 are the attack. Whole case
552 → 32.

### `rarity.py` — what this host has never done before

Every other signal in the tool encodes an attack somebody already described. This one
needs no attack description at all, which is what makes it the answer to "will it
catch the next one":

- **binary rarity** — a binary whose whole lifetime is one short burst
- **parent/child pair rarity** — `powershell.exe → node.exe` happened once ever;
  `explorer.exe → chrome.exe` constantly. The strongest of the three.
- **spawn bursts** — a parent whose entire spawn history is one burst

Measured blind, with severity forced to `info` so only rarity could speak: **all 31
chain events lifted; 591 of 24,475 process events promoted — 2.41%, a 41× narrowing.**

Capped at `med` on purpose. Rarity is a multiplier, not an alarm: a software install is
structurally identical to an intrusion, and the first two attempts at burst detection
flagged 80.97% and then 3.07% of all process events before landing at 2.10%.

### Also

- `Title` and `Details` fall back in `ctx.event()` rather than per parser — 3,723
  registry and text rows had both columns blank, including 8 autoruns at `high`.
- The bundled Sigma rule for EventID 104/1102 had no provider check and fired 205
  times, every hit a `Win32PnpWatcher` notification. That is the same
  unqualified-EventID bug this project already fixed on the parser side and wrote into
  DESIGN.md as costing 9,726 false positives — shipped again from the rule side. Now
  qualified on `Provider_Name`.
- README rewritten as a usage guide: flag tables, a `--rules` walkthrough, how to read
  a row, severity meanings, measured performance, and a gotchas section. Design
  rationale stays in DESIGN.md.

### Honest limits

- Everything above was measured on the one collection these heuristics were tuned
  against, with the incident time supplied. **`tests/test_score.py` asserts that
  incident's literal strings — those are regression guards, not validation.** Held-out
  scoring against HTB Sherlocks and Atomic Red Team is the next task.
- Output is still UTC even when the host timezone is correctly derived. An incident at
  11:50 local appears at 16:55.
- 7 Sigma rules hit the 200-hit cap, so their true counts are unknown; 41 rules fail
  to parse; 3 use modifiers outside the documented subset.
- The case file is 1.9 GB for 798k events, against a ~800 MB design estimate.

Tests 190 → 285.

## v0.5.0 — a timeline an analyst can read

Reported, correctly: "a forensics analyst would not be able to make much of what
inspecthor parsed." Measured on the real 798k-event KAPE collection, the complaint
was worse than it sounded — **418,514 rows had nothing to show but the words
"windows event"**, and 89% of all rows sat in a generic bucket.

**Root cause, and it was mine.** `evtx.py` captured fields from a hardcoded
allow-list of 25 names and built its message from a second hardcoded list of ten.
Real evidence has 200+ providers, so for most of them the parser read every field
out of the record and then threw it away. The data was always there.

**`details.py`** now renders one readable line per event, in Hayabusa's shape
(`Label: value ¦ Label: value`, U+00A6 rather than a pipe because the markdown
report escapes pipes). Three tiers, with an assert that none can return empty:

1. a curated template — `Type: 10 (RemoteInteractive) ¦ TgtUser: jsmith ¦ SrcIP: …`
2. no template — every field, labelled with its **raw Windows name**
3. no fields at all — provenance and the reason, not a bare noun

The label style is the honesty signal: curated labels mean the tool understood the
event, raw Windows names mean it is only transcribing one. Coded values are decoded
in place while keeping the raw value (`Status: 0xC000006A (bad password)`), with
Kerberos status dispatched separately from NTSTATUS since `0x18` means different
things to each.

**252 event templates**, keyed on `(provider, id)`: 247 enumerated across Security,
System, PowerShell, Sysmon, Task Scheduler, RDP, Defender, WinRM and SMB, plus five
written by hand for the highest-volume ids in the measured collection (4673, 4662,
4985, 4670, 10016), none of which had one. Researched levels are **capped at
`med`** — only the curated map may say `high` or `crit`, because applying 74
researched high/critical templates blind is exactly how v0.3 produced 9,726 false
positives.

**Five levels** (`crit/high/med/low/info`), added additively so the previous three
keep their spellings and every existing filter and test kept working. `low` means
recognized-and-routine, `info` means noise-or-unrecognized — which makes
`count(level > info)` a free measure of how much was understood.

**Two output files** instead of one unreadable one:

- `<case>-triage.csv` — level >= med. 31,362 rows on the real collection.
- `<case>-timeline.csv` — everything, 797,969 rows.

Both carry readable columns (`Timestamp, Level, Title, Host, Channel, EventID,
User, Details, …`). The raw `data` JSON column is gone from the CSV: it was the
thing that made the file unreadable, Excel truncates a cell at 32,767 chars, and
losslessness already lives in the JSONL export and the database. The export also
streams now instead of materializing 798k dicts.

**A coverage block** every run: per-channel recognition rate and the top
unrecognized ids as template candidates. A channel at 0% is reported as a gap in
coverage rather than left to look like an absence of activity.

**Also fixed**

- `Title` was blank for 3,723 registry and text rows, because only the EVTX parser
  set one. Falls back to a prettified event type — an empty column in the one place
  an analyst reads was the whole bug.
- FTS indexed `data`, a JSON re-encoding of text already covered by `message` and
  `extra_fields`: 336 MB of duplicate index on this case.
- `EventRecordID` and `channel` are captured and promoted to columns. The record id
  is the only way a report can point at an exact source record; the channel is what
  analysts actually filter on and it was buried inside the JSON.
- `inspecthor timeline` takes `--min-level` and always states what it filtered out.
  Replaces a two-query severity splice that could return fewer rows than `--limit`
  and re-sorted in Python.

**Five confidently wrong answers**

Making the timeline readable also made the answer layer legible enough to audit, and
it was wrong in five places on the same collection. All five share one shape: a
registry key holds several values, only one is the answer, and the tool took
whichever the store returned first. A wrong answer at 0.75 is worse than no answer —
nothing distinguishes it from a right one.

- **Hostname was `mnmsrvc`.** The `ComputerName` key also has a `(Default)` value,
  which held that, and it sorted first. Not just one bad candidate: `infer` took the
  same row, so every run reported `mnmsrvc` as the machine the evidence came from.
  Now `OKIMV1`, and the hostname answer went 0.75 -> 0.85 with the tie gone.
- **Timezone was `@tzres.dll,-161`** — an unresolved MUI resource reference, offered
  at the same 0.44 as a real value. Worse, it and its sibling pushed the actual
  answer, `Central Standard Time`, off the end of the list. `AnswerRule.value_names`
  now restricts which registry value names may answer, best first.
- **The inferred timezone was an hour out, under a source label naming a value it
  had not read.** `Bias` (UTC-06:00) and `ActiveTimeBias` (UTC-05:00) live in that
  same key; the loop returned on whichever came first and labelled it
  `registry ActiveTimeBias` either way. Only `ActiveTimeBias` includes the DST shift
  in force when the evidence was collected, and this offset is what every
  yearless-syslog timestamp is interpreted against. The source string exists so an
  analyst can catch exactly this, and it was the thing lying.
- **The attacker's IP was `127.0.0.1`.** 61 successful logons from `::1`, which
  `normalize_ip` renders as loopback, outvoted 2 real remote failures under
  `prefer="most_common"`. Loopback and the unspecified address are excluded; the
  answer is now the remote address that was actually there.
- **Registry transaction logs produced six errors every run.** On Windows 8+ a
  `.LOG1`/`.LOG2` opens with the same `regf` base block as a hive, so magic-byte
  matching claimed them at full confidence and each one failed. Skipped by name —
  noise in the warning channel teaches the analyst to ignore the warnings that
  matter. dissect.regf cannot replay them, so unflushed hive changes stay invisible.

Verified on the real 2.1 GB KAPE VHDX: 797,969 events, **zero rows with an empty
Details** in either file, zero `(no template)` titles in the triage file, Security
93.9% and PowerShell 99.6% titled. Details run a median of 110 characters in triage
and 346 across the full timeline.

59.5% of the full timeline is still `(no template)`, and it says so — 29,826 of those
are a single unmapped id, `SentinelOne/Operational` 131. That number is the honest
measure of how much work is left, and before this release there was no way to ask
for it.

The case file is 1.9 GB for 798k events, heavier than the ~800 MB the design
estimated. Dropping `data` from the FTS index cut that index from 246 MB to 164 MB,
but populating `title`/`details`/`extra_fields` on every row more than spent the
saving: the `events` table alone is 1.6 GB. Readability was worth it; the storage
shape is not solved.

Tests 130 -> 171.

## v0.4.0 — KAPE collections

Requested: KAPE writes its collections as a VHDX, so point the tool at one.

    inspecthor 2026-07-27T191212_HOSTNAME.vhdx

`diskimage.py` opens VHDX, VHD, E01, VMDK and QCOW2 — a container yields *files*,
so it sits beside the archive handling in `open_evidence()` rather than pretending
to be a parser. It finds the NTFS volume (with or without a partition table) and
walks it. No mounting, no elevation, no extracting first.

Extraction is **selective**: a real KAPE VHDX held 1482 files, 258 of which had a
parser, so copying the rest out would have burned gigabytes for nothing. What was
left behind is counted and reported — `left behind 516 .pf, 477 .lnk — no parser
for those yet` — so a coverage gap reads as a coverage gap rather than a quiet hole
in the timeline. In-image paths get the archive-member traversal check, and NTFS
internals are skipped by name (`$MFT` and `$Extend` deliberately excluded from that
list: they are evidence, and will be parsed as soon as a parser claims them).

**Two bugs that only a real collection could have found.**

- **9,726 false high-severity findings.** `_family()` fell back to `"system"` for
  any unrecognized provider, so anything emitting EventID 104 was reported as
  "audit log cleared". 215 distinct providers landed in that bucket; not one of the
  9,726 events came from the Eventlog service — they were StateRepository, an EDR
  agent, and assorted storage drivers, all of which use 104 for something else. An
  event ID means nothing without its provider. The families are closed sets now,
  `_SYSTEM_PROVIDERS` names who owns the System-channel IDs, and unmapped providers
  get a neutral `windows_event` label. High-severity events on that collection fell
  from 9,891 to 165, with every genuine detection kept: service installs still
  resolve from both Security-Auditing 4697 and Service Control Manager 7045,
  start-mode changes from SCM, shutdowns from User32.
- **The "what stands out" panel showed one finding 25 times.** 105 of the 165 real
  high-severity events were service installs, which crowded out the
  Defender-disabled and Run-key entries entirely. It now shows a few of each kind
  and states the true total, because five kinds of activity tell you more than one
  kind five times. Padding the list back up with the type that was capped was the
  first attempt and recreated the problem — a test catches that.

Also: `diskimage` capability listed in `tools`, disk-image signatures added to the
fingerprint table so a stray image inside an evidence folder is named rather than
called 'binary', and dev scratch scripts (`_*.sh`, `_*.py`) are now gitignored.

Verified against a real 2.1 GB KAPE VHDX: 258 files extracted (917 MB), 256
parsed, 797,969 events, timezone read from the registry as UTC-06:00 and the
computer name likewise — the inference working on genuine evidence rather than a
fixture.

Tests 112 -> 130.

## v0.3.2 — ready to be public

The repository went public, so: an audit for anything that should not be, plus the
things a stranger reasonably expects.

- **NOTICE with MITRE attribution.** The bundled ATT&CK data is a derivative of
  MITRE's STIX dataset, and redistributing it requires attribution. The trademark
  notice, permission statement and a link to the ATT&CK Terms of Use are now in
  NOTICE and summarized in the README. NOTICE also lists the licenses the optional
  extras pull in — several are copyleft, which matters to anyone bundling this into
  a container or a PyInstaller build.
- **`install.sh` was committed mode 644**, so `./install.sh` — the command the
  README gives you — failed on a fresh clone. Now 755.
- **`requires-python = ">=3.10"` was not true of the test suite**, which imported
  `tomllib` (3.11+). Guarded, so the claim holds.
- **CI** (`.github/workflows/tests.yml`): the suite on 3.10 through 3.13 for a bare
  install, all extras on 3.10 and 3.13, a check that no optional dependency leaks
  into the bare install, a check that every capability is available with `[full]`,
  and an end-to-end job that analyzes generated evidence and asserts the report
  contains the inferred year and the findings. The status badge is in the README —
  on a public repo it is the fastest way for a reader to see the suite is real.
  The first run passed on all four Python versions, which is what finally verified
  the >=3.10 claim empirically rather than by inspection.

Audited and clean: no credentials, internal hostnames, employer references or
personal paths anywhere in the history or the tree; every commit authored by the
GitHub noreply address; nothing generated or private tracked (45 files, 1.7 MB).

## v0.3.1 — case files no longer collide or accumulate

Reported: "it saves the case as a .db — how does it decide what to name it?
Worried about overwrites." The worry was justified, and the real failure was worse
than an overwrite.

- **Re-analyzing the same evidence duplicated everything.** Artifacts were
  idempotent but events were plain inserts, so a second run took a 3-event case to
  6 and a third to 9 — silently doubling the event count, the indicators and the
  timeline. Nothing was overwritten; it accumulated. A run now replaces the
  previous analysis of the same evidence and says so. The case file holds only
  derived data, so re-deriving it is safe and is the only correct answer.
- **Unrelated cases merged into one file.** The name comes from the evidence path,
  so two Sherlocks that both unpack to a folder called `evidence` shared one
  `evidence.db` — a single case containing both intrusions, which would answer
  questions with the wrong data. Sherlock packages are full of folders named
  `evidence`, `artifacts` and `logs`, so this was likely rather than theoretical.
  The evidence source is now recorded in the case, a run only reuses a file that
  belongs to the same evidence, and anything else takes the next free suffix
  (`evidence-2.db`) with the reason printed.
- The report and timeline follow the de-conflicted name instead of overwriting a
  sibling case's outputs.
- A file that is not one of its own cases — including something that is not even
  SQLite — is never touched.
- Added `--name` so the case and its files can be named directly.
- README now documents what gets written, where, and both collision rules.

Tests 107 -> 112.

## v0.3.0 — one command

Reworked on direct feedback: the tool was a toolkit when it should have done the
work. Getting value out of a Sherlock took five commands, there were 75 flags to
learn, the docs read like design notes, and it was coupled to another project.

**One command does everything.**

    inspecthor sherlock.zip

Unpack, route every file to a parser, derive the case context, run YARA and Sigma,
sweep indicators, find the question file the package shipped with, answer it, write
the report. No flags. `analyze.py` is the whole orchestration; there is no useful
state between those steps, so there is no reason to make anyone drive them.

**It works out what it used to ask for.** Classic syslog records no year and no UTC
offset — but the rest of the evidence usually does. Event logs carry absolute UTC
timestamps, and the registry records `TimeZoneInformation` and `ComputerName`. So
ingest runs in two passes: everything that dates itself first, then `infer.py`
derives timezone, year and host from that, and only then are the ambiguous files
read. `--year`, `--tz` and `--host` still exist as overrides, and every derived
value is displayed with its source, because an invisible inference that shifts a
timeline is worse than a wrong one you can see.

**Four commands, down from 22.** `inspecthor <evidence>`, plus `ask`, `find` and
`timeline` for following up. The REPL and the other 18 verbs are gone. Follow-up
commands locate the case file themselves, so `--db` is gone too. A bare path is
treated as `analyze <path>`. A test asserts the surface stays this size.

**Matrix coupling removed.** No interop module, no `export matrix`, no
sibling-path ATT&CK lookup, no Navigator layer. The bundled ATT&CK data stays —
that is MITRE's, and it loads with no configuration.

**Docs rewritten.** README is what to type and what comes back. The architecture,
the parser contract and the reasoning moved to DESIGN.md.

**Fixed along the way**

- Windows zone names resolved with the wrong sign: `Eastern Standard Time` became
  UTC+5 instead of UTC-5, a ten-hour error that would have quietly slid a whole
  Linux timeline. Windows' `ActiveTimeBias` and a real UTC offset have opposite
  signs and were being conflated.
- The reported activity window ran to "today" because YARA hits and mtime-anchored
  events record when the tool ran, not when anything happened. Those are now
  excluded from both the window and the year anchor.
- `ask "what command did they run as root?"` returned nothing: the answer rule
  looked only at `cmdline`, while sudo stores the command in `cmd`. Answer rules
  now try several field names, since the same fact lands under different keys
  depending on which parser produced it.
- `iocextract` emits SyntaxWarnings on import under Python 3.13, which landed in
  the middle of reports. Suppressed at the import site.

Tests 97 -> 107 (`test_rework.py` covers the autonomous flow). Passes on a bare
`pip install -e .` with the format-specific tests skipping themselves.

## v0.2.3 — a real install, and two bugs it exposed

Installing with all extras on Kali surfaced two things that only show up outside
a test venv.

- **`[full]` was not full.** It listed `dissect.target` and trusted that to pull
  the format libraries, but `dissect.target` does not depend on `dissect.esedb`,
  so `pip install '.[full]'` left the `ese` capability unavailable while claiming
  to install everything. The dissect format libs are now listed explicitly in both
  `[windows]` and `[full]`, and a test asserts `[full]` is a superset of every
  other extra so this cannot recur.
- **`detect` could never run YARA from the CLI.** The YARA branch was gated on an
  in-memory `evidence_root`, which only exists after an `ingest` in the *same*
  process — so a fresh `inspecthor detect` printed "no evidence root known" and
  recorded zero YARA findings even though every artifact path was in the database.
  Scan targets now come from the artifacts table, and when recorded paths no
  longer exist the count is reported rather than passing for a clean scan.

- Added `install.sh`, mirroring reap's: a project-local `.venv` by default or
  `--pipx` for a global command, with `--full`/`--windows`/`--detect`,
  `--trusted-host` for TLS-intercepting proxies, and `--link` to put the command
  on PATH. Debian-family Pythons are PEP-668 managed, so installing into the
  system interpreter is refused — both modes avoid that.

Verified on Kali WSL (Python 3.13.12): all 9 capabilities available, 97 tests
passing against the real install, and an end-to-end run where YARA caught a
planted webshell (T1505.003), Sigma caught the SSH brute force (T1110.001), and
all four questions in a task file were answered correctly.

Tests 93 -> 97.

## v0.2.2 — document every flag

Reported: the usage examples showed flags with no explanation of what they were
for. An audit found the problem was systemic rather than isolated — **37 of the 75
CLI arguments shipped with no help text at all**, including `path` on `ingest`,
every filter on `timeline`/`search`/`export` except four, and both rule-directory
flags. An undocumented flag is an unusable flag: the only way to find out what it
did was to read the source.

- Help text on all 75 arguments, plus `metavar`s so the usage lines read as
  English (`--since TIME`, `--limit N`, `--yara-rules DIR`) instead of shouting
  the dest name.
- The two rule-directory descriptions are now module constants shared by the REPL
  and the CLI, so the same flag cannot end up described two different ways.
- README gained a complete flag reference: global options, `ingest`, the shared
  filters, and every remaining command flag — with a note on which are worth
  setting and why (`--host` matters because most Linux logs never record one).
- Four tests now walk the real parser objects and assert every argument has help,
  every subcommand has a one-liner, and every REPL verb has a docstring, since
  `help <verb>` prints it. 54 arguments and 22 verbs are covered, so this cannot
  quietly regress.

Tests 89 -> 93.

## v0.2.1 — honour --tz, and explain the time flags

- **`--tz` was accepted and then ignored.** Both entry points hardcoded UTC, so
  `--tz America/Chicago` looked like it worked while every tz-naive syslog line
  stayed at the wrong hour — worse than not offering the flag, because the result
  is confidently wrong rather than obviously missing. It is now wired through to
  the parser and covered by a test that asserts the actual shift.
- `parse_tz()` accepts IANA names, `UTC`, and fixed offsets (`-06:00`, `+0530`),
  and **rejects** anything else instead of falling back to UTC.
- `--year` and `--tz` had no help text on the `ingest` subcommand and no
  explanation anywhere in the README, despite appearing in the usage examples.
  Both are now documented, including why the mtime-based year inference is
  unreliable for repackaged evidence.

Tests 86 -> 89.

## v0.2.0 — the pipeline

End-to-end: evidence in, timeline and candidate answers out.

**Core**

- `models.py` — the normalized `Event` every parser emits, plus `ParseContext`
  (which carries the assumed timezone, caps, the ATT&CK validator, and the
  `hint()` degradation channel), `EventFilter`, and `Fingerprint`.
- `store/` — per-case SQLite. Times stored twice (UTC ISO8601 for reading, epoch
  microseconds for sorting) with `(ts_epoch, id)` as the canonical order so
  "the first such event" is answerable. Bulk `executemany` inserts against a bare
  table; secondary indexes and the FTS5 index build in `finalize()` because
  maintaining them across a 100k-row load dominates the cost. FTS5 is probed at
  init and degrades to a bounded `LIKE` scan when the SQLite build lacks it.
- `engine.py` — magic-byte fingerprinting (registry, EVTX, MFT, SQLite, LNK,
  prefetch incl. `SCCA` at offset 4, pcap/pcapng, archives, PE/ELF/PDF), a
  printable-ratio text fallback, and ingest with per-artifact isolation so one bad
  file never aborts a case. Zip-bomb and traversal guards, file/size/record caps,
  and the HTB archive passwords tried automatically.
- `query.py` — timeline and search over parameterized SQL only. Filter values come
  from evidence, so interpolation would be an injection path from the artifacts.
- `ioc.py` — stdlib indicator regexes with defang handling. Noisy indicators are
  tagged `private`/`allowlisted`, never dropped, and every hit links back to its
  source event.
- `reporter.py` — rich tables, a markdown case report, and exporters for CSV,
  JSONL, plaso l2tcsv (17 fixed columns), and Timesketch.

**Parsers** — a `@register` + `pkgutil` backbone where dropping a decorated file
into `parsers/plugins/` is the whole extension story:

- `linux_syslog` (stdlib) — SSH brute-force→success correlation, sudo, account
  creation, rotated and compressed logs. Infers the year syslog omits, and records
  that the timezone was assumed.
- `generic_text` (stdlib) — timestamped log lines, Apache/nginx, and a fallback so
  an untimestamped file still reaches search and the IOC sweep.
- `evtx` (`[evtx]`) — mapping keyed on `(channel family, EventID)` so Sysmon 1 and
  Security 4688 do not collide; suspicious command lines upgrade both technique
  and severity.
- `registry` (`[registry]`) — Run keys, services, timezone, computer name, USB,
  UserAssist (ROT13), RDP history, amcache, with a `regipy` fallback.

**Detection, interop, answers**

- `detect/` — YARA over artifact bytes and a documented Sigma subset evaluated
  in process. Unsupported Sigma syntax is skipped with a hint rather than
  mis-evaluated, because a silently wrong detection reads as "no hits".
- `interop/` — ATT&CK resolution that prefers a co-located Matrix checkout and
  falls back to a bundled copy, with id validation before anything is stored;
  Matrix `case.json` / `.tar.gz` export matching Matrix's own format, and
  Navigator layer output.
- `sherlock.py` — maps a question to the artifact and field that answers it, ranks
  by how unambiguous the evidence is, and formats for HTB. Reads questions
  straight out of a Sherlock task file.
- `capabilities.py` — one place that knows what is installable and prints the
  command that unlocks it.

**Interface** — full `cmd.Cmd` REPL plus matching CLI subcommands that call the
same functions, and `inspecthor_run.py` for one-shot headless triage.

**Fixed**

- Install hints lost their extra name: `[evtx]` was parsed as a rich style tag, so
  the hint read `pip install 'inspecthor'`. Evidence-derived text is now wrapped
  so it can never be interpreted as markup — which also means a command line
  containing `[...]` renders verbatim instead of being partly swallowed.
- Bundled YARA rules used non-capturing groups, which YARA's regex engine rejects;
  one bad rule took the whole ruleset down.
- A mistyped `--since` propagated a `ValueError` out of the REPL instead of
  reporting the problem and returning to the prompt.
- "What account did the attacker create?" was answered by the compromised-account
  rule, because `what account` matched first.

**Tests** — 86 offline tests, no evidence, no network. Passes on a bare install
(extras-dependent tests skip) and on `[full]`.

## v0.1.0 — project skeleton

- Package scaffold with the `parsers/`, `detect/`, `interop/`, `store/`, and
  `data/` subpackages the pipeline is built into.
- PEP-621 packaging: core is stdlib + `rich`; every binary-artifact parser is an
  optional extra so a bare install still runs.
- `inspecthor` console script and `python -m inspecthor`.
- Repo hygiene: MIT license, LF normalization, and a `.gitignore` that keeps
  evidence, case databases, and raw artifacts out of git — Sherlock packages can
  contain live malware.
