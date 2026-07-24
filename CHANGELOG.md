# Changelog

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
