# Changelog

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
