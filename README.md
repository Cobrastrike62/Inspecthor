# inspecthor

```
██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗██╗  ██╗ ██████╗ ██████╗
██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗
██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ███████║██║   ██║██████╔╝
██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██║██║   ██║██╔══██╗
██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ██║  ██║╚██████╔╝██║  ██║
╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

Read-only forensic timeline and artifact analysis for blue teams and HTB Sherlocks.

> Use this only on evidence you are authorized to examine. Sherlock packages and
> real incident artifacts can contain live malware — work in an isolated VM.

You have a folder of evidence and a list of questions. inspecthor fingerprints
every file, routes each to a parser, and normalizes everything into one
time-sorted event store — so "when did the attacker first log in" becomes a query
instead of an afternoon.

```
$ inspecthor --db case.db ingest sherlock.zip --year 2024
$ inspecthor --db case.db sherlock "what is the attacker's IP?"

           Candidate answers — verify before submitting
 conf   what                  answer          from
 0.80   Attacker source IP    45.33.32.156    linux_syslog — ssh_failed_login @ 2024-03-01 09:15:01
```

## Install

```bash
git clone https://github.com/Cobrastrike62/Inspecthor && cd Inspecthor
pip install -e .
```

The bare install is deliberately light — stdlib plus `rich`. It already handles
text, syslog, JSON and SQLite evidence, and the whole pipeline (timeline, search,
IOC extraction, reports, Matrix export) works without a single binary parser.

Binary-artifact parsers are extras. A missing extra prints the command that fixes
it and moves on; it never fails the run:

```
! would parse with evtx — pip install 'inspecthor[evtx]'   # unlocks Windows Event Logs (.evtx)
```

```bash
pip install -e '.[windows]'   # every dissect format lib (EVTX, registry, MFT, ESE)
pip install -e '.[detect]'    # YARA + Sigma
pip install -e '.[full]'      # everything optional
```

| Extra | Unlocks |
|---|---|
| `[evtx]` | Windows Event Logs (`.evtx`) |
| `[registry]` | Registry hives, amcache/shimcache |
| `[ntfs]` | `$MFT`, `$J` USN journal |
| `[ese]` | SRUM / ESE databases (exfil byte counts) |
| `[windows]` | Umbrella for all of the above |
| `[yara]` / `[sigma]` / `[detect]` | Detection overlay |
| `[pcap]` | PCAP / PCAPNG (falls back to a `tshark` probe) |
| `[memory]` | Memory images via Volatility 3 |
| `[ioc]` | Richer IOC extraction than the stdlib regexes |

Run `inspecthor tools` to see what is available and what each missing piece unlocks.

## Usage

```bash
inspecthor                        # interactive console
inspecthor --db case.db ingest /evidence --host WS01 --year 2024
inspecthor --db case.db timeline --severity high
inspecthor --db case.db search 45.33.32.156
inspecthor --db case.db sherlock --readme task.txt
python inspecthor_run.py sherlock.zip --outdir out/ --detect --matrix
```

Every REPL verb has a matching subcommand and they call the same functions, so
scripted and interactive runs cannot drift.

| Command | What it does |
|---|---|
| `ingest <path>` | Fingerprint and parse a folder, a Sherlock `.zip`, or one file |
| `artifacts` | What was ingested, which parser claimed it, how it went |
| `timeline` | The super timeline, filterable by time/host/user/type/severity/tag |
| `search <text>` | One query across every artifact (`--regex` for patterns) |
| `ioc sweep` / `ioc list` | Extract indicators and link them back to their events |
| `detect` | YARA over artifact bytes, Sigma over normalized events |
| `findings` | Detections, worst first |
| `attck [query]` | Observed techniques, ATT&CK search, `--layer` for Navigator |
| `sherlock [question]` | Candidate answers, HTB-formatted (`--readme`, `--overview`) |
| `report [file.md]` | Markdown case writeup |
| `export <what> [file]` | `csv`, `jsonl`, `l2tcsv` (plaso), `timesketch`, or `matrix` |
| `hosts` / `users` / `types` | Facets with counts |
| `parsers` / `tools` / `info` | What is registered, available, and loaded |

Sherlock archives are password-protected; `hacktheblue` and `hackthebox` are
tried automatically so starting a case is one command.

## How it works

```
evidence/  or  sherlock.zip
        |
        v
   engine  ── magic-byte fingerprint, sha256, route  (caps + zip-bomb guards)
        |
        v
   parsers  ── plugins; each yields normalized Events
        |
        v
   store  ── per-case SQLite + FTS5  (bulk insert, indexes built after load)
        |
        +--> timeline      every artifact in one chronological view
        +--> search        one query hits EVTX + registry + logs at once
        +--> ioc           IPs / domains / hashes, linked to source events
        +--> detect        YARA + Sigma findings
        +--> sherlock      candidate answers, formatted for HTB
        +--> export        markdown, CSV, JSONL, Timesketch, plaso l2tcsv, Matrix
```

Every parser emits the same `Event`, which is what makes a cross-artifact
timeline and a single search index possible. Times are stored twice — UTC ISO8601
for reading and epoch microseconds for sorting — and `(ts_epoch, id)` is the
canonical order, so "the *first* such event" is answerable.

Some deliberate choices worth knowing:

- **Evidence is read-only.** Artifacts are opened `rb` and hashed; all derived
  state lives in a separate case database.
- **One bad artifact never aborts a case.** Each file parses inside its own
  guard and is recorded as `error`, so the rest of the evidence still lands.
- **Noisy indicators are tagged, not dropped.** Private ranges and CDN domains
  stay in the store marked `private`/`allowlisted` — sometimes the answer really
  is an internal pivot or an abused legitimate service.
- **Evidence text is never treated as markup.** A command line containing
  `[...]` renders verbatim rather than being parsed as a style tag.

## Extending

Adding an artifact type is one file in `inspecthor/parsers/plugins/`. No engine,
store, or console edits — the registry auto-imports whatever it finds:

```python
from __future__ import annotations
from pathlib import Path
from typing import Iterator
from ...models import Event, ParseContext
from ..base import Parser, register

@register
class PrefetchParser(Parser):
    name, display, category = "prefetch", "Windows Prefetch", "windows"
    magic = (b"MAM\x04",)
    path_globs = ("*.pf",)
    requires = "dissect.target"                    # omit for pure stdlib
    install_hint = "pip install 'inspecthor[windows]'"

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        try:
            import dissect.target                  # lazy: keeps discovery working
        except ImportError:
            ctx.hint(self.install_hint)            # degrade, never raise
            return
        for name, run_time, count in _read(path):
            yield ctx.event(timestamp=run_time, timestamp_desc="Last Run",
                            event_type="process_exec", attck=["T1204"],
                            message=f"{name} executed (run #{count})")
```

Import optional dependencies **inside** `parse()`. Every plugin module is
imported so its decorator runs, so a top-level `import dissect...` would break
discovery on a stdlib-only install.

Detection extends by **rule**, not code: drop a `.yar` into `data/yara/` or a
`.yml` into `data/sigma/`. Note that YARA's regex engine has no non-capturing
groups — write `(a|b)`, never `(?:a|b)`, or the ruleset will not compile.

## Parsers

| Status | Artifact | Extra |
|---|---|---|
| built | Linux auth.log / secure / syslog (+ rotated, gz/bz2/xz) | — |
| built | Generic timestamped logs, Apache/nginx, untimestamped text | — |
| built | Windows Event Logs — Security, System, PowerShell, Sysmon, Task, RDP, Defender | `[evtx]` |
| built | Registry hives — Run keys, services, timezone, USB, UserAssist, amcache | `[registry]` |
| next | `$MFT` / `$J`, prefetch, shimcache | `[ntfs]` `[registry]` |
| next | LNK/jumplists, SRUM, browser history, PCAP, scheduled-task XML | `[ese]` `[pcap]` |
| later | Memory, cloud logs (CloudTrail / M365 UAL), WMI, email | `[memory]` |

The EVTX parser keys its mapping on `(channel family, EventID)` rather than the
ID alone, because Sysmon 1 and Security 4688 both mean "process created" and
several IDs collide across providers. Suspicious command lines upgrade both the
ATT&CK technique and the severity, so an encoded PowerShell downloader does not
read the same as `notepad.exe`.

## Companion to Matrix

[Matrix](https://github.com/Cobrastrike62) tracks HTB cases, maps MITRE ATT&CK,
and keeps notes. inspecthor does the deep artifact parsing Matrix intentionally
leaves alone.

- When a Matrix checkout sits beside this one, inspecthor **reads Matrix's ATT&CK
  database** so both tools validate technique ids against the same version. Set
  `INSPECTHOR_ATTACK_DB` or `MATRIX_HOME` to be explicit; a bundled copy means
  Matrix is never required.
- `export matrix` writes a `.tar.gz` that `matrix.py import` accepts, carrying
  the techniques, indicators, and notable timeline entries.

Technique ids are validated against the database before they are stored, so a
typo or a retired id never reaches a report or a Navigator layer.

## Sherlock mode

`sherlock` maps a question to the artifact and field that probably answers it,
then formats the candidate the way HTB expects — UTC `YYYY-MM-DD HH:MM:SS`,
uppercase hashes, bare integers, exact paths. `--readme task.txt` pulls the
numbered questions straight out of a Sherlock task file and answers them in one
pass.

It ranks by how unambiguous the evidence is: a single distinct value scores
higher than one of forty. It never submits, and every row carries the event it
came from so you can check before you commit an attempt.

## Layout

```
inspecthor/
  console.py        REPL + CLI (the only layer that prints)
  models.py         Event / ParseContext / EventFilter dataclasses
  engine.py         fingerprint + ingest orchestration
  query.py          timeline and search (parameterized SQL only)
  ioc.py            indicator extraction and refanging
  reporter.py       rich tables, markdown, exporters
  capabilities.py   probe -> degrade -> hint for optional deps
  sherlock.py       question -> ranked candidate answers
  parsers/          contract, loader, and plugins/
  detect/           YARA and Sigma overlays
  interop/          ATT&CK loading, Matrix export
  store/            SQLite case store + schema.sql
  data/             bundled ATT&CK, YARA/Sigma rules, allowlist
tests/test_offline.py   offline suite; no evidence, no network, no extras needed
```

## Tests

```bash
pip install -e . pytest && pytest -q
```

The suite is fully offline — every fixture is synthesized in `tmp_path`. It passes
on a bare install (extras-dependent tests skip themselves) and gets stronger as
you add extras.

## License

MIT — see [LICENSE](LICENSE).
