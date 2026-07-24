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
time-sorted event store — so "when did the attacker first log in" is a query
instead of an afternoon.

**Status: early.** The skeleton and packaging are in place; the pipeline is being
built in order (store → parsers → ingest → search → IOC → report). See the
roadmap below for what exists and what is next.

## Install

```bash
git clone https://github.com/Cobrastrike62/inspecthor && cd inspecthor
pip install -e .
```

That bare install is deliberately light — stdlib plus `rich`. It already handles
text, syslog, SQLite and JSON evidence. Binary-artifact parsers are extras, and a
missing extra prints a one-line install hint instead of failing:

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

## Usage

```bash
inspecthor                      # interactive console
inspecthor --db case1.db        # pick a case database
python -m inspecthor            # same entry point
```

## How it works

```
evidence/  or  sherlock.zip
        |
        v
   engine  ── fingerprint by magic bytes, hash, route
        |
        v
   parsers  ── plugins; each yields normalized Events
        |
        v
   store  ── per-case SQLite + FTS5
        |
        +--> timeline      time-sorted across every artifact
        +--> search        one query hits EVTX + registry + logs at once
        +--> ioc           IPs / domains / hashes, linked back to events
        +--> detect        YARA + Sigma findings
        +--> report        markdown, CSV, JSONL, Timesketch, plaso l2tcsv
```

Every parser emits the same `Event` shape, which is what makes a cross-artifact
timeline and a single search index possible.

## Extending

Adding an artifact type is one file in `inspecthor/parsers/plugins/`. No engine,
store or console edits:

```python
from __future__ import annotations
from pathlib import Path
from typing import Iterator
from ...models import Event
from ..base import Parser, register

@register
class PrefetchParser(Parser):
    name, display, category = "prefetch", "Windows Prefetch", "windows"
    magic = (b"MAM\x04", b"SCCA")
    path_globs = ("*.pf",)

    def parse(self, path: Path, ctx) -> Iterator[Event]:
        for name, run_time, run_count in _read_prefetch(path):
            yield ctx.event(timestamp=run_time, timestamp_desc="Last Run",
                            event_type="process_exec",
                            message=f"{name} executed (run #{run_count})")
```

A parser needing a library sets `requires` and `install_hint`; the import stays
lazy inside `parse()`, so a stdlib-only install still loads the plugin and simply
reports the hint when that artifact shows up.

## Roadmap

| | Artifact | Extra |
|---|---|---|
| next | EVTX, Linux auth/syslog, registry hives | `[evtx]` `[registry]` |
| then | `$MFT`/`$J`, prefetch, amcache/shimcache | `[ntfs]` `[registry]` |
| later | LNK/jumplists, SRUM, browser history, PCAP, scheduled tasks | `[ese]` `[pcap]` |
| later | Memory, cloud logs (CloudTrail / M365 UAL), WMI, email | `[memory]` |

## Companion to Matrix

[Matrix](https://github.com/Cobrastrike62) tracks HTB cases, maps MITRE ATT&CK
and keeps notes. inspecthor does the deep artifact parsing Matrix intentionally
leaves alone. When both are checked out side by side, inspecthor reads Matrix's
bundled ATT&CK database so technique IDs stay consistent, and it can export a
case Matrix will import.

## Layout

```
inspecthor/
  console.py        interactive REPL + CLI (the only layer that prints)
  models.py         Event / ParseContext / EventFilter dataclasses
  engine.py         fingerprint + ingest orchestration
  query.py          timeline and search over the store
  ioc.py            IOC extraction and refanging
  reporter.py       rich tables, markdown, exporters
  capabilities.py   probe -> degrade -> hint for optional deps
  sherlock.py       question -> ranked candidate answers
  parsers/          parser base, loader, and plugins/
  detect/           YARA and Sigma overlays
  interop/          ATT&CK loading, Matrix export
  store/            SQLite case store + schema.sql
  data/             bundled ATT&CK, rules, answer rules
```

## License

MIT — see [LICENSE](LICENSE).
