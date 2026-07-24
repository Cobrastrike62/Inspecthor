# Changelog

## v0.1.0 — project skeleton

- Package scaffold: `inspecthor/` with `console.py` (cmd.Cmd REPL), and the
  `parsers/`, `parsers/plugins/`, `detect/`, `interop/`, `store/`, `data/`
  subpackages the pipeline is built into.
- PEP-621 `pyproject.toml`: core is stdlib + `rich` only; every binary-artifact
  parser is an optional extra (`[evtx]`, `[registry]`, `[ntfs]`, `[ese]`,
  `[windows]`, `[yara]`, `[sigma]`, `[detect]`, `[pcap]`, `[memory]`, `[ioc]`,
  `[full]`) so a bare install still runs.
- `inspecthor` console script + `python -m inspecthor`, both reaching the same
  entry point.
- Repo hygiene: MIT license, LF normalization, and a `.gitignore` that keeps
  evidence, case databases and raw artifacts out of git — Sherlock packages can
  contain live malware.
