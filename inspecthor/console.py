"""Interactive console + CLI entry point.

CONSTRAINT: this is the ONLY layer allowed to print. Parsers, the store, the
engine and the query layer return typed objects; presentation lives here (and in
reporter.py) via rich. That keeps the library usable from scripts and keeps the
interactive and scriptable paths from drifting — both call the same functions.
"""
from __future__ import annotations

import argparse
import cmd
import os
import sys

from rich.console import Console

from . import __version__

# Windows console setup: os.system("") flips on ANSI VT processing for legacy
# terminals, and reconfiguring to UTF-8 keeps the block-glyph banner from
# raising UnicodeEncodeError on a cp1252 code page.
if os.name == "nt":  # pragma: no cover - platform-specific
    os.system("")
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8")
        except Exception:
            pass


_BANNER_UTF8 = r"""
██╗███╗   ██╗███████╗██████╗ ███████╗ ██████╗████████╗██╗  ██╗ ██████╗ ██████╗
██║████╗  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██║  ██║██╔═══██╗██╔══██╗
██║██╔██╗ ██║███████╗██████╔╝█████╗  ██║        ██║   ███████║██║   ██║██████╔╝
██║██║╚██╗██║╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██║██║   ██║██╔══██╗
██║██║ ╚████║███████║██║     ███████╗╚██████╗   ██║   ██║  ██║╚██████╔╝██║  ██║
╚═╝╚═╝  ╚═══╝╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
"""

_BANNER_ASCII = r"""
 ___ _  _ ___ ___ ___ ___ _____ _  _ ___  ___
|_ _| \| / __| _ \ __/ __|_   _| || / _ \| _ \
 | || .` \__ \  _/ _| (__  | | | __ | (_) |   /
|___|_|\_|___/_| |___\___| |_| |_||_|\___/|_|_\
"""


def _banner() -> str:
    """Block glyphs when the terminal can encode them, ASCII otherwise."""
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    if "utf" in enc:
        return _BANNER_UTF8
    return _BANNER_ASCII


class InspecthorConsole(cmd.Cmd):
    """Interactive REPL. Command docstrings are the help text."""

    prompt = "inspecthor> "
    intro = None

    def __init__(self, db: str = "inspecthor.db") -> None:
        super().__init__()
        self.console = Console()
        self.db = db

    def preloop(self) -> None:
        self.console.print(f"[bold red]{_banner()}[/]", markup=True, highlight=False)
        self.console.print(
            f"  read-only DFIR timeline & artifact analysis  [dim]v{__version__}[/]"
        )
        self.console.print(f"  case db: [cyan]{self.db}[/]     type 'help' to begin\n")

    def emptyline(self) -> bool:
        return False

    def default(self, line: str) -> None:
        self.console.print(f"[yellow]unknown command:[/] {line.split()[0]}  (try 'help')")

    def do_version(self, arg: str) -> None:
        """Show the inspecthor version."""
        self.console.print(f"inspecthor {__version__}")

    def do_exit(self, arg: str) -> bool:
        """Leave the console."""
        return True

    do_quit = do_exit

    def do_EOF(self, arg: str) -> bool:
        """Ctrl-D leaves the console."""
        self.console.print()
        return True


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="inspecthor",
        description="read-only forensic timeline and artifact analysis",
    )
    p.add_argument("--db", default="inspecthor.db", help="case database (default: inspecthor.db)")
    p.add_argument("--version", action="version", version=f"inspecthor {__version__}")
    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    try:
        InspecthorConsole(args.db).cmdloop()
    except KeyboardInterrupt:
        print()


if __name__ == "__main__":  # pragma: no cover
    main()
