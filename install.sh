#!/usr/bin/env bash
# inspecthor installer — run on any Kali (or Linux) box after cloning.
#
# Debian-family Pythons are PEP-668 managed, so a plain `pip install` into the
# system interpreter is refused. Both modes below avoid that: a project-local
# .venv (default) or a pipx-managed global command.
set -euo pipefail

usage() {
  cat <<'EOF'
inspecthor installer

  ./install.sh [flags]

Flags (combine freely):
  --full           + every optional parser and detector (dissect, yara, sigma,
                     scapy, volatility3, iocextract)
  --windows        + the dissect format libs only (evtx, registry, MFT, ESE)
  --detect         + YARA and Sigma only
  --pipx           global `inspecthor` command via pipx (no venv to activate)
  --trusted-host   pass pip --trusted-host (use behind a TLS-intercepting proxy)
  --link           symlink the command into ~/.local/bin
  -h, --help       this help

Examples:
  ./install.sh                      local .venv, core only (stdlib + rich)
  ./install.sh --full               local .venv with everything
  ./install.sh --full --link        ... and put `inspecthor` on your PATH
  ./install.sh --full --trusted-host    behind a corporate proxy
EOF
}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"
PYTHON="${PYTHON:-python3}"

EXTRA=""
USE_PIPX=0
DO_LINK=0
PIP_ARGS=()

for arg in "$@"; do
  case "$arg" in
    --full) EXTRA="full" ;;
    --windows) EXTRA="windows" ;;
    --detect) EXTRA="detect" ;;
    --pipx) USE_PIPX=1 ;;
    --link) DO_LINK=1 ;;
    --trusted-host)
      PIP_ARGS+=(--trusted-host pypi.org --trusted-host files.pythonhosted.org
                 --trusted-host pypi.python.org) ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; usage; exit 2 ;;
  esac
done

TARGET="."
[ -n "$EXTRA" ] && TARGET=".[$EXTRA]"

if [ "$USE_PIPX" -eq 1 ]; then
  command -v pipx >/dev/null || { echo "pipx not found: apt install pipx" >&2; exit 1; }
  echo "==> pipx install --editable $TARGET"
  pipx install --editable "$TARGET" --force
  BIN="$(command -v inspecthor || echo "$HOME/.local/bin/inspecthor")"
else
  echo "==> creating .venv"
  [ -x .venv/bin/python ] || "$PYTHON" -m venv .venv
  ./.venv/bin/pip install --quiet --upgrade pip setuptools wheel "${PIP_ARGS[@]}"
  echo "==> pip install -e $TARGET"
  ./.venv/bin/pip install -e "$TARGET" "${PIP_ARGS[@]}"
  BIN="$HERE/.venv/bin/inspecthor"
fi

if [ "$DO_LINK" -eq 1 ]; then
  mkdir -p "$HOME/.local/bin"
  ln -sf "$BIN" "$HOME/.local/bin/inspecthor"
  echo "==> linked $HOME/.local/bin/inspecthor"
  case ":$PATH:" in
    *":$HOME/.local/bin:"*) ;;
    *) echo "    note: ~/.local/bin is not on your PATH yet" ;;
  esac
fi

echo
echo "==> installed: $("$BIN" --version)"
echo "==> capabilities:"
"$BIN" tools
echo
echo "Run it:  $BIN"
echo "Tests :  ${HERE}/.venv/bin/python -m pytest -q     (pip install pytest first)"
