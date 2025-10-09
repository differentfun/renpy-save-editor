#!/usr/bin/env bash
set -euo pipefail

# launch.sh
# Avvia la GUI o la CLI usando il venv locale se presente.
# Uso:
#   ./launch.sh gui
#   ./launch.sh cli [args...]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="${VENV_DIR:-.venv}"
PY=""

pick_python() {
  if [[ -d "$VENV_DIR" ]]; then
    if [[ -x "$VENV_DIR/bin/python" ]]; then
      PY="$VENV_DIR/bin/python"
    elif [[ -x "$VENV_DIR/Scripts/python" ]]; then
      PY="$VENV_DIR/Scripts/python"
    elif [[ -x "$VENV_DIR/Scripts/python.exe" ]]; then
      PY="$VENV_DIR/Scripts/python.exe"
    fi
  fi
  if [[ -z "$PY" ]]; then
    if command -v python3 >/dev/null 2>&1; then
      PY="python3"
    else
      PY="python"
    fi
  fi
}

usage() {
  cat <<'EOF'
Uso: launch.sh <gui|cli> [args...]

  gui          Avvia l'interfaccia grafica (Tkinter)
  cli ...      Esegue la CLI (renpy_save_edit.py) con gli argomenti forniti

Esempi:
  ./launch.sh gui
  ./launch.sh cli list path/to/save.save --prefix store.
  ./launch.sh cli get  path/to/save.save store.money
  ./launch.sh cli set  path/to/save.save store.money 9999
EOF
}

ensure_tk_for_gui() {
  "$PY" - <<'PY' 1>/dev/null 2>&1 || exit 7
import sys
try:
    import tkinter  # noqa: F401
except Exception as e:
    print("Tkinter non disponibile:", e)
    sys.exit(1)
PY
}

main() {
  pick_python
  cmd="${1:-gui}"
  case "$cmd" in
    -h|--help|help)
      usage; exit 0 ;;
    gui)
      ensure_tk_for_gui || {
        echo "[ERR ] Tkinter non disponibile nel Python selezionato ($PY)."
        echo "Suggerimenti: Debian/Ubuntu: sudo apt-get install python3-tk | Fedora: sudo dnf install python3-tkinter | Arch: sudo pacman -S tk | macOS: usa python.org o brew install python-tk@3.12"
        exit 1
      }
      exec "$PY" "$SCRIPT_DIR/renpy_save_gui.py" ;;
    cli)
      shift || true
      exec "$PY" "$SCRIPT_DIR/renpy_save_edit.py" "$@" ;;
    *)
      echo "[WARN] Comando sconosciuto: $cmd"
      usage; exit 2 ;;
  esac
}

main "$@"

