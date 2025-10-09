#!/usr/bin/env bash
set -euo pipefail

# setup_env.sh
# Crea un virtualenv locale e installa le dipendenze necessarie.
# Uso:
#   ./setup_env.sh [percorso_venv]
#
# Se non specificato, il venv è ".venv" nella root del repo.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV_DIR="${1:-.venv}"

info() { printf "\033[1;34m[INFO]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err()  { printf "\033[1;31m[ERR ]\033[0m %s\n" "$*"; }

detect_python() {
  if [[ -n "${PYTHON:-}" ]]; then
    PY="$PYTHON"
  elif command -v python3 >/dev/null 2>&1; then
    PY="python3"
  elif command -v python >/dev/null 2>&1; then
    PY="python"
  else
    err "Python 3 non trovato nel PATH. Installa Python 3 e riprova."
    exit 1
  fi
  "$PY" - <<'PY' || { echo "Python >= 3.7 richiesto"; exit 1; }
import sys
maj, min = sys.version_info[:2]
sys.exit(0 if (maj > 3 or (maj == 3 and min >= 7)) else 1)
PY
  echo "$PY"
}

create_venv() {
  local py="$1"
  if [[ -d "$VENV_DIR" ]]; then
    info "Venv esistente: $VENV_DIR"
  else
    info "Creo venv in $VENV_DIR"
    "$py" -m venv "$VENV_DIR"
  fi
}

venv_bin_dir() {
  if [[ -d "$VENV_DIR/bin" ]]; then
    echo "$VENV_DIR/bin"
  else
    echo "$VENV_DIR/Scripts" # Windows
  fi
}

install_deps() {
  local bindir; bindir="$(venv_bin_dir)"
  local pip="$bindir/pip"
  local py="$bindir/python"

  info "Aggiorno pip/setuptools/wheel"
  "$pip" install --upgrade pip setuptools wheel

  if [[ -f requirements.txt ]]; then
    info "Installo requirements.txt"
    "$pip" install -r requirements.txt
  else
    # Dipendenze dirette del progetto
    info "Installo dipendenze Python necessarie (ecdsa per firme Ren'Py)"
    "$pip" install ecdsa
  fi

  # Verifica opzionale moduli standard usati
  "$py" - <<'PY'
import sys
mods = ["zipfile","zlib","struct","tkinter"]
missing = []
for m in mods:
    try:
        __import__(m)
    except Exception:
        missing.append(m)
if missing:
    print("MANCANTI:", ", ".join(missing))
    sys.exit(2)
print("OK")
PY
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    warn "Alcuni moduli non sono disponibili nel Python corrente (vedi sopra)."
    if command -v uname >/dev/null 2>&1; then
      os="$(uname -s || true)"
      case "$os" in
        Linux)
          cat <<'EOS'
Suggerimenti per Tkinter su Linux:
  - Debian/Ubuntu:    sudo apt-get update && sudo apt-get install -y python3-tk
  - Fedora:            sudo dnf install -y python3-tkinter
  - Arch/Manjaro:      sudo pacman -S tk
EOS
          ;;
        Darwin)
          cat <<'EOS'
Suggerimenti per Tkinter su macOS:
  - Consigliato: installa Python da python.org (include Tkinter)
  - Homebrew (alternativa): brew install python-tk@3.12
EOS
          ;;
      esac
    fi
  fi
}

main() {
  info "Rilevo Python..."
  PYBIN="$(detect_python)"
  info "Userò: $PYBIN"

  create_venv "$PYBIN"
  install_deps

  BIN_DIR="$(venv_bin_dir)"
  echo
  info "Setup completato. Venv: $VENV_DIR"
  cat <<EOF

Per avviare la GUI:
  ./launch.sh gui

Per usare la CLI:
  ./launch.sh cli list /percorso/al/file.save
  ./launch.sh cli get  /percorso/al/file.save store.money
  ./launch.sh cli set  /percorso/al/file.save store.money 9999

Per attivare manualmente il venv (opzionale):
  source "$BIN_DIR/activate"
EOF
}

main "$@"

