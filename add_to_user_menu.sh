#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Ren'Py Save Editor"
APP_ID="renpy-save-editor"
APP_COMMENT="Launch the Ren'Py Save Editor GUI."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
XDG_APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
DESKTOP_FILE="$XDG_APPS_DIR/${APP_ID}.desktop"

mkdir -p "$XDG_APPS_DIR"

cat >"$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Name=${APP_NAME}
Comment=${APP_COMMENT}
Exec="${SCRIPT_DIR}/launch.sh" gui
Icon=utilities-terminal
Terminal=false
Categories=Utility;Game;
EOF

chmod +x "$DESKTOP_FILE"
echo "Desktop entry installed at $DESKTOP_FILE"
