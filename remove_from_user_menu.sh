#!/usr/bin/env bash
set -euo pipefail

APP_ID="renpy-save-editor"
DESKTOP_FILE="${XDG_DATA_HOME:-$HOME/.local/share}/applications/${APP_ID}.desktop"

if [[ -f "$DESKTOP_FILE" ]]; then
  rm "$DESKTOP_FILE"
  echo "Desktop entry removed from $DESKTOP_FILE"
else
  echo "No desktop entry found at $DESKTOP_FILE"
fi
