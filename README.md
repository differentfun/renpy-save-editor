## Ren'Py Save Editor (GUI + CLI)

Edit numeric values in Ren'Py saves safely. This repository provides:

- A Tkinter GUI to inspect and change variables in `.save` and `persistent`.
- A command‑line tool to list/get/set variables in `.save` files.

Backups are created automatically, and patching is conservative to avoid corrupting saves.

---

### Features

- Safe unpickling: prevents arbitrary code execution by mapping Ren'Py classes to safe stand‑ins.
- Byte‑level patching: only the encoded value is replaced, preserving the rest of the pickle/zip.
- Signatures support: regenerates `signatures` if `ecdsa` and local Ren'Py signing keys are available; otherwise writes empty (usually acceptable).
- GUI niceties: search, type filter, sorting, multi-edit, string editing, dedicated private-inventory editor, and automatic `.bak` backup.

---

### Requirements

- Python 3.7+
- GUI: Tkinter module must be present in your Python installation.
- Optional: `ecdsa` package for signature regeneration.

OS tips for Tkinter:

- Debian/Ubuntu: `sudo apt-get update && sudo apt-get install -y python3-tk`
- Fedora: `sudo dnf install -y python3-tkinter`
- Arch/Manjaro: `sudo pacman -S tk`
- macOS: install Python from python.org (includes Tkinter) or `brew install python-tk@3.12`

---

### Quick Start

1) Create a virtual environment and install deps:

```
./setup_env.sh
```

2) Launch the GUI or use the CLI via the launcher:

```
# GUI
./launch.sh gui

# CLI examples
./launch.sh cli list path/to/save.save --prefix store.
./launch.sh cli get  path/to/save.save store.money
./launch.sh cli set  path/to/save.save store.money 9999
```

You can also activate the venv manually with `source .venv/bin/activate`.

---

### GUI Usage (`renpy_save_gui.py`)

1) Open a `.save` (zip) or `persistent` (zlib) file.
2) Use search and type filters to find variables. The GUI lists scalar values (int/float/bool by default; enable strings via filter).
3) Double‑click the Value to edit; select multiple rows and press Enter for bulk edit. (Strings sono visibili subito perché il filtro numerico parte disattivato.)
4) Click “Save changes” to write back. A `.bak` is created the first time.

Tip: per modificare l'inventario privato, fai doppio click su `store.Player`. La finestra dedicata mostra le quantità effettive e i valori “stack” grezzi; inserisci la quantità desiderata e il tool calcolerà automaticamente lo stack corrispondente.

Notes:

- `.save`: variables are typically shown with fully‑qualified names (e.g., `store.money`).
- `persistent`: only top‑level string‑keyed scalars and one nested dict level are flattened.
- Signatures are regenerated if possible; otherwise empty signatures are written.

---

### CLI Usage (`renpy_save_edit.py`)

```
usage: renpy_save_edit.py {list,get,set} ...

# List numeric/bool variables (prefix defaults to store.)
python3 renpy_save_edit.py list path/to/save.save [--prefix store.]

# Get exact variable value
python3 renpy_save_edit.py get path/to/save.save store.money

# Set int/bool value (bool: 0/1)
python3 renpy_save_edit.py set path/to/save.save store.money 9999
```

Note: The CLI currently edits only integers/bools. Floats are supported in the GUI.

---

### How It Works (High Level)

- `.save` files are zip archives. The relevant entry is `log`, a Python pickle containing a mapping of variable names to values.
- The GUI uses a hardened unpickler (`SafeUnpickler`) that:
  - maps common Ren'Py types (e.g., RevertableList/Dict/Set, defaultdict, OrderedDict) to simple containers;
  - replaces unknown classes with benign proxies, so unpickling does not execute arbitrary code.
- For editing, the code searches for the key’s pickle `BINUNICODE` and replaces the immediately following scalar value bytes (int/float/bool), preserving pickle structure.
- `.save` repack: writes a new `log` and updates `signatures`. If `ecdsa` and local keys are available, valid signatures are generated; otherwise an empty `signatures` entry is written.
- `persistent` is zlib‑compressed pickle: the GUI decompresses, patches similarly, then recompresses.

Signing keys discovery: best‑effort lookup under standard Ren'Py token paths, e.g. `~/.renpy/tokens/security_keys.txt` and OS‑specific equivalents.

---

### Limitations

- CLI set: only int/bool today; float editing is GUI‑only.
- Heuristic matching: if a key appears multiple times or in unusual layouts, the first matching occurrence may be chosen. The GUI reduces risk by verifying the current value before patching.
- Persistent flattening: only top‑level scalars and one nested dict level with string keys are listed.
- Not a general pickle editor: complex/nested structures are intentionally out of scope.
- Signatures: regeneration requires `ecdsa` and your local Ren'Py signing keys; if missing, empty signatures are written.

---

### Troubleshooting

- Tkinter missing: install it per your OS (see Requirements). The launcher warns if Tkinter is unavailable.
- `ecdsa` missing: run `./setup_env.sh` or `pip install ecdsa` inside the venv.
- Save cannot be read: some games may use unusual pickling patterns; the safe unpickler proxies most classes, but unsupported edge cases may still fail.
- Write errors on `.save`: ensure you have write permission; the tool writes a temporary file and then replaces the original; a `.bak` is created on first write.

---

### Development

- Scripts:
  - `setup_env.sh`: creates `./.venv` and installs dependencies.
  - `launch.sh`: runs the GUI/CLI using the venv if present.
- Main programs:
  - `renpy_save_gui.py`: Tkinter GUI for `.save` and `persistent`.
  - `renpy_save_edit.py`: CLI for `.save` listing/getting/setting.

Contributions welcome via issues and pull requests.

---

### Disclaimer

Editing save files is at your own risk. Always keep backups. This tool does its best to patch conservatively and avoid executing code during unpickling, but it cannot guarantee compatibility with every game or Ren'Py version.

- Not affiliated with Ren'Py, PyTom, or any game/studio. “Ren'Py” and other names are used descriptively and may be trademarks of their respective owners.
- Usage may violate specific games' or platforms' EULA/ToS (especially online/competitive titles). You are responsible for complying with applicable terms.
- The tool does not include or distribute any third‑party private signing keys; signature regeneration only uses keys present on your local machine if available.

License: see `LICENSE.md`.
