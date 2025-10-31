#!/usr/bin/env python3
import sys
import os
import io
import zipfile
import base64
import pickle
import importlib
import struct
import ast
import types
import copy
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import zlib
from pickletools import genops


# ----------------- Safe Unpickler to read Ren'Py log -----------------

class _Proxy:
    def __init__(self, *a, **k):
        # Collect state and list-like data pushed during unpickling.
        self._state = None
        self._list = []
    def __setstate__(self, state):
        setattr(self, '_state', state)
    # Some pickles for sequence-like custom types use APPEND/APPENDS opcodes.
    # Provide minimal list-like surface so unpickling doesn't fail.
    def append(self, item):
        self._list.append(item)
    def extend(self, items):
        try:
            self._list.extend(items)
        except Exception:
            for it in items:
                self._list.append(it)
    def __iter__(self):
        return iter(self._list)
    def __len__(self):
        return len(self._list)

class _RevertableList(list):
    def __setstate__(self, state):
        try:
            if isinstance(state, (list, tuple)) and state:
                first = state[0]
                if isinstance(first, (list, tuple)):
                    self.extend(first)
        except Exception:
            pass

class _RevertableDict(dict):
    def __setstate__(self, state):
        try:
            if isinstance(state, dict):
                self.update(state)
            elif isinstance(state, (list, tuple)) and state and isinstance(state[0], dict):
                self.update(state[0])
        except Exception:
            pass

class _RevertableSet(set):
    def __setstate__(self, state):
        try:
            if isinstance(state, (list, tuple)) and state and isinstance(state[0], (list, tuple, set)):
                self.update(state[0])
        except Exception:
            pass

class _SimpleDefaultDict(dict):
    def __init__(self, *a, **k):
        self.default_factory = None
    def __setstate__(self, state):
        try:
            if isinstance(state, tuple) and len(state) == 2:
                self.default_factory = state[0]
                st = state[1]
                if isinstance(st, dict):
                    self.update(st)
        except Exception:
            pass

class _SimpleOrderedDict(dict):
    def __setstate__(self, state):
        try:
            if isinstance(state, dict):
                self.update(state)
            elif isinstance(state, list):
                for k, v in state:
                    self[k] = v
        except Exception:
            pass

_SPECIAL = {
    ('renpy.revertable', 'RevertableList'): _RevertableList,
    ('renpy.revertable', 'RevertableDict'): _RevertableDict,
    ('renpy.revertable', 'RevertableSet'): _RevertableSet,
    ('collections', 'defaultdict'): _SimpleDefaultDict,
    ('collections', 'OrderedDict'): _SimpleOrderedDict,
}


def _ensure_module(name: str):
    if name in sys.modules:
        return sys.modules[name]
    parts = name.split('.') if name else []
    parent = None
    accumulated = []
    for part in parts:
        accumulated.append(part)
        module_name = '.'.join(accumulated)
        if module_name not in sys.modules:
            module = types.ModuleType(module_name)
            sys.modules[module_name] = module
            if parent is not None:
                setattr(parent, part, module)
        parent = sys.modules[module_name]
    return sys.modules.get(name, parent)


class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) in _SPECIAL:
            cls = _SPECIAL[(module, name)]
            cls.__module__ = module
            mod = _ensure_module(module)
            if mod is not None:
                setattr(mod, cls.__name__, cls)
                setattr(mod, name, cls)
            return cls
        # Be tolerant of module path variations for common Ren'Py types
        if name in ('RevertableList', 'RevertableDict', 'RevertableSet'):
            mapping = {
                'RevertableList': _RevertableList,
                'RevertableDict': _RevertableDict,
                'RevertableSet': _RevertableSet,
            }
            cls = mapping[name]
            cls.__module__ = module
            mod = _ensure_module(module)
            if mod is not None:
                setattr(mod, cls.__name__, cls)
                setattr(mod, name, cls)
            return cls
        if module == 'builtins':
            return getattr(importlib.import_module(module), name)
        # Everything else becomes a benign proxy class.
        mod = _ensure_module(module)
        cls = type(name, (_Proxy,), {})
        cls.__module__ = module
        if mod is not None:
            setattr(mod, name, cls)
        return cls


def unzip_log_bytes(save_path: str) -> bytes:
    with zipfile.ZipFile(save_path, 'r') as zf:
        return zf.read('log')


def repack_log_bytes(src_save: str, dst_save: str, new_log: bytes):
    with zipfile.ZipFile(src_save, 'r') as zin:
        with zipfile.ZipFile(dst_save, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == 'log':
                    zi = zipfile.ZipInfo(item.filename)
                    zi.date_time = item.date_time
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.external_attr = item.external_attr
                    zout.writestr(zi, new_log)
                elif item.filename == 'signatures':
                    sig = _make_signatures(new_log)
                    zi = zipfile.ZipInfo(item.filename)
                    zi.date_time = item.date_time
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.external_attr = item.external_attr
                    zout.writestr(zi, sig)
                else:
                    zout.writestr(item, zin.read(item.filename))


def _find_security_keys():
    candidates = [
        os.path.expanduser('~/.renpy/tokens/security_keys.txt'),
        os.path.expanduser('~/Library/RenPy/tokens/security_keys.txt'),
        os.path.join(os.environ.get('APPDATA', ''), 'RenPy', 'tokens', 'security_keys.txt'),
        os.path.join(os.environ.get('LOCALAPPDATA', ''), 'RenPy', 'tokens', 'security_keys.txt'),
        os.path.expanduser('~/.local/share/renpy/tokens/security_keys.txt'),
        os.path.expanduser('~/.config/renpy/tokens/security_keys.txt'),
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return p
    return None


def _load_signing_keys(keys_path):
    keys = []
    try:
        with open(keys_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if parts and parts[0] == 'signing-key' and len(parts) >= 2:
                    try:
                        der = base64.b64decode(parts[1])
                        keys.append(der)
                    except Exception:
                        pass
    except Exception:
        pass
    return keys


def _make_signatures(log_bytes: bytes) -> bytes:
    """Return Ren'Py signatures for given log, or empty bytes if not possible."""
    keys_path = _find_security_keys()
    if not keys_path:
        return b''
    keys = _load_signing_keys(keys_path)
    if not keys:
        return b''
    try:
        import ecdsa  # type: ignore
    except Exception:
        return b''
    out_lines = []
    for der in keys:
        try:
            sk = ecdsa.SigningKey.from_der(der)
            vk = getattr(sk, 'verifying_key', None)
            if vk is None:
                continue
            sig = sk.sign(log_bytes)
            vk_der = vk.to_der()
            line = 'signature ' + base64.b64encode(vk_der).decode('ascii') + ' ' + base64.b64encode(sig).decode('ascii')
            out_lines.append(line)
        except Exception:
            continue
    if not out_lines:
        return b''
    return ('\n'.join(out_lines) + '\n').encode('utf-8')


# ----------------- Pickle value parsing/patching -----------------

STRING = 0x53
BINSTRING = 0x54
SHORT_BINSTRING = 0x55
UNICODE = 0x56
BINUNICODE = 0x58
SHORT_BINUNICODE = 0x8C
BINUNICODE8 = 0x8D
BINVAL1 = 0x4B  # BININT1
BINVAL2 = 0x4D  # BININT2
BINVAL4 = 0x4A  # BININT
BINFLOAT = 0x47
NEWTRUE = 0x88
NEWFALSE = 0x89
LONG1 = 0x8A
LONG4 = 0x8B


def _parse_value_at(data: bytes, pos: int):
    if pos >= len(data):
        return None
    op = data[pos]
    if op == BINVAL1 and pos + 2 <= len(data):
        return (data[pos + 1], pos + 2, 'BININT1')
    if op == BINVAL2 and pos + 3 <= len(data):
        return (struct.unpack('<H', data[pos + 1:pos + 3])[0], pos + 3, 'BININT2')
    if op == BINVAL4 and pos + 5 <= len(data):
        return (struct.unpack('<i', data[pos + 1:pos + 5])[0], pos + 5, 'BININT4')
    if op == BINFLOAT and pos + 9 <= len(data):
        return (struct.unpack('>d', data[pos + 1:pos + 9])[0], pos + 9, 'BINFLOAT')
    if op == NEWTRUE:
        return (True, pos + 1, 'BOOL')
    if op == NEWFALSE:
        return (False, pos + 1, 'BOOL')
    if op == ord('I'):
        end = data.find(b'\n', pos)
        if end != -1:
            txt = data[pos + 1:end]
            try:
                return (int(txt.decode('ascii')), end + 1, 'INTTXT')
            except Exception:
                return None
    if op == ord('F'):
        end = data.find(b'\n', pos)
        if end != -1:
            txt = data[pos + 1:end]
            try:
                return (float(txt.decode('ascii')), end + 1, 'FLTTXT')
            except Exception:
                return None
    if op == SHORT_BINUNICODE and pos + 2 <= len(data):
        ln = data[pos + 1]
        start = pos + 2
        end = start + ln
        if end <= len(data):
            return (data[start:end].decode('utf-8', 'replace'), end, 'SHORT_BINUNICODE')
    if op == BINUNICODE and pos + 5 <= len(data):
        ln = struct.unpack('<I', data[pos + 1:pos + 5])[0]
        start = pos + 5
        end = start + ln
        if end <= len(data):
            return (data[start:end].decode('utf-8', 'replace'), end, 'BINUNICODE')
    if op == BINUNICODE8 and pos + 9 <= len(data):
        ln = struct.unpack('<Q', data[pos + 1:pos + 9])[0]
        start = pos + 9
        end = start + ln
        if end <= len(data):
            return (data[start:end].decode('utf-8', 'replace'), end, 'BINUNICODE8')
    if op == SHORT_BINSTRING and pos + 2 <= len(data):
        ln = data[pos + 1]
        start = pos + 2
        end = start + ln
        if end <= len(data):
            return (data[start:end].decode('utf-8', 'replace'), end, 'SHORT_BINSTRING')
    if op == BINSTRING and pos + 5 <= len(data):
        ln = struct.unpack('<I', data[pos + 1:pos + 5])[0]
        start = pos + 5
        end = start + ln
        if end <= len(data):
            return (data[start:end].decode('utf-8', 'replace'), end, 'BINSTRING')
    if op in (STRING, UNICODE):
        end = data.find(b'\n', pos)
        if end != -1:
            raw = data[pos + 1:end]
            try:
                text = ast.literal_eval(raw.decode('ascii'))
                if isinstance(text, str):
                    return (text, end + 1, 'UNICODE' if op == UNICODE else 'STRING')
            except Exception:
                return None
    # LONG1/LONG4 handling (integers outside 32-bit). We'll decode but only re-encode if new value fits 32-bit.
    if op == LONG1 and pos + 2 <= len(data):
        n = data[pos + 1]
        if pos + 2 + n <= len(data):
            mag = int.from_bytes(data[pos + 2:pos + 2 + n], 'little', signed=True)
            return (mag, pos + 2 + n, 'LONG1')
    if op == LONG4 and pos + 5 <= len(data):
        n = struct.unpack('<I', data[pos + 1:pos + 5])[0]
        if pos + 5 + n <= len(data):
            mag = int.from_bytes(data[pos + 5:pos + 5 + n], 'little', signed=True)
            return (mag, pos + 5 + n, 'LONG4')
    return None


def _read_key_token(data: bytes, pos: int):
    if pos >= len(data):
        return None
    op = data[pos]
    if op == BINUNICODE and pos + 5 <= len(data):
        ln = struct.unpack('<I', data[pos + 1:pos + 5])[0]
        start = pos + 5
        end = start + ln
        if end <= len(data):
            return (data[start:end].decode('utf-8', 'replace'), end)
    if op == SHORT_BINUNICODE and pos + 2 <= len(data):
        ln = data[pos + 1]
        start = pos + 2
        end = start + ln
        if end <= len(data):
            return (data[start:end].decode('utf-8', 'replace'), end)
    if op == BINUNICODE8 and pos + 9 <= len(data):
        ln = struct.unpack('<Q', data[pos + 1:pos + 9])[0]
        start = pos + 9
        end = start + ln
        if end <= len(data):
            return (data[start:end].decode('utf-8', 'replace'), end)
    if op == SHORT_BINSTRING and pos + 2 <= len(data):
        ln = data[pos + 1]
        start = pos + 2
        end = start + ln
        if end <= len(data):
            return (data[start:end].decode('utf-8', 'replace'), end)
    if op == BINSTRING and pos + 5 <= len(data):
        ln = struct.unpack('<I', data[pos + 1:pos + 5])[0]
        start = pos + 5
        end = start + ln
        if end <= len(data):
            return (data[start:end].decode('utf-8', 'replace'), end)
    if op in (STRING, UNICODE):
        end = data.find(b'\n', pos)
        if end != -1:
            raw = data[pos + 1:end]
            try:
                txt = ast.literal_eval(raw.decode('ascii'))
                if isinstance(txt, str):
                    return (txt, end + 1)
            except Exception:
                return None
    return None


def _encode_scalar(value, enc_hint=None):
    if isinstance(value, bool):
        return b"\x88" if value else b"\x89"
    if isinstance(value, float):
        return b"\x47" + struct.pack('>d', float(value))
    if isinstance(value, int):
        if 0 <= value <= 0xFF:
            return b"\x4b" + bytes([value])
        if 0 <= value <= 0xFFFF:
            return b"\x4d" + struct.pack('<H', value)
        if -0x80000000 <= value <= 0x7FFFFFFF:
            return b"\x4a" + struct.pack('<i', int(value))
        # Fallback: LONG4 minimal two's complement
        mag = int(value).to_bytes((int(value).bit_length() + 8) // 8 or 1, 'little', signed=True)
        return b"\x8b" + struct.pack('<I', len(mag)) + mag
    if isinstance(value, str):
        raw = value.encode('utf-8')
        if enc_hint == 'SHORT_BINSTRING' and len(raw) <= 0xFF:
            return bytes([SHORT_BINSTRING, len(raw)]) + raw
        if enc_hint == 'BINSTRING' and len(raw) <= 0xFFFFFFFF:
            return bytes([BINSTRING]) + struct.pack('<I', len(raw)) + raw
        if enc_hint in ('STRING', 'UNICODE'):
            lit = repr(value).encode('utf-8')
            return bytes([STRING if enc_hint == 'STRING' else UNICODE]) + lit + b'\n'
        if enc_hint == 'SHORT_BINUNICODE' and len(raw) <= 0xFF:
            return bytes([SHORT_BINUNICODE, len(raw)]) + raw
        if enc_hint == 'BINUNICODE' and len(raw) <= 0xFFFFFFFF:
            return bytes([BINUNICODE]) + struct.pack('<I', len(raw)) + raw
        if enc_hint == 'BINUNICODE8':
            return bytes([BINUNICODE8]) + struct.pack('<Q', len(raw)) + raw
        if len(raw) <= 0xFF:
            return bytes([SHORT_BINUNICODE, len(raw)]) + raw
        if len(raw) <= 0xFFFFFFFF:
            return bytes([BINUNICODE]) + struct.pack('<I', len(raw)) + raw
        return bytes([BINUNICODE8]) + struct.pack('<Q', len(raw)) + raw
    raise ValueError('Unsupported type')


def patch_value_for_key(log_bytes: bytes, key: str, current_value, new_value):
    target = key.decode('utf-8', 'replace') if isinstance(key, bytes) else str(key)
    i = 0
    n = len(log_bytes)
    while i < n:
        parsed = _read_key_token(log_bytes, i)
        if parsed is None:
            i += 1
            continue
        ktext, next_pos = parsed
        if ktext == target:
            pos = next_pos
            if pos + 1 <= n and log_bytes[pos] == ord('q'):
                pos += 2
            if pos + 5 <= n and log_bytes[pos] == ord('r'):
                pos += 5
            for look in range(0, 1024):
                pv = _parse_value_at(log_bytes, pos + look)
                if pv is None:
                    continue
                val, vend, enc = pv
                if isinstance(current_value, bool):
                    equal = bool(val) == bool(current_value)
                elif isinstance(current_value, float):
                    equal = abs(float(val) - float(current_value)) < 1e-9
                else:
                    equal = (val == current_value)
                if equal:
                    rep = _encode_scalar(new_value, enc_hint=enc)
                    return log_bytes[:pos + look] + rep + log_bytes[vend:]
        i = next_pos
    raise KeyError(f'Key not found or value encoding unsupported: {key}')


# ----------------- Tkinter GUI -----------------

class SaveEditorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Ren'Py Save Editor")
        self.geometry('1000x600')
        self.save_path = None
        self.log_bytes = None
        self.persistent_path = None
        self.persistent_bytes = None  # decompressed zlib bytes
        self.mode = None  # 'save' or 'persistent'
        self.roots = {}   # display_name -> value
        self.key_tokens = {}  # display_name -> key token to search in pickle
        self.tree = None
        self.item_base_counts = {}
        # Remember last folders for file dialogs
        self.last_save_dir = None
        self.last_persistent_dir = None
        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill='x', padx=8, pady=6)

        ttk.Button(top, text='Open .save', command=self.open_save).pack(side='left')
        ttk.Button(top, text='Open persistent', command=self.open_persistent).pack(side='left', padx=6)
        ttk.Button(top, text='Save changes', command=self.save_changes).pack(side='left', padx=6)

        self.only_numeric = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text='Only numeric/bool/float variables', variable=self.only_numeric, command=self.refresh_list).pack(side='left', padx=12)

        # Type filter
        ttk.Label(top, text='Type:').pack(side='left', padx=(12, 4))
        self.type_filter = tk.StringVar(value='All')
        self.type_combo = ttk.Combobox(top, textvariable=self.type_filter, width=10, state='readonly',
                                       values=['All', 'Int', 'Float', 'Bool', 'Str'])
        self.type_combo.pack(side='left')
        self.type_combo.bind('<<ComboboxSelected>>', lambda e: self.refresh_list())

        ttk.Label(top, text='Filter:').pack(side='left', padx=(24, 4))
        self.search_var = tk.StringVar()
        ent = ttk.Entry(top, textvariable=self.search_var, width=32)
        ent.pack(side='left')
        ent.bind('<KeyRelease>', lambda e: self.refresh_list())

        ttk.Label(top, text='Double-click Value to edit').pack(side='right')

        cols = ('name', 'type', 'value')
        self.tree = ttk.Treeview(self, columns=cols, show='headings', selectmode='extended')
        for c, w in (('name', 600), ('type', 100), ('value', 200)):
            # heading with sort command
            self.tree.heading(c, text=c, command=lambda cc=c: self._sort_by(cc))
            self.tree.column(c, width=w, stretch=(c == 'name'))
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<Double-1>', self._on_double)
        # Edit selected (one or many) on Enter
        self.tree.bind('<Return>', self._on_enter)

        yscroll = ttk.Scrollbar(self, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)
        yscroll.place(relx=1.0, rely=0, relheight=1.0, anchor='ne')

        # sorting state
        self._sort_col = None
        self._sort_desc = False

    def open_save(self):
        # Start from last visited directory if available
        default_dir = os.path.join(os.getcwd(), 'game', 'saves')
        initdir = self.last_save_dir if (self.last_save_dir and os.path.isdir(self.last_save_dir)) else default_dir
        path = filedialog.askopenfilename(title='Select .save file', filetypes=[('Ren\'Py Save', '*.save')], initialdir=initdir)
        if not path:
            return
        # Remember directory for next time
        try:
            self.last_save_dir = os.path.dirname(path)
        except Exception:
            pass
        try:
            b = unzip_log_bytes(path)
            roots, log = SafeUnpickler(io.BytesIO(b)).load()
        except Exception as e:
            messagebox.showerror('Error', f'Unable to read save: {e}')
            return
        self.mode = 'save'
        self.save_path = path
        self.log_bytes = b
        # roots from save: already a flat dict of full names (e.g., store.money)
        self.roots = {}
        self.key_tokens = {}
        if isinstance(roots, dict):
            for k, v in roots.items():
                if isinstance(k, str):
                    self.roots[k] = v
                    self.key_tokens[k] = k
        self._build_item_catalog(roots)
        self.refresh_list()

    def open_persistent(self):
        # Default to game/saves or last visited
        default = os.path.join(os.getcwd(), 'game', 'saves', 'persistent')
        fallback_dir = os.path.dirname(default) if os.path.exists(default) else os.path.join(os.getcwd(), 'game', 'saves')
        initdir = self.last_persistent_dir if (self.last_persistent_dir and os.path.isdir(self.last_persistent_dir)) else fallback_dir
        path = filedialog.askopenfilename(title='Select persistent file', filetypes=[('Ren\'Py Persistent', 'persistent')], initialdir=initdir)
        if not path:
            return
        # Remember directory for next time
        try:
            self.last_persistent_dir = os.path.dirname(path)
        except Exception:
            pass
        try:
            raw = open(path, 'rb').read()
            db = zlib.decompress(raw)
            obj = SafeUnpickler(io.BytesIO(db)).load()
        except Exception as e:
            messagebox.showerror('Error', f'Unable to open persistent file: {e}')
            return
        self.mode = 'persistent'
        self.persistent_path = path
        self.persistent_bytes = db
        self.roots = {}
        self.key_tokens = {}
        self.item_base_counts = {}
        state = getattr(obj, '_state', {}) if obj is not None else {}
        # Include top-level scalar str-keyed values
        if isinstance(state, dict):
            for k, v in state.items():
                if isinstance(k, str) and isinstance(v, (int, float, bool, str)):
                    self.roots[k] = v
                    self.key_tokens[k] = k
            # Flatten one level for dict children with str keys
            for k, v in state.items():
                if isinstance(k, str) and isinstance(v, dict):
                    for k2, v2 in v.items():
                        if isinstance(k2, str) and isinstance(v2, (int, float, bool, str)):
                            name = f"{k}.{k2}"
                            self.roots[name] = v2
                            # For patching, we search by the terminal key string
                            self.key_tokens[name] = k2
        self.refresh_list()

    def refresh_list(self):
        self.tree.delete(*self.tree.get_children())
        q = (self.search_var.get() or '').lower()
        type_sel = self.type_filter.get()

        def type_ok(v):
            if type_sel == 'Tutti':
                return True
            if type_sel == 'Int':
                return isinstance(v, int) and not isinstance(v, bool)
            if type_sel == 'Float':
                return isinstance(v, float)
            if type_sel == 'Bool':
                return isinstance(v, bool)
            if type_sel == 'Str':
                return isinstance(v, str)
            return True

        for k, v in self.roots.items():
            t = type(v).__name__
            if self.only_numeric.get() and not isinstance(v, (int, float, bool)):
                continue
            if not type_ok(v):
                continue
            if q:
                vtxt = repr(v).lower()
                if (q not in k.lower()) and (q not in vtxt):
                    continue
            self.tree.insert('', 'end', values=(k, t, repr(v)))

        # re-apply current sort
        if self._sort_col:
            self._sort_by(self._sort_col, toggle=False)

    def _on_double(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        name, t, valrepr = self.tree.item(item, 'values')
        if self.mode == 'save' and name in (
            'store.Player',
            'store.inventory',
            'store.inventory_private',
            'store.private_inventory',
            'inventory',
            'inventory_private',
        ):
            player = self.roots.get('store.Player')
            if player is not None and hasattr(player, '_state'):
                self._open_private_inventory_dialog(player)
                return
        curv = self.roots.get(name)
        if not isinstance(curv, (int, float, bool, str)):
            # Offer container-specific editing
            if self.mode == 'save' and name == 'store.Player' and hasattr(curv, '_state'):
                self._open_private_inventory_dialog(curv)
                return
            messagebox.showinfo('Info', 'This variable cannot be edited here (supported: int/float/bool/str).')
            return
        # Prompt new value
        new = self._prompt_value(name, curv)
        if new is None:
            return
        # Attempt patch in log bytes
        token = self.key_tokens.get(name, name)
        try:
            if self.mode == 'persistent':
                new_bytes = patch_value_for_key(self.persistent_bytes, token, curv, new)
                self.persistent_bytes = new_bytes
            else:
                new_bytes = patch_value_for_key(self.log_bytes, token, curv, new)
                self.log_bytes = new_bytes
        except Exception as e:
            messagebox.showerror('Error', f'Failed to patch {name}: {e}')
            return
        self.roots[name] = new
        self.refresh_list()

    def _on_enter(self, event):
        # Handle editing for one or multiple selected rows
        sel = self.tree.selection()
        if not sel:
            return
        items = [self.tree.item(i, 'values') for i in sel]
        # Build editable list
        editable = []  # list of (name, current_value)
        for name, t, valrepr in items:
            curv = self.roots.get(name)
            if isinstance(curv, (int, float, bool, str)):
                editable.append((name, curv))
        if not editable:
            messagebox.showinfo('Info', 'No editable variables selected.')
            return
        # Prompt once for target value (raw string), prefill using first item's value
        sample_curv = editable[0][1]
        s = self._prompt_multi_value(len(editable), sample_curv)
        if s is None:
            return
        # Apply to all editable selections
        errors = []
        changed = 0
        buf = self.persistent_bytes if self.mode == 'persistent' else self.log_bytes
        for name, curv in editable:
            try:
                new_val = self._coerce_value_for(curv, s)
            except Exception:
                errors.append(name)
                continue
            try:
                token = self.key_tokens.get(name, name)
                buf = patch_value_for_key(buf, token, curv, new_val)
                self.roots[name] = new_val
                changed += 1
            except Exception:
                errors.append(name)
        if changed:
            if self.mode == 'persistent':
                self.persistent_bytes = buf
            else:
                self.log_bytes = buf
            self.refresh_list()
        if errors:
            msg = f"Updated {changed} entries. Not modified: {', '.join(errors[:5])}"
            if len(errors) > 5:
                msg += '...'
            messagebox.showwarning('Partial', msg)

    def _prompt_value(self, name, curv):
        dlg = tk.Toplevel(self)
        dlg.title(f'Edit {name}')
        dlg.transient(self)
        ttk.Label(dlg, text=f'Current value: {curv} ({type(curv).__name__})').pack(padx=10, pady=(10, 4))
        var = tk.StringVar(value=str(int(curv) if isinstance(curv, bool) else curv))
        ent = ttk.Entry(dlg, textvariable=var)
        ent.pack(padx=10, pady=6)
        ent.focus_set()
        rv = {'val': None}

        def ok(event=None):
            raw = var.get()
            s = raw if isinstance(curv, str) else raw.strip()
            try:
                if isinstance(curv, bool):
                    rv['val'] = (s.lower() not in ('0', 'false', ''))
                elif isinstance(curv, int) and not isinstance(curv, bool):
                    rv['val'] = int(s)
                elif isinstance(curv, float):
                    rv['val'] = float(s)
                elif isinstance(curv, str):
                    rv['val'] = raw
            except Exception:
                messagebox.showerror('Error', 'Invalid value')
                return
            dlg.destroy()

        def cancel(event=None):
            dlg.destroy()

        btns = ttk.Frame(dlg)
        btns.pack(fill='x', padx=10, pady=8)
        ttk.Button(btns, text='OK', command=ok).pack(side='left')
        ttk.Button(btns, text='Cancel', command=cancel).pack(side='right')
        dlg.bind('<Return>', ok)
        dlg.bind('<Escape>', cancel)
        try:
            dlg.wait_visibility()
        except Exception:
            pass
        self.wait_window(dlg)
        return rv['val']

    def _prompt_multi_value(self, count, sample_curv):
        dlg = tk.Toplevel(self)
        dlg.title(f'Set value for {count} selected')
        dlg.transient(self)
        ttk.Label(dlg, text=f'Sample type: {type(sample_curv).__name__}').pack(padx=10, pady=(10, 4))
        if isinstance(sample_curv, bool):
            init = str(int(sample_curv))
        else:
            init = str(sample_curv)
        var = tk.StringVar(value=init)
        ent = ttk.Entry(dlg, textvariable=var)
        ent.pack(padx=10, pady=6)
        ent.focus_set()
        rv = {'val': None}

        def ok(event=None):
            rv['val'] = var.get()
            dlg.destroy()

        def cancel(event=None):
            dlg.destroy()

        btns = ttk.Frame(dlg)
        btns.pack(fill='x', padx=10, pady=8)
        ttk.Button(btns, text='OK', command=ok).pack(side='left')
        ttk.Button(btns, text='Cancel', command=cancel).pack(side='right')
        dlg.bind('<Return>', ok)
        dlg.bind('<Escape>', cancel)
        try:
            dlg.wait_visibility()
        except Exception:
            pass
        self.wait_window(dlg)
        return rv['val']

    def _coerce_value_for(self, curv, s: str):
        if isinstance(curv, bool):
            return (s.strip().lower() not in ('0', 'false', ''))
        if isinstance(curv, int) and not isinstance(curv, bool):
            return int(s.strip())
        if isinstance(curv, float):
            return float(s.strip())
        if isinstance(curv, str):
            return s
        raise ValueError('Unsupported type')

    # ---------- Inventory helpers ----------

    def _locate_private_stack_positions(self, log_bytes, expected_count=None):
        """Return ordered list of (value_start, value_end, enc_hint) for private_inventory stack_count."""
        positions = []
        capturing = False
        stack_memo = None
        expect_stack_memo = False
        for op, arg, pos in genops(log_bytes):
            if op.name == 'BINUNICODE':
                if arg == 'stack_count':
                    expect_stack_memo = True
                else:
                    expect_stack_memo = False
                if arg == 'private_inventory':
                    capturing = True
                    continue
                if capturing and arg in ('home_inventory', 'quick_inventory', 'quest_inventory'):
                    if expected_count is not None and len(positions) >= expected_count:
                        break
                    continue
            if not capturing:
                if expect_stack_memo and op.name in ('BINPUT', 'LONG_BINPUT'):
                    stack_memo = arg
                    expect_stack_memo = False
                continue
            if expect_stack_memo and op.name in ('BINPUT', 'LONG_BINPUT'):
                stack_memo = arg
                expect_stack_memo = False
                continue
            if stack_memo is None:
                continue
            if op.name in ('BINGET', 'LONG_BINGET') and arg == stack_memo:
                if op.name == 'BINGET':
                    value_pos = pos + 2
                else:
                    value_pos = pos + 5
                parsed = _parse_value_at(log_bytes, value_pos)
                if parsed is None:
                    continue
                value, end_pos, enc = parsed
                positions.append((value_pos, end_pos, enc))
                if expected_count is not None and len(positions) >= expected_count:
                    break
        return positions

    def _build_item_catalog(self, roots):
        """Build mapping item name -> base stack size (if available)."""
        self.item_base_counts = {}
        catalog = roots.get('store.items_list')
        if isinstance(catalog, list):
            for entry in catalog:
                st = getattr(entry, '_state', None)
                if not isinstance(st, dict):
                    continue
                name = st.get('name')
                base = st.get('stack_count')
                if isinstance(name, str) and isinstance(base, int) and base > 0:
                    self.item_base_counts[name] = base

    def _locate_private_inventory_chunks(self, log_bytes):
        """Scan pickle ops and return list of chunk info for private_inventory items."""
        items = []
        mark_stack = []
        capturing = False
        pending_stack_key_memo = False
        stack_key_memo = None
        current_item = None
        waiting_value = False
        for op, arg, pos in genops(log_bytes):
            # record last position for chunk slicing
            if op.name == 'MARK':
                mark_stack.append(pos)
            elif op.name in ('SETITEMS', 'APPENDS'):
                if mark_stack:
                    mark_stack.pop()

            if op.name == 'BINUNICODE':
                if arg == 'stack_count':
                    pending_stack_key_memo = True
                if arg == 'private_inventory':
                    capturing = True
                elif arg in ('home_inventory', 'quick_inventory', 'quest_inventory'):
                    if capturing and current_item is not None:
                        # finalize if we somehow exited unexpectedly
                        current_item = None
                    capturing = False
                continue
            if pending_stack_key_memo and op.name in ('BINPUT', 'LONG_BINPUT'):
                stack_key_memo = arg
                pending_stack_key_memo = False
                continue

            if not capturing:
                continue

            if waiting_value and current_item is not None:
                parsed = _parse_value_at(log_bytes, pos)
                if parsed is None:
                    continue
                val, vend, enc = parsed
                current_item['value_start'] = pos
                current_item['value_end'] = vend
                current_item['enc'] = enc
                current_item['stack_value'] = val
                waiting_value = False
                continue

            if stack_key_memo is not None and op.name in ('BINGET', 'LONG_BINGET') and arg == stack_key_memo:
                if not mark_stack:
                    continue
                current_item = {
                    'start': mark_stack[-1],
                    'memo': stack_key_memo,
                    'value_start': None,
                    'value_end': None,
                    'enc': None,
                    'stack_value': None,
                    'end': None,
                }
                waiting_value = True
                continue

            if current_item and op.name == 'BUILD':
                current_item['end'] = pos + 1
                items.append(current_item)
                current_item = None
                waiting_value = False
        return items

    def _extract_private_inventory_entries(self, player, log_bytes):
        """Return list of dicts describing items in Player.private_inventory, including chunk metadata."""
        state = getattr(player, '_state', None)
        if not isinstance(state, dict):
            return []
        bag = state.get('private_inventory')
        if not isinstance(bag, dict):
            return []
        try:
            slot_keys = sorted(bag.keys(), key=lambda x: int(x))
        except Exception:
            slot_keys = list(bag.keys())

        chunk_infos = self._locate_private_inventory_chunks(log_bytes)
        entries = []
        flat_index = 0
        for slot in slot_keys:
            lst = bag.get(slot)
            if not isinstance(lst, list):
                continue
            for idx, item in enumerate(lst):
                st = getattr(item, '_state', None)
                if not isinstance(st, dict):
                    continue
                stack = st.get('stack_count')
                if not isinstance(stack, int):
                    continue
                name = st.get('name', '<unnamed>')
                base = self.item_base_counts.get(name, 1) or 1
                quantity = stack // base if base else stack
                chunk = chunk_infos[flat_index] if flat_index < len(chunk_infos) else None
                if chunk is None:
                    flat_index += 1
                    continue
                chunk_start = chunk['start']
                chunk_end = chunk['end'] or chunk['value_end']
                entries.append({
                    'slot': slot,
                    'idx': idx,
                    'name': name,
                    'stack': stack,
                    'item_state': st,
                    'item_obj': item,
                    'base': base,
                    'quantity': quantity,
                    'chunk_start': chunk_start,
                    'chunk_end': chunk_end,
                    'value_start': chunk.get('value_start'),
                    'value_end': chunk.get('value_end'),
                    'chunk_bytes': log_bytes[chunk_start:chunk_end],
                })
                flat_index += 1
        return entries

    def _aggregate_inventory_groups(self, items):
        from collections import OrderedDict
        groups_map = OrderedDict()
        for entry in items:
            key = (entry['slot'], entry['name'])
            grp = groups_map.setdefault(key, {
                'slot': entry['slot'],
                'name': entry['name'],
                'base': entry['base'],
                'items': [],
            })
            grp['items'].append(entry)
        groups = []
        for grp in groups_map.values():
            items_list = grp['items']
            quantity = len(items_list)
            base = grp['base']
            total = quantity * base
            grp.update({
                'quantity': quantity,
                'total': total,
            })
            groups.append(grp)
        return groups

    # (legacy byte-level mutator removed in favor of object-level edits)

    def _patch_inventory_stack(self, buf, expected_count, entry_index, current_value, new_value):
        positions = self._locate_private_stack_positions(buf, expected_count=expected_count)
        if not positions:
            raise ValueError('Inventory not found in pickle.')
        if len(positions) != expected_count:
            raise ValueError("Inventory layout changed; reload the save.")
        if entry_index >= len(positions):
            raise IndexError('Invalid inventory index')
        start, end, enc = positions[entry_index]
        parsed = _parse_value_at(buf, start)
        if parsed is None:
            raise ValueError('Unable to read current value')
        cur_val, cur_end, cur_enc = parsed
        if cur_val != current_value:
            raise ValueError('Current value differs from expected; reload the save')
        rep = _encode_scalar(new_value, enc_hint=cur_enc)
        return buf[:start] + rep + buf[end:]

    def _open_private_inventory_dialog(self, player):
        if self.mode != 'save':
            messagebox.showinfo('Info', 'The inventory can only be edited in .save files.')
            return
        def rebuild_state():
            try:
                new_roots, _ = SafeUnpickler(io.BytesIO(self.log_bytes)).load()
            except Exception as e:
                messagebox.showerror('Error', f'Failed to reload save: {e}')
                return None, None, None
            new_player = new_roots.get('store.Player')
            if isinstance(self.roots, dict):
                self.roots['store.Player'] = new_player
            self._build_item_catalog(new_roots)
            items = self._extract_private_inventory_entries(new_player, self.log_bytes)
            groups = self._aggregate_inventory_groups(items)
            return new_player, groups, items

        player, groups, items = rebuild_state()
        if player is None or groups is None:
            return
        if not groups:
            messagebox.showinfo('Info', 'Private inventory empty or unrecognized.')
            return

        dlg = tk.Toplevel(self)
        dlg.title('Private inventory')
        dlg.transient(self)
        try:
            dlg.grab_set()
        except Exception:
            pass

        columns = ('slot', 'name', 'quantity', 'base', 'total')
        tree = ttk.Treeview(dlg, columns=columns, show='headings', selectmode='browse')
        tree.heading('slot', text='Slot')
        tree.heading('name', text='Item')
        tree.heading('quantity', text='Qty')
        tree.heading('base', text='Base stack')
        tree.heading('total', text='Total')
        tree.column('slot', width=80, anchor='center')
        tree.column('name', width=280, anchor='w')
        tree.column('quantity', width=90, anchor='center')
        tree.column('base', width=100, anchor='center')
        tree.column('total', width=110, anchor='center')

        yscroll = ttk.Scrollbar(dlg, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=yscroll.set)
        tree.grid(row=0, column=0, sticky='nsew')
        yscroll.grid(row=0, column=1, sticky='ns')
        dlg.rowconfigure(0, weight=1)
        dlg.columnconfigure(0, weight=1)

        def populate():
            tree.delete(*tree.get_children())
            for i, grp in enumerate(groups):
                tree.insert('', 'end', iid=str(i), values=(
                    grp['slot'],
                    grp['name'],
                    grp['quantity'],
                    grp['base'],
                    grp['total'],
                ))

        def apply_group_edit(idx, new_qty):
            nonlocal player, groups, items
            grp = groups[idx]
            if new_qty < 0:
                messagebox.showerror('Error', 'Quantity must be positive.')
                return False
            try:
                roots, payload = SafeUnpickler(io.BytesIO(self.log_bytes)).load()
            except Exception as e:
                messagebox.showerror('Error', f'Failed to reload save: {e}')
                return False
            self._build_item_catalog(roots)
            player_obj = roots.get('store.Player')
            if not player_obj or not hasattr(player_obj, '_state'):
                messagebox.showerror('Error', 'Player structure not recognized.')
                return False
            state = getattr(player_obj, '_state', {})
            bag = state.get('private_inventory')
            if not isinstance(bag, dict):
                messagebox.showerror('Error', 'Private inventory unavailable.')
                return False
            lst = bag.get(grp['slot'])
            if not isinstance(lst, list):
                messagebox.showerror('Error', f'Slot {grp["slot"]} not recognized.')
                return False
            current_qty = grp['quantity']
            if new_qty == current_qty:
                return False

            def item_name(item_obj):
                st = getattr(item_obj, '_state', None)
                if isinstance(st, dict):
                    return st.get('name')
                return None

            # Collect existing items with same name
            matching = [item for item in lst if item_name(item) == grp['name']]
            if not matching:
                messagebox.showerror('Error', 'Unable to find an item to use as a template.')
                return False

            if new_qty < len(matching):
                keep = []
                to_keep = new_qty
                for item in lst:
                    if item_name(item) == grp['name']:
                        if to_keep > 0:
                            keep.append(item)
                            to_keep -= 1
                    else:
                        keep.append(item)
                lst[:] = keep
            else:
                template = matching[0]
                clones_needed = new_qty - len(matching)
                try:
                    template_bytes = pickle.dumps(template, protocol=pickle.HIGHEST_PROTOCOL)
                except Exception as e:
                    messagebox.showerror('Error', f'Failed to clone object: {e}')
                    return False
                for _ in range(clones_needed):
                    clone = pickle.loads(template_bytes)
                    st = getattr(clone, '_state', None)
                    if isinstance(st, dict) and '_state' in st and isinstance(st['_state'], dict):
                        clone._state = copy.deepcopy(st['_state'])
                    lst.append(clone)

            try:
                new_log = pickle.dumps((roots, payload), protocol=pickle.HIGHEST_PROTOCOL)
            except Exception as e:
                messagebox.showerror('Error', f'Failed to regenerate log: {e}')
                return False

            self.log_bytes = new_log
            self.roots['store.Player'] = player_obj
            rebuilt = rebuild_state()
            if rebuilt[0] is None:
                return False
            player, groups, items = rebuilt
            populate()
            self.refresh_list()
            return True

        populate()

        def on_edit(event=None):
            sel = tree.selection()
            if not sel:
                return
            idx = int(sel[0])
            grp = groups[idx]
            new_qty = simpledialog.askinteger(
                'Edit quantity',
                (
                    f"{grp['name']} (slot {grp['slot']})\n"
                    f"Current quantity: {grp['quantity']} (base stack {grp['base']})\n"
                    "Enter new quantity:"
                ),
                parent=dlg,
                initialvalue=grp['quantity'],
                minvalue=0,
            )
            if new_qty is None or new_qty == grp['quantity']:
                return
            apply_group_edit(idx, new_qty)

        def on_key_edit(event):
            on_edit()

        def close_dialog(event=None):
            dlg.destroy()

        btns = ttk.Frame(dlg)
        btns.grid(row=1, column=0, columnspan=2, sticky='ew', pady=6)
        ttk.Button(btns, text='Edit', command=on_edit).pack(side='left', padx=(0, 6))
        ttk.Button(btns, text='Close', command=close_dialog).pack(side='right')

        tree.bind('<Double-1>', on_edit)
        tree.bind('<Return>', on_key_edit)
        dlg.bind('<Escape>', close_dialog)
        tree.focus_set()

        try:
            dlg.wait_window()
        except Exception:
            pass

    def _sort_by(self, col, toggle=True):
        # Determine descending
        if toggle:
            if self._sort_col == col:
                self._sort_desc = not self._sort_desc
            else:
                self._sort_desc = False
        self._sort_col = col

        items = [(self.tree.set(i, 'name'), self.tree.set(i, 'type'), self.tree.set(i, 'value'), i)
                 for i in self.tree.get_children('')]

        def key_func(row):
            name, typ, valrepr, iid = row
            lower_name = name.lower() if isinstance(name, str) else str(name)
            if col == 'name':
                return lower_name
            if col == 'type':
                return typ.lower() if isinstance(typ, str) else str(typ)
            if col == 'value':
                v = self.roots.get(name)
                if isinstance(v, bool):
                    return (0, int(v))
                if isinstance(v, (int, float)):
                    return (1, v)
                if isinstance(v, str):
                    return (2, v.lower())
                if v is None:
                    return (3, '')
                return (4, str(valrepr).lower())
            return lower_name

        items.sort(key=key_func, reverse=self._sort_desc)
        for idx, (_, _, _, iid) in enumerate(items):
            self.tree.move(iid, '', idx)

    def save_changes(self):
        if self.mode == 'save':
            if not self.save_path or self.log_bytes is None:
                return
            bak = self.save_path + '.bak'
            if not os.path.exists(bak):
                import shutil
                shutil.copy2(self.save_path, bak)
            tmp = self.save_path + '.tmp'
            repack_log_bytes(self.save_path, tmp, self.log_bytes)
            os.replace(tmp, self.save_path)
            messagebox.showinfo('Saved', f'Changes saved to {self.save_path}\nBackup: {bak}')
        elif self.mode == 'persistent':
            if not self.persistent_path or self.persistent_bytes is None:
                return
            bak = self.persistent_path + '.bak'
            if not os.path.exists(bak):
                import shutil
                shutil.copy2(self.persistent_path, bak)
            # recompress with zlib and write
            comp = zlib.compress(self.persistent_bytes)
            with open(self.persistent_path + '.tmp', 'wb') as f:
                f.write(comp)
            os.replace(self.persistent_path + '.tmp', self.persistent_path)
            messagebox.showinfo('Saved', f'Changes saved to {self.persistent_path}\nBackup: {bak}')


def main():
    app = SaveEditorApp()
    app.mainloop()


if __name__ == '__main__':
    main()
