#!/usr/bin/env python3
import sys
import os
import io
import zipfile
import base64

def _find_security_keys():
    """Best-effort search for Ren'Py signing keys file."""
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
    """Parse signing keys from security_keys.txt. Returns list of DER bytes."""
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


def _signatures_for_log(log_bytes):
    """Create Ren'Py-compatible signatures string for given log, or b'' if unavailable.

    Attempts to import ecdsa and use local security keys. If ecdsa or keys are
    unavailable, returns empty bytes which Ren'Py treats as acceptable (no warning).
    """
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
import struct
import argparse
import pickle
import importlib
import ast


def read_zip_log(path):
    with zipfile.ZipFile(path, 'r') as zf:
        data = zf.read('log')
    return data


def write_zip_log(src_path, dst_path, new_log_bytes):
    with zipfile.ZipFile(src_path, 'r') as zin:
        with zipfile.ZipFile(dst_path, 'w', compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == 'log':
                    # write replaced log
                    zi = zipfile.ZipInfo(item.filename)
                    zi.date_time = item.date_time
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.external_attr = item.external_attr
                    zout.writestr(zi, new_log_bytes)
                elif item.filename == 'signatures':
                    # Regenerate signatures for the new log, or write empty to suppress warning
                    sig = _signatures_for_log(new_log_bytes)
                    zi = zipfile.ZipInfo(item.filename)
                    zi.date_time = item.date_time
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zi.external_attr = item.external_attr
                    zout.writestr(zi, sig)
                else:
                    zout.writestr(item, zin.read(item.filename))


def _le32(n):
    return struct.pack('<I', n)


BINUNICODE = 0x58
BINVAL1 = 0x4B  # BININT1
BINVAL2 = 0x4D  # BININT2
BINVAL4 = 0x4A  # BININT
BINFLOAT = 0x47
NEWTRUE = 0x88
NEWFALSE = 0x89
LONG1 = 0x8A
LONG4 = 0x8B
BINSTRING = 0x54
SHORT_BINSTRING = 0x55
STRING = 0x53
SHORT_BINUNICODE = 0x8C


def _parse_value_at(data: bytes, pos: int):
    n = len(data)
    if pos >= n:
        return None
    op = data[pos]
    if op == BINVAL1 and pos + 2 <= n:
        return (data[pos + 1], pos + 2, 'BININT1')
    if op == BINVAL2 and pos + 3 <= n:
        return (struct.unpack('<H', data[pos + 1:pos + 3])[0], pos + 3, 'BININT2')
    if op == BINVAL4 and pos + 5 <= n:
        return (struct.unpack('<i', data[pos + 1:pos + 5])[0], pos + 5, 'BININT4')
    if op == BINFLOAT and pos + 9 <= n:
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
    if op == LONG1 and pos + 2 <= n:
        ln = data[pos + 1]
        if pos + 2 + ln <= n:
            mag = int.from_bytes(data[pos + 2:pos + 2 + ln], 'little', signed=True)
            return (mag, pos + 2 + ln, 'LONG1')
    if op == LONG4 and pos + 5 <= n:
        ln = struct.unpack('<I', data[pos + 1:pos + 5])[0]
        if pos + 5 + ln <= n:
            mag = int.from_bytes(data[pos + 5:pos + 5 + ln], 'little', signed=True)
            return (mag, pos + 5 + ln, 'LONG4')
    return None


def iter_numeric_entries(log_bytes, key_prefix=b'store.'):
    """Yield (key, value, value_pos, value_bytes) for scalar numeric/bool/float values.

    Uses a resilient scan similar to the GUI: after a key BINUNICODE, skip
    optional memo ops and scan forward a small window to find the first scalar.
    """
    def _read_key(data, pos):
        n = len(data)
        if pos >= n:
            return None
        op = data[pos]
        if op == BINUNICODE and pos + 5 <= n:
            ln = struct.unpack('<I', data[pos + 1:pos + 5])[0]
            start = pos + 5
            end = start + ln
            if end <= n:
                return data[start:end], end
        if op == SHORT_BINUNICODE and pos + 2 <= n:
            ln = data[pos + 1]
            start = pos + 2
            end = start + ln
            if end <= n:
                return data[start:end], end
        if op == BINSTRING and pos + 5 <= n:
            ln = struct.unpack('<I', data[pos + 1:pos + 5])[0]
            start = pos + 5
            end = start + ln
            if end <= n:
                return data[start:end], end
        if op == SHORT_BINSTRING and pos + 2 <= n:
            ln = data[pos + 1]
            start = pos + 2
            end = start + ln
            if end <= n:
                return data[start:end], end
        if op == STRING:
            end = data.find(b'\n', pos)
            if end != -1:
                raw = data[pos + 1:end]
                try:
                    text = ast.literal_eval(raw.decode('ascii'))
                    if isinstance(text, str):
                        return text.encode('utf-8'), end + 1
                except Exception:
                    return None
        return None

    i = 0
    n = len(log_bytes)
    while i < n:
        parsed = _read_key(log_bytes, i)
        if parsed:
            kbytes, next_pos = parsed
            # Basic sanity: filter by prefix if provided
            if (not key_prefix or kbytes.startswith(key_prefix)) and b'\x00' not in kbytes:
                pos = next_pos
                # Skip BINPUT 'q' and LONG_BINPUT 'r' if present
                if pos + 1 <= n and log_bytes[pos] == ord('q'):
                    pos += 2
                if pos + 5 <= n and log_bytes[pos] == ord('r'):
                    pos += 5
                # Scan ahead a limited window for first scalar
                for look in range(0, 1024):
                    pv = _parse_value_at(log_bytes, pos + look)
                    if pv is None:
                        continue
                    val, vend, enc = pv
                    if isinstance(val, (int, float, bool)):
                        key = kbytes.decode('utf-8', 'replace')
                        yield (key, val, pos + look, log_bytes[pos + look:vend])
                        break
            i = next_pos
        else:
            i += 1


def _encode_scalar(value):
    if isinstance(value, bool):
        return b"\x88" if value else b"\x89"
    if isinstance(value, int):
        if 0 <= value <= 0xFF:
            return b"\x4b" + bytes([value])
        if 0 <= value <= 0xFFFF:
            return b"\x4d" + struct.pack('<H', value)
        if -0x80000000 <= value <= 0x7FFFFFFF:
            return b"\x4a" + struct.pack('<i', int(value))
        # LONG4 minimal two's complement for very large ints
        mag = int(value).to_bytes((int(value).bit_length() + 8) // 8 or 1, 'little', signed=True)
        return b"\x8b" + struct.pack('<I', len(mag)) + mag
    raise ValueError('Only int/bool supported in CLI set')


def patch_numeric_value(log_bytes, key, new_value):
    # Replace the scalar bytes that follow the given key, using parsed span length.
    rep = _encode_scalar(new_value)
    for k, cur, pos, vbytes in iter_numeric_entries(log_bytes, key_prefix=b''):
        if k == key:
            return log_bytes[:pos] + rep + log_bytes[pos + len(vbytes):]
    raise KeyError(f"Key not found or unsupported encoding for: {key}")


# ---------- Safe unpickler to reliably read roots mapping ----------

class _Proxy:
    def __init__(self, *a, **k):
        self._state = None
        self._list = []
    def __setstate__(self, state):
        setattr(self, '_state', state)
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

class SafeUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if (module, name) in _SPECIAL:
            return _SPECIAL[(module, name)]
        if name in ('RevertableList', 'RevertableDict', 'RevertableSet'):
            mapping = {
                'RevertableList': _RevertableList,
                'RevertableDict': _RevertableDict,
                'RevertableSet': _RevertableSet,
            }
            return mapping[name]
        if module == 'builtins':
            return getattr(importlib.import_module(module), name)
        return type(name, (_Proxy,), {})


def list_roots_numeric(log_bytes, prefix: str = 'store.'):
    """Return list of (key, value) for numeric/bool/float from roots mapping, filtered by prefix."""
    roots, _log = SafeUnpickler(io.BytesIO(log_bytes)).load()
    out = []
    if isinstance(roots, dict):
        for k, v in roots.items():
            if not isinstance(k, str):
                continue
            if prefix and not k.startswith(prefix):
                continue
            if isinstance(v, (int, float, bool)):
                out.append((k, v))
    return out


def cmd_list(args):
    log = read_zip_log(args.save)
    # Prefer robust roots-based listing
    try:
        entries = list_roots_numeric(log, prefix=args.prefix)
        for k, v in entries:
            print(f"{k}\t{v}")
    except Exception:
        # Fallback to heuristic scan
        entries = list(iter_numeric_entries(log, key_prefix=args.prefix.encode('utf-8')))
        for k, v, pos, vbytes in entries:
            print(f"{k}\t{v}")


def cmd_get(args):
    log = read_zip_log(args.save)
    # Try from roots first
    try:
        roots, _ = SafeUnpickler(io.BytesIO(log)).load()
        if isinstance(roots, dict) and args.key in roots:
            print(roots[args.key])
            return
    except Exception:
        pass
    # Fallback to scan
    for k, v, pos, vbytes in iter_numeric_entries(log, key_prefix=b''):
        if k == args.key:
            print(v)
            return
    print('NOT_FOUND', file=sys.stderr)
    sys.exit(1)


def cmd_set(args):
    log = read_zip_log(args.save)
    new_log = patch_numeric_value(log, args.key, args.value)
    # Backup original
    bak = args.save + '.bak'
    if not os.path.exists(bak):
        import shutil
        shutil.copy2(args.save, bak)
    # Write to temp and replace
    tmp = args.save + '.tmp'
    write_zip_log(args.save, tmp, new_log)
    os.replace(tmp, args.save)
    print('OK')


def main():
    ap = argparse.ArgumentParser(description='Ren\'Py .save numeric editor (safe token-preserving)')
    sub = ap.add_subparsers(dest='cmd', required=True)

    ap_list = sub.add_parser('list', help='List numeric/bool variables')
    ap_list.add_argument('save', help='.save file path')
    ap_list.add_argument('--prefix', default='store.', help='Variable name prefix to filter (default: store.)')
    ap_list.set_defaults(func=cmd_list)

    ap_get = sub.add_parser('get', help='Get a variable value')
    ap_get.add_argument('save', help='.save file path')
    ap_get.add_argument('key', help='Exact variable name (e.g., store.money)')
    ap_get.set_defaults(func=cmd_get)

    ap_set = sub.add_parser('set', help='Set a numeric/bool variable')
    ap_set.add_argument('save', help='.save file path')
    ap_set.add_argument('key', help='Exact variable name (e.g., store.money)')
    ap_set.add_argument('value', type=int, help='New integer value (bool: 0/1)')
    ap_set.set_defaults(func=cmd_set)

    args = ap.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
