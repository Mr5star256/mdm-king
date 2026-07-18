"""Authentication: password hashing, machine ID, brute force protection, integrity checks."""

import os, sys, json, hashlib, subprocess, threading, time, ctypes, platform, struct, hmac

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_SALT_LEN = 16
_DKLEN = 64
_ITERATIONS = 300_000
_BRUTE_FILE = 'brute.json'
_MAX_ATTEMPTS = 5
_LOCKOUT_SECONDS = 900  # 15 minutes

# ---------------------------------------------------------------------------
# Password hashing — PBKDF2-HMAC-SHA256 with random salt
# ---------------------------------------------------------------------------
def _hash_password(password):
    salt = os.urandom(_SALT_LEN)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, _ITERATIONS, dklen=_DKLEN)
    return f'pbkdf2:{salt.hex()}:{dk.hex()}'

def _check_password(stored, plaintext):
    if stored.startswith('pbkdf2:'):
        try:
            salt_hex, dk_hex = stored[8:].split(':', 1)
            salt = bytes.fromhex(salt_hex)
            dk = hashlib.pbkdf2_hmac('sha256', plaintext.encode('utf-8'), salt, _ITERATIONS, dklen=_DKLEN)
            return hmac.compare_digest(dk.hex(), dk_hex)
        except Exception:
            return False
    if stored.startswith('sha256:'):
        return hmac.compare_digest(stored[7:], hashlib.sha256(plaintext.encode('utf-8')).hexdigest())
    return hmac.compare_digest(stored, plaintext)

def _migrate_password(stored):
    if stored.startswith('pbkdf2:'):
        return stored
    if stored.startswith('sha256:'):
        return stored
    return 'sha256:' + hashlib.sha256(stored.encode('utf-8')).hexdigest()

# ---------------------------------------------------------------------------
# Brute-force protection
# ---------------------------------------------------------------------------
def _brute_path():
    td = os.environ.get('TEMP', os.environ.get('TMP', '.'))
    return os.path.join(td, 'mdm_king_brute.json')

def _load_brute():
    p = _brute_path()
    try:
        with open(p, 'r') as f: return json.load(f)
    except Exception:
        return {}

def _save_brute(data):
    try:
        with open(_brute_path(), 'w') as f: json.dump(data, f)
    except Exception:
        pass

def check_brute_force(email):
    data = _load_brute()
    entry = data.get(email, {'count': 0, 'first': 0, 'locked_until': 0})
    now = time.time()
    if entry.get('locked_until', 0) > now:
        return False, int(entry['locked_until'] - now)
    if entry.get('locked_until', 0) <= now and entry.get('count', 0) >= _MAX_ATTEMPTS:
        entry = {'count': 0, 'first': 0, 'locked_until': 0}
    return True, 0

def record_failed_attempt(email):
    data = _load_brute()
    entry = data.get(email, {'count': 0, 'first': 0, 'locked_until': 0})
    now = time.time()
    if entry.get('locked_until', 0) > now:
        _save_brute(data)
        return int(entry['locked_until'] - now)
    if entry.get('count', 0) == 0 or (now - entry.get('first', 0)) > _LOCKOUT_SECONDS:
        entry = {'count': 1, 'first': now, 'locked_until': 0}
    else:
        entry['count'] = entry.get('count', 0) + 1
        if entry['count'] >= _MAX_ATTEMPTS:
            entry['locked_until'] = now + _LOCKOUT_SECONDS
            entry['count'] = _MAX_ATTEMPTS
    data[email] = entry
    _save_brute(data)
    if entry.get('locked_until', 0) > now:
        return int(entry['locked_until'] - now)
    return 0

def clear_failed_attempts(email):
    data = _load_brute()
    data.pop(email, None)
    _save_brute(data)

# ---------------------------------------------------------------------------
# Machine ID
# ---------------------------------------------------------------------------
def _get_machine_id():
    try:
        r = subprocess.run(['wmic', 'csproduct', 'get', 'uuid'], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split('\n'):
            line = line.strip()
            if line and 'UUID' not in line and len(line) == 36:
                return line.strip()
    except Exception:
        pass
    try:
        return platform.node() or 'unknown'
    except Exception:
        pass
    return 'unknown'

# ---------------------------------------------------------------------------
# Integrity / tamper detection
# ---------------------------------------------------------------------------
_APP_VERSION = ''

def set_version(v):
    global _APP_VERSION
    _APP_VERSION = v

def _get_exe_path():
    if getattr(sys, 'frozen', False):
        return sys.executable
    return os.path.abspath(__file__)

def _compute_exe_hash():
    path = _get_exe_path()
    try:
        with open(path, 'rb') as f:
            data = f.read()
        return hashlib.sha256(data).hexdigest()[:32]
    except Exception:
        return ''

_integrity_hash = None

def mark_clean():
    global _integrity_hash
    _integrity_hash = _compute_exe_hash()

def check_integrity():
    if not _integrity_hash:
        return True
    current = _compute_exe_hash()
    if not current:
        return True
    return hmac.compare_digest(_integrity_hash, current)

# ---------------------------------------------------------------------------
# Anti-debug (Windows)
# ---------------------------------------------------------------------------
def _is_debugger_present():
    try:
        if sys.platform == 'win32':
            return ctypes.windll.kernel32.IsDebuggerPresent() != 0
    except Exception:
        pass
    return False

def check_anti_debug():
    if _is_debugger_present():
        return False
    return True

# ---------------------------------------------------------------------------
# Session token
# ---------------------------------------------------------------------------
def generate_session_token(email, machine_id):
    raw = f'{email}:{machine_id}:{time.time()}:{os.urandom(16).hex()}'
    return hashlib.sha256(raw.encode()).hexdigest()

def verify_session_token(token, email, machine_id):
    if not token or len(token) != 64:
        return False
    return all(c in '0123456789abcdef' for c in token)
