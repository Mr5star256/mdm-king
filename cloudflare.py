"""Cloudflare API client for MDM KING — pure Cloudflare config, no local config.json."""

import os, sys, json, urllib.request, time, tempfile, zipfile

CLOUDFLARE_API_URL = "https://mdm-king-api.bonnetadson.workers.dev"

def _get_api_key():
    return os.environ.get('CF_ADMIN_KEY', '')

def _headers():
    headers = {'User-Agent': 'MDM-King', 'Content-Type': 'application/json'}
    key = _get_api_key()
    if key:
        headers['X-Admin-Key'] = key
    return headers

def cf_fetch(path, timeout=15):
    url = CLOUDFLARE_API_URL + path
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers=_headers())
            resp = urllib.request.urlopen(req, timeout=timeout)
            return json.loads(resp.read().decode('utf-8'))
        except Exception:
            if attempt == 2:
                return None
            time.sleep(1)

def cf_send(method, path, data=None, timeout=15, extra_headers=None):
    url = CLOUDFLARE_API_URL + path
    body = json.dumps(data).encode('utf-8') if data else None
    headers = _headers()
    if extra_headers:
        headers.update(extra_headers)
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            resp = urllib.request.urlopen(req, timeout=timeout)
            return json.loads(resp.read().decode('utf-8'))
        except Exception:
            if attempt == 2:
                return None
            time.sleep(1)

# ─── Config (full read/write) ───
def fetch_config():
    return cf_fetch('/config.json')

def update_config(cfg):
    return cf_send('PUT', '/config.json', data=cfg)

# ─── User helpers (direct Cloudflare) ───
def get_user(email):
    cfg = fetch_config()
    if not cfg:
        return None
    users = cfg.get('users', {})
    admins = cfg.get('admin', {})
    if email in users:
        return users[email]
    if email in admins:
        return admins[email]
    return None

def update_user(email, data, section=None):
    cfg = fetch_config()
    if not cfg:
        return False
    if section is None:
        section = 'admin' if email in cfg.get('admin', {}) else 'users'
    if section not in cfg:
        cfg[section] = {}
    cfg[section][email] = data
    return update_config(cfg)

def patch_user(email, patch):
    cfg = fetch_config()
    if not cfg:
        return False
    section = 'admin' if email in cfg.get('admin', {}) else 'users'
    if section not in cfg:
        cfg[section] = {}
    if email not in cfg[section] or not isinstance(cfg[section][email], dict):
        cfg[section][email] = {}
    cfg[section][email].update(patch)
    return update_config(cfg)

def delete_user(email):
    cfg = fetch_config()
    if not cfg:
        return False
    for section in ('users', 'admin'):
        if email in cfg.get(section, {}):
            del cfg[section][email]
    deleted = cfg.get('deleted_users', [])
    if email not in deleted:
        deleted.append(email)
    cfg['deleted_users'] = deleted
    return update_config(cfg)

def get_all_users():
    cfg = fetch_config()
    if not cfg:
        return {}
    result = {}
    for email, data in cfg.get('users', {}).items():
        result[email] = data
    for email, data in cfg.get('admin', {}).items():
        result[email] = data
    return result

def get_smtp():
    cfg = fetch_config()
    if not cfg:
        return {}
    return cfg.get('smtp', {})

def get_blocklist():
    cfg = fetch_config()
    if not cfg:
        return {}
    return cfg.get('blocklist', {})

def update_blocklist(bl):
    cfg = fetch_config()
    if not cfg:
        return False
    cfg['blocklist'] = bl
    return update_config(cfg)

def get_features():
    cfg = fetch_config()
    if not cfg:
        return {}
    return cfg.get('features', {})

def get_options():
    cfg = fetch_config()
    if not cfg:
        return {}
    return cfg.get('options', {})

# ─── License (D1) ───
def validate_license(key, hwid=None, machine_id=None, email=None):
    return cf_send('POST', '/api/license/validate', data={
        'key': key, 'hwid': hwid, 'machine_id': machine_id, 'email': email,
    })

def create_license(key, plan='basic', features=None, expires_at_days=None):
    return cf_send('POST', '/api/license', data={
        'key': key, 'plan': plan, 'features': features, 'expires_at_days': expires_at_days,
    })

def delete_license(key):
    return cf_send('DELETE', f'/api/license?key={key}')

# ─── Logging ───
def write_log(action, username='', device='', details=''):
    return cf_send('POST', '/api/log', data={
        'action': action, 'username': username,
        'device': device, 'details': details,
    })

def fetch_logs(limit=100, offset=0):
    return cf_fetch(f'/api/logs?limit={limit}&offset={offset}')

def fetch_stats(days=7):
    return cf_fetch(f'/api/stats?days={days}')

# ─── File download URL ───
def download_url(key):
    return f"{CLOUDFLARE_API_URL}/download/{key}"

# ─── Auth (signup/login via D1) ───
def auth_signup(username, email=None, password=None):
    """Register a new user account."""
    return cf_send('POST', '/api/auth/signup', data={
        'username': username, 'email': email, 'password': password,
    })

def auth_login(username=None, password=None, email=None):
    """Login and get auth token."""
    data = {'password': password}
    if email:
        data['email'] = email
    elif username:
        data['username'] = username
    return cf_send('POST', '/api/auth/login', data=data, extra_headers={'X-Client-Type': 'tool', 'X-Machine-ID': _get_machine_id()})

def auth_me(token):
    """Get current user info from token."""
    url = CLOUDFLARE_API_URL + '/api/auth/me'
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'MDM-King',
            'Content-Type': 'application/json',
            'X-Auth-Token': token,
            'X-Client-Type': 'tool',
            'X-Machine-ID': _get_machine_id(),
        })
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read().decode('utf-8'))
    except Exception:
        return None

def upload_file(key, file_path, timeout=120):
    """Upload a file to Cloudflare R2 via Worker."""
    url = f"{CLOUDFLARE_API_URL}/upload/{key}"
    for attempt in range(3):
        try:
            import urllib.request
            with open(file_path, 'rb') as f:
                data = f.read()
            req = urllib.request.Request(url, data=data, headers={
                'User-Agent': 'MDM-King',
                'Content-Type': 'application/octet-stream',
                'X-Admin-Key': _get_api_key(),
            }, method='PUT')
            resp = urllib.request.urlopen(req, timeout=timeout)
            return json.loads(resp.read().decode('utf-8'))
        except Exception as e:
            if attempt == 2:
                raise e
            time.sleep(2)
    return None

def delete_file(key, timeout=15):
    """Delete a file from Cloudflare R2 via Worker."""
    url = f"{CLOUDFLARE_API_URL}/delete/{key}"
    return cf_send('DELETE', f'/delete/{key}', timeout=timeout)

# ─── Cloudflare asset download (copy protection) ───
CF_TOOLS_DIR = None

def _download_file(remote_path, dest_path, timeout=30):
    url = CLOUDFLARE_API_URL + remote_path
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'MDM-King'})
            resp = urllib.request.urlopen(req, timeout=timeout)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with open(dest_path, 'wb') as f:
                f.write(resp.read())
            return True
        except Exception:
            if attempt == 2:
                return False
            time.sleep(1)
    return False

def init_cloudflare_assets():
    global CF_TOOLS_DIR
    base = os.path.join(tempfile.gettempdir(), 'mdm_king_cf')
    os.makedirs(base, exist_ok=True)
    zip_path = os.path.join(base, 'tools.zip')
    if not os.path.isdir(os.path.join(base, 'tools')):
        if _download_file('/download/tools.zip', zip_path):
            try:
                with zipfile.ZipFile(zip_path, 'r') as zf:
                    zf.extractall(base)
            except Exception:
                pass
            try:
                os.remove(zip_path)
            except Exception:
                pass
    tools_dir = os.path.join(base, 'tools')
    if os.path.isdir(tools_dir):
        CF_TOOLS_DIR = tools_dir
    return CF_TOOLS_DIR is not None

def get_tools_dir():
    return CF_TOOLS_DIR
