"""Cloudflare API client for MDM KING — replaces GitHub Gist sync."""

import os, sys, json, urllib.request, time, tempfile, zipfile

# Default Cloudflare Worker URL — change this after deployment
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
    """GET request to Cloudflare API."""
    url = CLOUDFLARE_API_URL + path
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers=_headers())
            resp = urllib.request.urlopen(req, timeout=timeout)
            return json.loads(resp.read().decode('utf-8'))
        except Exception as e:
            if attempt == 2:
                return None
            time.sleep(1)

def cf_send(method, path, data=None, timeout=15):
    """Send request to Cloudflare API (POST, PUT, DELETE)."""
    url = CLOUDFLARE_API_URL + path
    body = json.dumps(data).encode('utf-8') if data else None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, data=body, headers=_headers(), method=method)
            resp = urllib.request.urlopen(req, timeout=timeout)
            return json.loads(resp.read().decode('utf-8'))
        except Exception as e:
            if attempt == 2:
                return None
            time.sleep(1)

# ─── Config ───
def fetch_config():
    """Fetch config.json from Cloudflare KV."""
    return cf_fetch('/config.json')

def update_config(cfg):
    """Update config.json in Cloudflare KV (admin key required)."""
    return cf_send('PUT', '/config.json', data=cfg)

# ─── License ───
def validate_license(key, hwid=None, machine_id=None, email=None):
    """Validate a license key via Cloudflare D1."""
    return cf_send('POST', '/api/license/validate', data={
        'key': key, 'hwid': hwid, 'machine_id': machine_id, 'email': email,
    })

def create_license(key, plan='basic', features=None, expires_at_days=None):
    """Create a new license (admin)."""
    return cf_send('POST', '/api/license', data={
        'key': key, 'plan': plan, 'features': features, 'expires_at_days': expires_at_days,
    })

def delete_license(key):
    """Deactivate a license (admin)."""
    return cf_send('DELETE', f'/api/license?key={key}')

# ─── User ───
def create_user(username, password_hash, email=None, is_admin=False):
    """Create user in D1."""
    return cf_send('POST', '/api/user', data={
        'username': username, 'password_hash': password_hash,
        'email': email, 'is_admin': is_admin,
    })

def activate_user(username, activate=True):
    """Activate/deactivate user."""
    return cf_send('POST', '/api/user/activate', data={
        'username': username, 'activate': activate,
    })

# ─── Logging ───
def write_log(action, username='', device='', details=''):
    """Write a usage log entry."""
    return cf_send('POST', '/api/log', data={
        'action': action, 'username': username,
        'device': device, 'details': details,
    })

def fetch_logs(limit=100, offset=0):
    """Fetch recent logs (admin)."""
    return cf_fetch(f'/api/logs?limit={limit}&offset={offset}')

def fetch_stats(days=7):
    """Fetch usage statistics (admin)."""
    return cf_fetch(f'/api/stats?days={days}')

# ─── File download URL ───
def download_url(key):
    """Get the download URL for a file in R2."""
    return f"{CLOUDFLARE_API_URL}/download/{key}"

# ─── Config sync (replaces _sync_download / _sync_upload from auth.py) ───
def sync_download(cfg_path):
    """Download remote config and merge users into local config."""
    remote = fetch_config()
    if not remote:
        return
    try:
        with open(cfg_path, encoding='utf-8') as f:
            local = json.load(f)
    except Exception:
        local = {}
    for key in ('users', 'admin', 'blocklist', 'features', 'options', 'smtp'):
        if key in remote:
            local[key] = remote[key]
    _write_config(local, cfg_path)

def sync_upload(cfg_path):
    """Upload local config to Cloudflare KV."""
    try:
        with open(cfg_path, encoding='utf-8') as f:
            cfg = json.load(f)
    except Exception:
        return
    update_config(cfg)

def _write_config(cfg, path):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass

# ─── Cloudflare asset download (copy protection) ───
CF_TOOLS_DIR = None

def _download_file(remote_path, dest_path, timeout=30):
    """Download a binary file from Cloudflare R2 via the worker."""
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
    """Download tools.zip from Cloudflare and extract to temp.
    
    Called at app startup (frozen/PyInstaller only) to enable copy protection —
    the EXE downloads its tools at runtime instead of bundling them.
    """
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
    """Return the path to downloaded tools/ directory, or None."""
    return CF_TOOLS_DIR
