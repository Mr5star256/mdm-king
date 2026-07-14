"""Authentication: password hashing, machine ID, Cloudflare sync."""

import os, sys, json, hashlib, subprocess, urllib.request, threading, time
from cloudflare import CLOUDFLARE_API_URL, sync_upload, sync_download, _write_config

GIST_TOKEN = os.environ.get('GIST_TOKEN') or ''
GIST_ID = ""
SYNC_URL_KEY = "sync_url"

def _hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def _check_password(stored, plaintext):
    if stored.startswith('sha256:'):
        return stored[7:] == hashlib.sha256(plaintext.encode('utf-8')).hexdigest()
    return stored == plaintext

def _migrate_password(stored):
    if stored.startswith('sha256:'):
        return stored
    return 'sha256:' + hashlib.sha256(stored.encode('utf-8')).hexdigest()

def _get_machine_id():
    try:
        r = subprocess.run(['wmic', 'csproduct', 'get', 'uuid'], capture_output=True, text=True, timeout=3)
        for line in r.stdout.split('\n'):
            line = line.strip()
            if line and 'UUID' not in line and len(line) == 36:
                return line.strip()
    except Exception: pass
    try:
        import platform
        return platform.node() or 'unknown'
    except Exception: pass
    return 'unknown'

# Legacy — kept for imports that still reference these
def _gist_token():
    return ""

def _gist_headers():
    return {'User-Agent': 'MDM-King'}
