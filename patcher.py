"""Hex pattern engine: FastPatternFinder, pattern data, remote algo engine."""

import re, os, sys, json, time, struct, subprocess, urllib.request, threading

# Neon color list for effects
NEONS = ['#00ffff', '#ff00ff', '#ffcc00', '#00ff88', '#ff004d']

def _semver_gt(a, b):
    try:
        ap = [int(x) for x in a.lstrip('v').split('.')]
        bp = [int(x) for x in b.lstrip('v').split('.')]
        for i in range(max(len(ap), len(bp))):
            av = ap[i] if i < len(ap) else 0
            bv = bp[i] if i < len(bp) else 0
            if av != bv: return av > bv
        return False
    except Exception:
        return a > b

# ─── Hex pattern sets ───
PROD_SEC_PATTERNS = [
    {'name': 'PROD_SEC_MARKER',  'chipset': 'all', 'bytes': bytes.fromhex('70726f642d73656375726564'), 'desc': 'prod-secured'},
    {'name': 'PROD_LOCK_STATE',  'chipset': 'all', 'bytes': bytes.fromhex('70726f642e6c6f636b2e7374617465'), 'desc': 'prod.lock.state'},
    {'name': 'PROD_MDM_ENABLE',  'chipset': 'all', 'bytes': bytes.fromhex('70726f642e6d646d2e656e61626c65'), 'desc': 'prod.mdm.enable'},
    {'name': 'PROD_LOCK_FLAG',   'chipset': 'all', 'bytes': bytes.fromhex('70726f642e6c6f636b2e666c6167'), 'desc': 'prod.lock.flag'},
]

MTK_FP_PATTERNS = [
    {'name': 'MTK_FP_SCORPIO',   'chipset': 'mtk', 'bytes': bytes.fromhex('6d746b2e73636f7270696f2e6669'), 'desc': 'mtk.scorpio.fi'},
    {'name': 'MTK_FP_LOCKED',    'chipset': 'mtk', 'bytes': bytes.fromhex('6d746b2e66696e6765727072696e742e6c6f636b'), 'desc': 'mtk.fingerprint.lock'},
    {'name': 'MTK_FP_SECURITY',  'chipset': 'mtk', 'bytes': bytes.fromhex('6d746b2e73656375726974792e666c6167'), 'desc': 'mtk.security.flag'},
    {'name': 'MTK_FP_ENROLL',    'chipset': 'mtk', 'bytes': bytes.fromhex('6d746b2e656e726f6c6c2e66696e676572'), 'desc': 'mtk.enroll.finger'},
]

PRIV_APP_PATTERNS = [
    {'name': 'PRIV_APK_SIG',     'chipset': 'all', 'bytes': bytes.fromhex('707269762d6170702f53656375726974'), 'desc': 'priv-app/Securit'},
    {'name': 'PRIV_SEC_COM',     'chipset': 'all', 'bytes': bytes.fromhex('707269762d6170702f536563757269747943'), 'desc': 'priv-app/SecurityC'},
    {'name': 'PRIV_SCORPIO',     'chipset': 'all', 'bytes': bytes.fromhex('707269762d6170702f73636f7270696f'), 'desc': 'priv-app/scorpio'},
    {'name': 'PRIV_SYS_UPDATE',  'chipset': 'all', 'bytes': bytes.fromhex('707269762d6170702f53797374656d55'), 'desc': 'priv-app/SystemU'},
]

MTK_PCS_PATTERNS = [
    {'name': 'MTK_PCS_LOCK',     'chipset': 'mtk', 'bytes': bytes.fromhex('6d746b2e7063732e6c6f636b6564'), 'desc': 'mtk.pcs.locked'},
    {'name': 'MTK_PCS_SCORPIO',  'chipset': 'mtk', 'bytes': bytes.fromhex('6d746b2e7063732e73636f7270696f'), 'desc': 'mtk.pcs.scorpio'},
    {'name': 'MTK_PCS_ENABLE',   'chipset': 'mtk', 'bytes': bytes.fromhex('6d746b2e7063732e656e61626c65'), 'desc': 'mtk.pcs.enable'},
    {'name': 'MTK_PCS_STATE',    'chipset': 'mtk', 'bytes': bytes.fromhex('6d746b2e7063732e7374617465'), 'desc': 'mtk.pcs.state'},
]

PCS_APKOAT_PATTERNS = [
    {'name': 'PCS_OAT_SEC',      'chipset': 'all', 'bytes': bytes.fromhex('7063732f5365637572697479436f6d'), 'desc': 'pcs/SecurityCom'},
    {'name': 'PCS_OAT_SCORPIO',  'chipset': 'all', 'bytes': bytes.fromhex('7063732f73636f7270696f'), 'desc': 'pcs/scorpio'},
    {'name': 'PCS_OAT_SYS_UPD',  'chipset': 'all', 'bytes': bytes.fromhex('7063732f53797374656d557064'), 'desc': 'pcs/SystemUpd'},
]

SEC_ODEX_PATTERNS = [
    {'name': 'SEC_ODEX_LOCKSRV', 'chipset': 'all', 'bytes': bytes.fromhex('7365637572697479636f6d2e6f646578'), 'desc': 'securitycom.odex'},
    {'name': 'SEC_ODEX_PLUGIN',  'chipset': 'all', 'bytes': bytes.fromhex('5365637572697479506c7567696e2e6f646578'), 'desc': 'SecurityPlugin.odex'},
    {'name': 'SEC_VDEX_V400',    'chipset': 'all', 'bytes': bytes.fromhex('7365637572697479636f6d2e76646578'), 'desc': 'securitycom.vdex'},
    {'name': 'SEC_ART_V400',     'chipset': 'all', 'bytes': bytes.fromhex('7365637572697479636f6d2e617274'), 'desc': 'securitycom.art'},
]

ALL_HEX_PATTERNS = PROD_SEC_PATTERNS + MTK_FP_PATTERNS + PRIV_APP_PATTERNS + MTK_PCS_PATTERNS + PCS_APKOAT_PATTERNS + SEC_ODEX_PATTERNS

CHIPSET_PACKAGES = {
    'common': [
        'com.android.mms','com.android.mms.service','com.android.htmlviewer',
        'com.android.proxyhandler','com.android.systemupdate',
        'com.android.cts.ctsshim','com.android.cts.priv.ctsshim','com.android.cts',
        'com.android.appupdate','com.android.dynsystem','com.android.configupdater',
        'com.android.keychain','com.google.android.devicelockcontroller',
        'com.google.android.configupdater',
        'com.transsion.plat.appupdate','com.transsion.systemupdate',
    ],
    'spd': [
        'com.android.settings/.Settings\\$PrivateDnsModeSettingsActivity',
        'com.android.settings/.Settings\\$PrivateDnsSettingsActivity',
        'com.android.settings/.Settings\\$PrivacyDnsSettingsActivity',
        'com.scorpio.securitycompanion',
        'com.scorpio.securityservice','com.scorpio.securityupdate',
        'com.scorpio.securitymonitor','com.scorpio.secureconfig',
        'com.scorpio.securitywatchdog','com.scorpio.securityplugin',
        'com.itel.security','com.itel.scorpio','com.itel.lock',
        'com.transsion.security','com.transsion.scorpio',
        'com.transsion.toolservice','com.sprd.omacp',
    ],
    'mtk': [
        'com.transsion.security','com.transsion.scorpio','com.transsion.toolservice',
        'com.transsion.securityplugin','com.transsion.systemupdate',
        'com.transsion.overlaysuw','com.transsion.phoenix',
        'com.transsion.phoenix.lock','com.transsion.daemon',
        'com.transsion.oobe','com.transsion.assistant',
        'com.transsion.mdm','com.transsion.mdm.receiver',
        'com.transsion.itelephony','com.transsion.telephony',
        'com.tecno.security','com.tecno.securityplugin','com.tecno.mdm',
        'com.tecno.life','com.tecno.assistant','com.tecno.wizard',
        'com.tecno.daemon','com.tecno.reserve','com.tecno.joy',
        'com.tecno.gionee','com.tecno.hifi',
        'com.infinix.security','com.infinix.securityplugin','com.infinix.mdm',
        'com.infinix.xmanager','com.infinix.faceunlock','com.infinix.life',
        'com.infinix.daemon','com.infinix.reserve','com.infinix.calendar',
        'com.itel.security','com.itel.securityplugin','com.itel.mdm',
        'com.itel.lock','com.itel.scorpio','com.itel.daemon',
        'com.scorpio.securitycompanion',
        'com.scorpio.securityservice','com.scorpio.securityupdate',
        'com.scorpio.securitymonitor','com.scorpio.secureconfig',
        'com.scorpio.securitywatchdog','com.scorpio.securityplugin',
        'com.scorpio.privatecomp','com.scorpio.lockscreen',
        'com.cybercat.acbridge','com.cybercat.acbridgeoobe',
        'oobe',
    ],
    'samsung': [
        'com.samsung.android.knox.policy','com.samsung.android.knox.core',
        'com.samsung.android.knox.enrollment','com.samsung.android.knox.enrolled',
        'com.samsung.android.knox.pushmanager','com.samsung.android.knox.attestation',
        'com.samsung.android.knox.restrictor','com.samsung.android.knox.zt.framework',
        'com.samsung.android.knox.kpec','com.samsung.android.knox.kpu',
        'com.samsung.android.knox.mpos','com.samsung.android.knox.license',
        'com.samsung.android.knox.enterprise','com.samsung.android.knox.zt',
        'com.samsung.android.knox.zt.config','com.samsung.android.knox.containercore',
        'com.samsung.android.knox.containeragent','com.samsung.android.knox.trustzone',
        'com.samsung.android.knox.rcp.components','com.samsung.android.knox.nfcprovision',
        'com.samsung.android.knox.analytics.uploader','com.samsung.android.knox.ocs',
        'com.samsung.android.knox.knoxanalytics','com.samsung.android.knox.knoxsetupwizard',
        'com.samsung.android.knox.setupwizardclient','com.samsung.android.knx.core',
        'com.samsung.android.mdm','com.samsung.android.sdm','com.samsung.sdm',
        'com.samsung.android.securitylogagent','com.samsung.android.kgclient',
        'com.samsung.android.cidmanager','com.samsung.android.fotaclient',
        'com.samsung.android.fota','com.samsung.android.fmm',
        'com.samsung.android.app.findmydevice','com.samsung.android.app.remotecontrol',
        'com.samsung.android.pushmanager','com.samsung.android.securitymanager',
        'com.samsung.android.sm.policy','com.samsung.android.sm.devicesecurity',
        'com.samsung.knox.securefolder','com.samsung.knox.appsupdateagent',
        'com.sec.enterprise.knox.cloudmdm','com.sec.enterprise.knox.cloudmdm.smdms',
        'com.sec.enterprise.knox.managed','com.sec.enterprise.knox.managedprovisioning',
        'com.sec.enterprise.knox.attestation','com.sec.android.soagent',
        'com.sec.omadm','com.sec.omadm.service','com.policydm',
    ],
    'vivo': [
        'com.vivo.bsptest','com.vivo.vivomanager','com.vivo.securedaemon',
        'com.vivo.secure','com.vivo.agency','com.vivo.vivotrack',
        'com.vivo.daemon','com.vivo.daemon.service','com.vivo.assistant',
        'com.vivo.fingerprint','com.vivo.safecenter','com.vivo.safephone',
        'com.vivo.charge','com.vivo.upslide','com.vivo.space',
        'com.vivo.doubletap','com.vivo.EasyShare','com.vivo.motion',
        'com.vivo.smartmultiwindow','com.vivo.browser','com.vivo.speech',
        'com.vivo.appstore','com.bbk.ict','com.bbk.account',
        'com.bbk.cloud','com.bbk.updater','com.bbk.lbs',
        'com.bbk.pwmanager','com.bbk.stroe','com.fb.android',
        'com.iqoo.secure','com.iqoo.videocall',
    ],
    'xiaomi': [
        'com.miui.securitycenter','com.miui.securityadd','com.miui.securitycore',
        'com.miui.cloudservice','com.miui.cloudbackup','com.miui.cloudsync',
        'com.miui.finddevice','com.miui.faceenroll','com.miui.analytics',
        'com.miui.bugreport','com.miui.video','com.miui.player',
        'com.miui.miuibbs','com.miui.hybrid','com.miui.hybrid.accessory',
        'com.miui.notes','com.miui.gallery','com.miui.miservice',
        'com.miui.system','com.miui.daemon','com.xiaomi.finddevice',
        'com.xiaomi.discover','com.xiaomi.mipush','com.xiaomi.simactivate.service',
        'com.xiaomi.account','com.xiaomi.market','com.xiaomi.payment',
        'com.xiaomi.shop','com.xiaomi.shopchannel','com.android.quicksearchbox',
    ],
    'oppo': [
        'com.oppo.engineermode','com.oppo.ota','com.oppo.safecenter',
        'com.oppo.camera','com.oppo.launcher','com.oppo.weather',
        'com.oppo.bttestmode','com.oppo.atest','com.oppo.music',
        'com.oppo.particles','com.oppo.mtp','com.oppo.screenlock',
        'com.oppo.secure','com.oppo.powergenie','com.oppo.daemon',
        'com.oppo.daemon.system','com.coloros.securitycenter',
        'com.coloros.safecenter','com.coloros.findmyphone',
        'com.coloros.weather','com.coloros.weather.service',
        'com.coloros.guard','com.coloros.secure','com.coloros.backuprestore',
        'com.coloros.cloud','com.coloros.ocr','com.coloros.screenlock',
        'com.coloros.fingerprint','com.coloros.focus',
        'com.heytap.cloud','com.heytap.market','com.heytap.mcs',
        'com.heytap.pictorial','com.heytap.usercenter',
    ],
    'realme': [
        'com.realme.securitycheck','com.realme.movies','com.realme.wallpaper',
        'com.realme.link','com.realme.diag','com.realme.diagdaemon',
        'com.realme.logkit','com.realme.securitycom','com.realme.ota',
        'com.realme.movies','com.realme.music','com.realme.guard',
    ],
    'tecno': [
        'com.tecno.mdm','com.tecno.security','com.tecno.itadmin',
        'com.tecno.life','com.tecno.assistant','com.tecno.wizard',
        'com.tecno.daemon','com.tecno.reserve','com.tecno.joy',
        'com.tecno.gionee','com.tecno.gionee3','com.tecno.hifi',
        'com.transsion.tecno.mdm','com.transsion.phoenix',
    ],
    'infinix': [
        'com.infinix.mdm','com.infinix.security','com.infinix.itadmin',
        'com.infinix.xmanager','com.infinix.camera','com.infinix.faceunlock',
        'com.infinix.life','com.infinix.daemon','com.infinix.reserve',
        'com.transsion.infinix.mdm',
    ],
}

def _parse_remote_patterns(data):
    patterns = []
    for entry in data.get('patterns', []):
        try:
            patterns.append({
                'name': entry.get('name', 'REMOTE'),
                'chipset': entry.get('chipset', 'all'),
                'bytes': bytes.fromhex(entry['hex'].replace(' ', '')),
                'desc': entry.get('desc', ''),
            })
        except Exception: continue
    return patterns if patterns else None

def _merge_remote_patterns(remote, local=None):
    if local is None: local = ALL_HEX_PATTERNS
    existing = {p['bytes'] for p in local}
    added = 0
    for pat in (remote or []):
        if pat['bytes'] not in existing:
            local.append(pat)
            existing.add(pat['bytes'])
            added += 1
    return added

class FastPatternFinder:
    """Multi-pattern binary search using compiled regex for single-pass scanning."""
    __slots__ = ('_patterns', '_regex', '_patmap')
    def __init__(self, patterns=None):
        self._patterns = patterns or ALL_HEX_PATTERNS
        self._regex = None
        self._patmap = {}
        self._compile()
    def _compile(self):
        parts = []
        for pat in self._patterns:
            pb = pat['bytes']
            escaped = re.escape(pb)
            parts.append(escaped)
            self._patmap[pb] = pat
        if parts:
            self._regex = re.compile(b'|'.join(parts))
    def scan(self, data, start=0, end=None):
        if end is None: end = len(data)
        results = []
        if not self._regex: return results
        for m in self._regex.finditer(data, start, end):
            pb = m.group()
            pat = self._patmap.get(pb)
            if pat:
                results.append({'offset': m.start(), 'pattern': pat})
        return results
    def find_multi(self, data, start=0, end=None):
        if end is None: end = len(data)
        results = []
        if not self._regex: return results
        for m in self._regex.finditer(data, start, end):
            pb = m.group()
            pat = self._patmap.get(pb)
            if pat:
                results.append((m.start(), pat))
        return results
    def find_first_in_range(self, data, rstart, rend):
        if not self._regex: return None
        m = self._regex.search(data, rstart, rend)
        if m:
            pb = m.group()
            pat = self._patmap.get(pb)
            if pat:
                return (m.start(), pat)
        return None
    def find_last_in_range(self, data, rstart, rend):
        if not self._regex: return None
        last = None
        for m in self._regex.finditer(data, rstart, rend):
            pb = m.group()
            pat = self._patmap.get(pb)
            if pat:
                last = (m.start(), pat)
        return last

from cloudflare import CLOUDFLARE_API_URL, cf_fetch, cf_send

REMOTE_CONFIG_URL = CLOUDFLARE_API_URL + "/config.json"
REMOTE_ALGO_URL = CLOUDFLARE_API_URL + "/api/health"
PATTERN_UPDATE_URL = CLOUDFLARE_API_URL + "/config.json"

_REMOTE_PATTERN_CACHE = None
_REMOTE_PATTERN_CACHE_TIME = 0

def _get_remote_patterns_cached(url=None, max_age=300):
    """Fetch remote patterns with caching (default 5 min TTL)."""
    global _REMOTE_PATTERN_CACHE, _REMOTE_PATTERN_CACHE_TIME
    now = time.time()
    if _REMOTE_PATTERN_CACHE is not None and (now - _REMOTE_PATTERN_CACHE_TIME) < max_age:
        return _REMOTE_PATTERN_CACHE
    result = _fetch_remote_patterns(url)
    if result is not None:
        _REMOTE_PATTERN_CACHE = result
        _REMOTE_PATTERN_CACHE_TIME = now
    return _REMOTE_PATTERN_CACHE

def _fetch_remote_patterns(url=None, timeout=15):
    url = url or PATTERN_UPDATE_URL
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': 'MDM-King'
            })
            resp = urllib.request.urlopen(req, timeout=timeout)
            raw = json.loads(resp.read().decode('utf-8'))
            result = {'hex': None, 'string': None, 'keywords': None}
            if 'patterns' in raw:
                result['hex'] = _parse_remote_patterns(raw) or []
            if 'string_patterns' in raw:
                result['string'] = _parse_remote_string_patterns(raw) or []
            if 'keywords' in raw:
                result['keywords'] = _parse_remote_keywords(raw) or []
            return result
        except Exception:
            if attempt < 2:
                time.sleep(1)
    return None

def _parse_remote_string_patterns(data):
    """Parse string MDM patterns from remote config."""
    patterns = []
    for entry in data.get('string_patterns', []):
        try:
            pat_bytes = bytes.fromhex(entry['hex'].replace(' ', ''))
            if 'replacement_hex' in entry:
                rep_bytes = bytes.fromhex(entry['replacement_hex'].replace(' ', ''))
            else:
                _r = bytearray(pat_bytes)
                if len(pat_bytes) > 1:
                    _r[1:] = b'\x00' * (len(pat_bytes) - 1)
                rep_bytes = bytes(_r)
            patterns.append({
                'pattern': pat_bytes,
                'replacement': rep_bytes,
                'name': entry.get('name', 'REMOTE_STR'),
            })
        except Exception:
            continue
    return patterns

def _parse_remote_keywords(data):
    """Parse keyword checks from remote config."""
    kws = []
    for entry in data.get('keywords', []):
        try:
            if 'hex' in entry:
                kws.append(bytes.fromhex(entry['hex'].replace(' ', '')))
            elif 'text' in entry:
                kws.append(entry['text'].encode('utf-8'))
        except Exception:
            continue
    return kws

def _merge_remote_string_patterns(remote_pats, local_pats=None, local_reps=None):
    """Merge remote string patterns into MDM_PATTERNS / MDM_REPLACEMENTS style lists."""
    import sys
    if local_pats is None:
        frame = sys._getframe(1)
        local_pats = frame.f_globals.get('MDM_PATTERNS', [])
    if local_reps is None:
        frame = sys._getframe(1)
        local_reps = frame.f_globals.get('MDM_REPLACEMENTS', [])
    existing = {p for p in local_pats}
    added = 0
    for rp in (remote_pats or []):
        if rp['pattern'] not in existing:
            local_pats.append(rp['pattern'])
            local_reps.append(rp['replacement'])
            existing.add(rp['pattern'])
            added += 1
    return added

def _strip_slot_suffix(name):
    """Safely strip _a or _b slot suffix from partition name."""
    if name.endswith('_a') or name.endswith('_b'):
        return name[:-2]
    return name

def _detect_vabc_super(extracted_partitions, orig_super_path, tools_dir=None):
    """
    Detect if a super image uses Virtual A/B layout.
    Returns True for vABC, False for standard A/B or legacy non-A/B.
    """
    has_ab_suffix = False
    for pp in (extracted_partitions or []):
        base = os.path.splitext(os.path.basename(pp))[0]
        if base.endswith('_a') or base.endswith('_b'):
            has_ab_suffix = True
            break
    if has_ab_suffix:
        return False
    _lp_ver = 0
    _meta_slots = 0
    try:
        super_size = os.path.getsize(orig_super_path)
        with open(orig_super_path, 'rb') as f:
            for off in range(max(0, super_size - 4096), super_size - 64):
                f.seek(off)
                if f.read(4) == b'\x41\x4c\x50\x1b':
                    f.seek(off + 12)
                    _lp_ver = struct.unpack('<I', f.read(4))[0]
                    if _lp_ver >= 10:
                        f.seek(off + 36)
                        _meta_slots = struct.unpack('<I', f.read(4))[0]
                    break
    except Exception:
        pass
    if _lp_ver >= 10 and _meta_slots >= 2:
        return True
    if _lp_ver > 0:
        return False
    if tools_dir:
        _lpdump = os.path.join(tools_dir, 'lpdump.exe')
        if os.path.isfile(_lpdump):
            try:
                r = subprocess.run([_lpdump, '--json', orig_super_path],
                                   capture_output=True, text=True, timeout=30)
                if r.returncode == 0 and r.stdout:
                    _data = json.loads(r.stdout)
                    if _data and isinstance(_data, dict):
                        slots = _data.get('slot_number', 0)
                        if slots > 1:
                            return False
                        groups = _data.get('partitions', _data)
                        if isinstance(groups, dict):
                            for gname, gparts in groups.items():
                                if 'cow' in gname.lower():
                                    return True
            except Exception:
                pass
    return True
