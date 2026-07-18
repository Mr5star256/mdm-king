# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['mdm_king.pyw'],
    pathex=[],
    binaries=[],
    datas=[
        ('tools\\platform-tools\\adb.exe', 'tools\\platform-tools'),
        ('tools\\platform-tools\\AdbWinApi.dll', 'tools\\platform-tools'),
        ('tools\\platform-tools\\AdbWinUsbApi.dll', 'tools\\platform-tools'),
        ('tools\\simg2img.exe', 'tools'),
        ('tools\\img2simg.exe', 'tools'),
        ('tools\\lpmake.exe', 'tools'),
        ('tools\\mdm_king_admin.apk', 'tools'),
        ('tools\\mdm_king_admin_signed.apk', 'tools'),
        ('tools\\aurora-clean.apk', 'tools'),
        ('tools\\aurora-store.apk', 'tools'),
        ('tools\\mdm_king_logo_circular.ico', 'tools'),
        ('tools\\mdm_king_logo_circular_32.png', 'tools'),
        ('tools\\mdm_king_logo_circular.png', 'tools'),
        ('tools\\mdm_king_logo.ico', 'tools'),
        ('tools\\mdm_king_logo.png', 'tools'),
    ],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='MDM KING v0.3.7',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
