# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['mdm_king.pyw'],
    pathex=[],
    binaries=[],
    datas=[
        # Logos kept bundled (tiny UI assets); all functional tools (adb, simg2img,
        # lpmake, admin/aurora APKs, BusyBox, SPD driver) are fetched at runtime from
        # Cloudflare R2 via init_cloudflare_assets() -> /download/tools.zip
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
    name='MDM KING v0.3.8',
    icon='tools/mdm_king_logo.ico',
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
