# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['mdm_king.pyw'],
    pathex=[],
    binaries=[],
    datas=[('tools\\mdm_king_logo_circular.ico', 'tools'), ('tools\\mdm_king_logo_circular_32.png', 'tools'), ('tools\\mdm_king_logo_circular.png', 'tools'), ('tools\\mdm_king_logo.ico', 'tools'), ('tools\\mdm_king_logo.png', 'tools')],
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
    name='MDM KING v0.3.6',
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
