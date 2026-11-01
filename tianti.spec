# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['tianti.sandbox.containment', 'tianti.sandbox.replay', 'tianti.sandbox.telemetry_etw', 'tianti.sandbox.snapshot', 'tianti.sandbox.netmon', 'tianti.sandbox.isolation', 'tianti.sandbox.watchdog', 'tianti.rules.engine', 'tianti.detect.detectors', 'tianti.report.html', 'tianti.report.jsonr', 'tianti.api.httpd']
hiddenimports += collect_submodules('tianti')
hiddenimports += collect_submodules('tools')


a = Analysis(
    ['packaging/cli_entry.py'],
    pathex=['G:/天体引擎'],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
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
    [],
    exclude_binaries=True,
    name='tianti',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='tianti',
)
