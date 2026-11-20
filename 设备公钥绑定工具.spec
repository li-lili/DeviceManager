# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('assets', 'assets')],
    hiddenimports=['serial.tools.list_ports'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
# Use the runtime shipped with Qt consistently; Conda's older DLLs can
# otherwise be loaded first from the bundle root.
from pathlib import Path
import PySide6
qt_dir = Path(PySide6.__file__).parent
runtime_names = {p.name.lower() for pattern in ('msvcp140*.dll', 'vcruntime140*.dll')
                 for p in qt_dir.glob(pattern)}
a.binaries = [entry for entry in a.binaries
              if Path(entry[0]).name.lower() not in runtime_names
              and entry[0].lower() != 'ucrtbase.dll'
              # Qt uses Windows ICU; PATH may contain incompatible third-party ICU.
              and not Path(entry[0]).name.lower().startswith('icu')
              and not entry[0].lower().startswith('api-ms-win-')]
for name in sorted(runtime_names):
    source = next(p for p in qt_dir.iterdir() if p.name.lower() == name)
    a.binaries.append((source.name, str(source), 'BINARY'))
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='设备公钥绑定工具',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
