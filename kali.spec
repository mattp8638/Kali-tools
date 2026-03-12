# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the top-level Kali Tools Suite executable (kali.exe).
Run from the repo root (Kali-tools):
    venv\Scripts\pyinstaller.exe kali.spec

This creates a one-file bundle including all host plugins and UI modules.
"""
import os
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None

spec_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
icon_path = os.path.abspath(os.path.join(spec_dir, 'Tools.ico'))

# Collect plugin YAMLs from all hosts
plugin_datas = []
added_datas = []
hidden_imports = []

# Hosts: (display name, package name, plugin relative dir)
hosts = [
    ('Reconnaissance', 'kali_host', os.path.join('Reconnaissance', 'kali_host', 'plugins')),
    ('Scanning', 'scanning_host', os.path.join('Scanning', 'scanning_host', 'plugins')),
    ('Vulnerability Assessment', 'va_host', os.path.join('Vulnerability Assessment', 'va_host', 'plugins')),
    ('Exploitation', 'exploit_host', os.path.join('Exploitation', 'exploit_host', 'plugins')),
]

# Always include top-level app package
try:
    hidden_imports += collect_submodules('app')
except Exception:
    # fallback to explicit modules if package not importable
    hidden_imports += ['app.main_window', 'app.phase_page']

# Collect each host package submodules and plugin data files
for display, pkg, plugin_rel in hosts:
    try:
        hidden_imports += collect_submodules(pkg)
    except Exception:
        # If package can't be imported in the build env, fall back to best-effort names
        hidden_imports.append(f"{pkg}")

    plugin_dir = os.path.join(spec_dir, plugin_rel)
    if os.path.exists(plugin_dir):
        # Add all YAMLs from the plugin directory into the bundle under the same relative path
        plugin_datas.append((os.path.join(plugin_dir, '*.yaml'), plugin_rel))
    else:
        print(f"[WARN] Plugin directory missing for {display}: {plugin_dir}")

# Common package data
added_datas = plugin_datas + collect_data_files('certifi')

# Common extra libs we rely on at runtime
hidden_imports += ['requests', 'urllib3', 'certifi', 'bs4', 'lxml', 'yaml', 'PyQt5']

a = Analysis(
    ['main.py'],
    # Ensure PyInstaller can import host packages by adding their parent folders to pathex
    pathex=[
        spec_dir,
        os.path.join(spec_dir, 'Reconnaissance'),
        os.path.join(spec_dir, 'Scanning'),
        os.path.join(spec_dir, 'Vulnerability Assessment'),
        os.path.join(spec_dir, 'Exploitation'),
    ],
    binaries=[],
    datas=added_datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter','matplotlib','numpy','pandas','scipy','IPython','jupyter','notebook','pytest','setuptools'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

if not os.path.exists(icon_path):
    print(f"[WARN] Icon not found: {icon_path}")
else:
    print(f"[INFO] Using icon: {icon_path}")

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='kali',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon_path if os.path.exists(icon_path) else None,
    onefile=True,
)
