# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for Forensic Collector

Builds a single EXE for Windows distribution.
Requires Windows environment with admin privileges for full functionality.
"""

import sys
from pathlib import Path

# Ensure we're building on Windows
if sys.platform != 'win32':
    raise RuntimeError("This collector must be built on Windows")

block_cipher = None

# Source directory
src_dir = Path('src')

# Analysis configuration
a = Analysis(
    [str(src_dir / 'main.py')],
    pathex=[str(src_dir)],
    binaries=[],
    datas=[
        # WinPmem memory acquisition tool
        ('resources/winpmem_mini_x64.exe', 'resources'),
    ],
    hiddenimports=[
        # PyQt6 imports
        'PyQt6.QtWidgets',
        'PyQt6.QtCore',
        'PyQt6.QtGui',
        # Networking
        'aiohttp',
        'websockets',
        'requests',
        # Windows-specific
        'win32api',
        'win32con',
        'win32security',
        'wmi',
        'ctypes',
        'ctypes.wintypes',
        'psutil',
        # MFT Collection (pytsk3)
        'pytsk3',
        # iOS Forensics
        'plistlib',
        'biplist',
        # Standard library
        'asyncio',
        'json',
        'hashlib',
        'tempfile',
        'shutil',
        'glob',
        'fnmatch',
        'socket',
        'sqlite3',
        'threading',
        'subprocess',
        # Application modules
        'gui.app',
        'gui.consent_dialog',
        'collectors.mft_collector',
        'collectors.artifact_collector',
        'collectors.memory_collector',
        'collectors.android_collector',
        'collectors.ios_collector',
        'core.encryptor',
        'core.token_validator',
        'core.uploader',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude unnecessary modules to reduce size
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'tkinter',
        'unittest',
        'test',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Remove duplicate binaries
seen = set()
a.binaries = [x for x in a.binaries if not (x[0] in seen or seen.add(x[0]))]

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ForensicCollector',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Set to False for GUI app
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Add icon path if available: icon='assets/icon.ico'
    version='version_info.txt',  # Windows version info
    uac_admin=True,  # Request admin privileges
    uac_uiaccess=False,
)
