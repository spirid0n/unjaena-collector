# -*- mode: python ; coding: utf-8 -*-
import os
import sys
import platform
from pathlib import Path

current_os = platform.system().lower()  # 'windows', 'linux', 'darwin'

# =============================================================================
# USB Library Detection (Windows only)
# =============================================================================

def find_libusb_dll():
    """Find libusb-1.0.dll for bundling with the application (Windows only)"""
    if current_os != 'windows':
        return []

    dll_locations = []
    possible_paths = [
        Path('resources/libusb-1.0.dll'),
        Path(os.environ.get('PROGRAMFILES', 'C:/Program Files')) / 'libusb-1.0' / 'MS64' / 'libusb-1.0.dll',
        Path(os.environ.get('PROGRAMFILES(X86)', 'C:/Program Files (x86)')) / 'libusb-1.0' / 'MS32' / 'libusb-1.0.dll',
    ]

    try:
        import usb1
        usb1_path = Path(usb1.__file__).parent
        dll_in_package = usb1_path / 'libusb-1.0.dll'
        if dll_in_package.exists():
            possible_paths.insert(0, dll_in_package)
    except ImportError:
        pass

    for path_dir in os.environ.get('PATH', '').split(os.pathsep):
        dll_path = Path(path_dir) / 'libusb-1.0.dll'
        if dll_path.exists():
            possible_paths.append(dll_path)

    for dll_path in possible_paths:
        if dll_path.exists():
            print(f"[USB] Found libusb DLL: {dll_path}")
            dll_locations.append((str(dll_path), '.'))
            break

    if not dll_locations:
        print("[USB] WARNING: libusb-1.0.dll not found. Android USB collection may not work.")

    return dll_locations


usb_binaries = find_libusb_dll()

# =============================================================================
# Platform-Specific Hidden Imports
# =============================================================================

# Common hidden imports (all platforms)
common_hidden_imports = [
    'adb_shell',
    'adb_shell.adb_device',
    'adb_shell.adb_device_usb',
    'adb_shell.auth',
    'adb_shell.auth.keygen',
    'adb_shell.auth.sign_pythonrsa',
    'adb_shell.exceptions',
    'adb_shell.handle',
    'adb_shell.transport',
    'usb1',
    'libusb1',
    'rsa',
    'pymobiledevice3',
    'pymobiledevice3.usbmux',
    'pymobiledevice3.lockdown',
    'pymobiledevice3.services',
    'pymobiledevice3.services.afc',
    'pymobiledevice3.services.installation_proxy',
    'pymobiledevice3.services.house_arrest',
    'pymobiledevice3.services.diagnostics',
    'pymobiledevice3.services.syslog',
    'pymobiledevice3.exceptions',
    'pymobiledevice3.common',
    'biplist',
    'iphone_backup_decrypt',
    'collectors.ios_backup_decryptor',
    'Crypto',
    'Crypto.Cipher',
    'Crypto.Cipher.AES',
    'Crypto.Util',
    'Crypto.Util.Padding',
    'cryptography',
    'cryptography.hazmat',
    'cryptography.hazmat.primitives',
    'cryptography.hazmat.backends',
]

# Windows-specific
windows_hidden_imports = [
    'win32api',
    'win32con',
    'win32security',
    'wmi',
    'pytsk3',
]

# Combine based on platform
if current_os == 'windows':
    all_hidden_imports = common_hidden_imports + windows_hidden_imports
else:
    all_hidden_imports = common_hidden_imports

# =============================================================================
# Platform-Specific Settings
# =============================================================================

if current_os == 'windows':
    exe_name = 'IntelligenceCollector'
    use_console = False
elif current_os == 'darwin':
    exe_name = 'IntelligenceCollector'
    use_console = False
else:
    # Linux
    exe_name = 'IntelligenceCollector'
    use_console = True  # Linux headless environments need console

# =============================================================================
# Analysis Configuration
# =============================================================================

a = Analysis(
    ['src/main.py'],
    pathex=[],
    binaries=usb_binaries,
    datas=[
        ('resources', 'resources'),
        ('config.json', '.'),
    ],
    hiddenimports=all_hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

if current_os == 'darwin':
    # macOS: build .app bundle
    exe = EXE(
        pyz,
        a.scripts,
        [],
        exclude_binaries=True,
        name=exe_name,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=use_console,
        disable_windowed_traceback=False,
        argv_emulation=True,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.datas,
        strip=False,
        upx=False,
        name=exe_name,
    )
    app = BUNDLE(
        coll,
        name=f'{exe_name}.app',
        bundle_identifier='com.forensics.collector',
    )
else:
    # Windows & Linux: single-file binary
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name=exe_name,
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=True,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=use_console,
        disable_windowed_traceback=False,
        argv_emulation=False,
        target_arch=None,
        codesign_identity=None,
        entitlements_file=None,
    )
