#!/usr/bin/env python3
"""
Android Collector Test

Tests for Android USB-direct collector:
- Artifact type definitions
- USB library availability
- Device enumeration (requires USB libraries)
- RSA key generation
- Shell command execution (requires connected device)
- File pull (requires connected device)
"""

import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_android_artifact_types():
    """Test Android artifact types are defined"""
    print("=" * 60)
    print("Android Collector Artifact Types Test")
    print("=" * 60)

    from collectors.android_collector import ANDROID_ARTIFACT_TYPES

    print(f"\nTotal artifact types: {len(ANDROID_ARTIFACT_TYPES)}")

    # Expected types
    expected_basic = [
        'mobile_android_sms',
        'mobile_android_call',
        'mobile_android_contacts',
        'mobile_android_app',
        'mobile_android_wifi',
        'mobile_android_location',
    ]

    expected_messenger = [
        'mobile_android_kakaotalk',
        'mobile_android_whatsapp',
        'mobile_android_telegram',
        'mobile_android_line',
        'mobile_android_facebook_messenger',
        'mobile_android_signal',
    ]

    expected_sns = [
        'mobile_android_instagram',
        'mobile_android_twitter',
        'mobile_android_tiktok',
        'mobile_android_snapchat',
    ]

    print("\n[1/3] Basic Artifacts:")
    for t in expected_basic:
        if t in ANDROID_ARTIFACT_TYPES:
            info = ANDROID_ARTIFACT_TYPES[t]
            print(f"  [OK] {t}: {info.get('name', 'N/A')}")
        else:
            print(f"  [FAIL] {t}: NOT FOUND")

    print("\n[2/3] Messenger Apps:")
    for t in expected_messenger:
        if t in ANDROID_ARTIFACT_TYPES:
            info = ANDROID_ARTIFACT_TYPES[t]
            paths = info.get('paths', [info.get('db_path', 'N/A')])
            print(f"  [OK] {t}")
            for p in paths[:2]:  # Show first 2 paths
                print(f"       -> {p}")
        else:
            print(f"  [FAIL] {t}: NOT FOUND")

    print("\n[3/3] SNS Apps:")
    for t in expected_sns:
        if t in ANDROID_ARTIFACT_TYPES:
            info = ANDROID_ARTIFACT_TYPES[t]
            paths = info.get('paths', [])
            print(f"  [OK] {t}")
            for p in paths[:2]:
                print(f"       -> {p}")
        else:
            print(f"  [FAIL] {t}: NOT FOUND")

    # Summary
    all_expected = expected_basic + expected_messenger + expected_sns
    found = sum(1 for t in all_expected if t in ANDROID_ARTIFACT_TYPES)

    print(f"\n{'=' * 60}")
    print(f"Result: {found}/{len(all_expected)} artifact types found")
    print("=" * 60)

    return found == len(all_expected)


def test_usb_libraries_available():
    """Test USB libraries are available (informational - not a failure if missing)"""
    print("\n" + "=" * 60)
    print("USB Libraries Availability Test")
    print("=" * 60)

    from collectors.android_collector import USB_AVAILABLE, check_usb_available

    print(f"\n  USB_AVAILABLE (import): {USB_AVAILABLE}")

    if USB_AVAILABLE:
        libusb_ok = check_usb_available()
        print(f"  libusb accessible: {libusb_ok}")

        if not libusb_ok:
            print("\n  [INFO] USB libraries imported but libusb not accessible.")
            print("  Platform-specific requirements:")
            print("    - Windows: libusb-1.0.dll required")
            print("    - Linux: sudo apt-get install libusb-1.0-0")
            print("    - macOS: brew install libusb")
    else:
        print("\n  [INFO] USB libraries not available.")
        print("  Install: pip install adb-shell[usb] libusb1")
        print("  (This is expected if running without USB support)")

    print("\n" + "=" * 60)
    # Return True - this is informational only, not a pass/fail test
    return True


def test_device_enumeration():
    """Test USB device enumeration (requires USB libraries)"""
    print("\n" + "=" * 60)
    print("USB Device Enumeration Test")
    print("=" * 60)

    from collectors.android_collector import USB_AVAILABLE, ADBDeviceMonitor

    if not USB_AVAILABLE:
        print("\n  [SKIP] USB libraries not available")
        return True  # Skip test, not a failure

    monitor = ADBDeviceMonitor()
    devices = monitor._enumerate_usb_devices()

    print(f"\n  Android USB devices found: {len(devices)}")
    for device in devices:
        print(f"    - Serial: {device.get('serial', 'N/A')}")
        print(f"      Manufacturer: {device.get('manufacturer', 'N/A')}")
        print(f"      Product: {device.get('product', 'N/A')}")
        if device.get('vendor_id'):
            print(f"      USB ID: {device['vendor_id']:04x}:{device['product_id']:04x}")

    if not devices:
        print("\n  [INFO] No Android devices connected via USB.")
        print("  To test device connection:")
        print("    1. Enable USB debugging on Android device")
        print("    2. Connect via USB cable")
        print("    3. Accept USB debugging prompt on device")

    print("\n" + "=" * 60)
    return True  # Enumeration itself succeeded


def test_key_generation():
    """Test ADB RSA key generation"""
    print("\n" + "=" * 60)
    print("RSA Key Generation Test")
    print("=" * 60)

    from collectors.android_collector import USB_AVAILABLE

    if not USB_AVAILABLE:
        print("\n  [SKIP] USB libraries not available")
        return True

    from collectors.android_collector import ADBDeviceMonitor

    monitor = ADBDeviceMonitor()

    # Use a temp directory for testing
    with tempfile.TemporaryDirectory() as tmpdir:
        test_key_path = Path(tmpdir) / "test_adbkey"
        monitor._adb_key_path = test_key_path

        # Clear any cached signer
        monitor._signer = None

        try:
            signer = monitor._get_or_create_adb_key()
            print(f"\n  Key generated: {signer is not None}")
            print(f"  Private key exists: {test_key_path.exists()}")
            print(f"  Public key exists: {Path(f'{test_key_path}.pub').exists()}")

            if test_key_path.exists():
                print(f"  Private key size: {test_key_path.stat().st_size} bytes")

            success = signer is not None and test_key_path.exists()
            print(f"\n  Result: {'OK' if success else 'FAIL'}")
            print("=" * 60)
            return success

        except Exception as e:
            print(f"\n  [FAIL] Key generation error: {e}")
            print("=" * 60)
            return False


def test_shell_command():
    """Test shell command execution (requires connected device)"""
    print("\n" + "=" * 60)
    print("Shell Command Execution Test")
    print("=" * 60)

    from collectors.android_collector import USB_AVAILABLE, AndroidCollector

    if not USB_AVAILABLE:
        print("\n  [SKIP] USB libraries not available")
        return True

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = AndroidCollector(output_dir=tmpdir)

        try:
            # Try to connect to first available device
            collector.connect()
            print(f"\n  Connected to: {collector.device_info.serial}")
            print(f"  Model: {collector.device_info.model}")

            # Test shell command
            output, returncode = collector._adb_shell("getprop ro.build.version.sdk")
            print(f"\n  Command: getprop ro.build.version.sdk")
            print(f"  Output: {output.strip()}")
            print(f"  Return code: {returncode}")

            success = returncode == 0 and output.strip().isdigit()
            print(f"\n  Result: {'OK' if success else 'FAIL'}")
            print("=" * 60)
            return success

        except RuntimeError as e:
            print(f"\n  [SKIP] {e}")
            print("  Connect an Android device with USB debugging enabled to test.")
            print("=" * 60)
            return True  # Skip, not a failure

        finally:
            collector.disconnect()


def test_file_pull():
    """Test file pull (requires connected device)"""
    print("\n" + "=" * 60)
    print("File Pull Test")
    print("=" * 60)

    from collectors.android_collector import USB_AVAILABLE, AndroidCollector

    if not USB_AVAILABLE:
        print("\n  [SKIP] USB libraries not available")
        return True

    with tempfile.TemporaryDirectory() as tmpdir:
        collector = AndroidCollector(output_dir=tmpdir)

        try:
            collector.connect()
            print(f"\n  Connected to: {collector.device_info.serial}")

            # Pull a system file that's always accessible
            local_path = Path(tmpdir) / "build.prop"
            success = collector._adb_pull("/system/build.prop", str(local_path))

            print(f"\n  Remote: /system/build.prop")
            print(f"  Local: {local_path}")
            print(f"  Pull success: {success}")

            if success and local_path.exists():
                print(f"  File size: {local_path.stat().st_size} bytes")
                # Read first few lines
                with open(local_path, 'r', errors='replace') as f:
                    lines = f.readlines()[:5]
                print(f"  First 5 lines:")
                for line in lines:
                    print(f"    {line.strip()[:60]}")

            print(f"\n  Result: {'OK' if success else 'FAIL'}")
            print("=" * 60)
            return success

        except RuntimeError as e:
            print(f"\n  [SKIP] {e}")
            print("=" * 60)
            return True

        finally:
            collector.disconnect()


def test_device_info():
    """Test getting full device info (requires connected device)"""
    print("\n" + "=" * 60)
    print("Device Info Test")
    print("=" * 60)

    from collectors.android_collector import USB_AVAILABLE, ADBDeviceMonitor

    if not USB_AVAILABLE:
        print("\n  [SKIP] USB libraries not available")
        return True

    monitor = ADBDeviceMonitor()
    devices = monitor.get_connected_devices()

    if not devices:
        print("\n  [SKIP] No devices connected")
        print("=" * 60)
        return True

    for device in devices:
        print(f"\n  Device: {device.serial}")
        print(f"    Model: {device.model}")
        print(f"    Manufacturer: {device.manufacturer}")
        print(f"    Android Version: {device.android_version}")
        print(f"    SDK Version: {device.sdk_version}")
        print(f"    USB Debugging: {device.usb_debugging}")
        print(f"    Rooted: {device.rooted}")
        if device.vendor_id:
            print(f"    USB ID: {device.vendor_id:04x}:{device.product_id:04x}")

    print("\n  Result: OK")
    print("=" * 60)
    return True


if __name__ == "__main__":
    results = {}

    # Always run artifact type test
    results['artifact_types'] = test_android_artifact_types()

    # USB-specific tests
    results['usb_libraries'] = test_usb_libraries_available()
    results['key_generation'] = test_key_generation()
    results['device_enumeration'] = test_device_enumeration()
    results['device_info'] = test_device_info()
    results['shell_command'] = test_shell_command()
    results['file_pull'] = test_file_pull()

    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    for test_name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  {test_name}: {status}")

    all_passed = all(results.values())
    print(f"\nOverall: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    print("=" * 60)

    sys.exit(0 if all_passed else 1)
