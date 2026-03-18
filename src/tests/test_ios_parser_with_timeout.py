# -*- coding: utf-8 -*-
"""
iOS Parser Test with Timeout Protection

iOS parser test with timeout protection to prevent hanging
"""
import sys
import os
import time
import signal
import threading
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Test configuration
BACKUP_PATH = Path(__file__).parent.parent.parent / "test_ios_backup" / "00008130-000239522E21001C"
OUTPUT_DIR = Path(__file__).parent.parent.parent / "test_ios_output"
DEFAULT_TIMEOUT = 30  # seconds per operation


class TimeoutError(Exception):
    """Operation timeout error"""
    pass


def run_with_timeout(func, timeout_seconds, *args, **kwargs):
    """
    Run a function with timeout protection.

    Args:
        func: Function to run
        timeout_seconds: Maximum execution time
        *args, **kwargs: Arguments to pass to func

    Returns:
        Function result or raises TimeoutError
    """
    result = [None]
    exception = [None]

    def target():
        try:
            result[0] = func(*args, **kwargs)
        except Exception as e:
            exception[0] = e

    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout_seconds)

    if thread.is_alive():
        raise TimeoutError(f"Operation timed out after {timeout_seconds} seconds")

    if exception[0]:
        raise exception[0]

    return result[0]


def test_import_modules():
    """Test 1: Module import test"""
    print("\n" + "=" * 60)
    print("[Test 1] Module Import")
    print("=" * 60)

    start = time.time()

    try:
        from collectors.ios_collector import (
            iOSBackupParser,
            iOSCollector,
            IOS_ARTIFACT_TYPES,
            BackupInfo
        )
        elapsed = time.time() - start
        print(f"  [OK] Import successful ({elapsed:.2f}s)")
        print(f"  [OK] Found {len(IOS_ARTIFACT_TYPES)} artifact types")
        return True
    except Exception as e:
        print(f"  [FAIL] Import failed: {e}")
        return False


def test_backup_info():
    """Test 2: Backup info parsing test"""
    print("\n" + "=" * 60)
    print("[Test 2] Backup Info Parsing")
    print("=" * 60)

    if not BACKUP_PATH.exists():
        print(f"  [FAIL] Backup path not found: {BACKUP_PATH}")
        return False

    try:
        from collectors.ios_collector import iOSBackupParser

        def parse_backup():
            parser = iOSBackupParser(BACKUP_PATH)
            return parser

        parser = run_with_timeout(parse_backup, DEFAULT_TIMEOUT)

        print(f"  [OK] Parser created successfully")
        print(f"  [OK] Backup path: {BACKUP_PATH}")

        # Check backup info
        if hasattr(parser, 'backup_info'):
            info = parser.backup_info
            print(f"  [OK] Device: {getattr(info, 'device_name', 'Unknown')}")
            print(f"  [OK] iOS Version: {getattr(info, 'ios_version', 'Unknown')}")
            print(f"  [OK] Encrypted: {getattr(info, 'encrypted', 'Unknown')}")

        return True

    except TimeoutError as e:
        print(f"  [FAIL] TIMEOUT: {e}")
        return False
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_list_files():
    """Test 3: File listing test"""
    print("\n" + "=" * 60)
    print("[Test 3] List Files from Manifest.db")
    print("=" * 60)

    try:
        from collectors.ios_collector import iOSBackupParser

        def list_files():
            parser = iOSBackupParser(BACKUP_PATH)
            files = list(parser.list_files())
            return files

        files = run_with_timeout(list_files, DEFAULT_TIMEOUT * 2)  # More time for large manifest

        print(f"  [OK] Found {len(files)} files in backup")

        # Show sample files
        if files:
            print(f"  [OK] Sample files:")
            for f in files[:5]:
                domain = f.get('domain', 'unknown')[:30]
                path = f.get('relative_path', 'unknown')[:40]
                print(f"      - [{domain}] {path}")

        return True

    except TimeoutError as e:
        print(f"  [FAIL] TIMEOUT: {e}")
        return False
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_list_files_by_domain():
    """Test 4: File listing by domain test"""
    print("\n" + "=" * 60)
    print("[Test 4] List Files by Domain")
    print("=" * 60)

    test_domains = [
        'HomeDomain',
        'AppDomain-com.iwilab.KakaoTalk',
        'AppDomainGroup-group.net.whatsapp.WhatsApp.shared',
        'AppDomain-ph.telegra.Telegraph',
    ]

    try:
        from collectors.ios_collector import iOSBackupParser

        parser = run_with_timeout(lambda: iOSBackupParser(BACKUP_PATH), DEFAULT_TIMEOUT)

        for domain in test_domains:
            def get_domain_files(d=domain):
                return list(parser.list_files(domain_filter=d))

            try:
                files = run_with_timeout(get_domain_files, 10)
                print(f"  [OK] {domain}: {len(files)} files")
            except TimeoutError:
                print(f"  [WARN] {domain}: TIMEOUT")
            except Exception as e:
                print(f"  [WARN] {domain}: {e}")

        return True

    except TimeoutError as e:
        print(f"  [FAIL] TIMEOUT: {e}")
        return False
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_extract_sms():
    """Test 5: SMS data extraction test"""
    print("\n" + "=" * 60)
    print("[Test 5] Extract SMS Database")
    print("=" * 60)

    OUTPUT_DIR.mkdir(exist_ok=True)

    try:
        from collectors.ios_collector import iOSBackupParser

        def extract_sms():
            parser = iOSBackupParser(BACKUP_PATH)
            output_path = OUTPUT_DIR / "sms.db"
            success = parser.extract_file(
                'HomeDomain',
                'Library/SMS/sms.db',
                output_path
            )
            return success, output_path

        success, output_path = run_with_timeout(extract_sms, DEFAULT_TIMEOUT)

        if success and output_path.exists():
            size = output_path.stat().st_size
            print(f"  [OK] SMS database extracted: {output_path}")
            print(f"  [OK] Size: {size:,} bytes")
            return True
        else:
            print(f"  [WARN] SMS database not found in backup (this may be normal)")
            return True  # Not a failure, just no SMS

    except TimeoutError as e:
        print(f"  [FAIL] TIMEOUT: {e}")
        return False
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_extract_contacts():
    """Test 6: Contacts data extraction test"""
    print("\n" + "=" * 60)
    print("[Test 6] Extract Contacts Database")
    print("=" * 60)

    OUTPUT_DIR.mkdir(exist_ok=True)

    try:
        from collectors.ios_collector import iOSBackupParser

        def extract_contacts():
            parser = iOSBackupParser(BACKUP_PATH)
            output_path = OUTPUT_DIR / "AddressBook.sqlitedb"
            success = parser.extract_file(
                'HomeDomain',
                'Library/AddressBook/AddressBook.sqlitedb',
                output_path
            )
            return success, output_path

        success, output_path = run_with_timeout(extract_contacts, DEFAULT_TIMEOUT)

        if success and output_path.exists():
            size = output_path.stat().st_size
            print(f"  [OK] Contacts database extracted: {output_path}")
            print(f"  [OK] Size: {size:,} bytes")
            return True
        else:
            print(f"  [WARN] Contacts database not found in backup")
            return True

    except TimeoutError as e:
        print(f"  [FAIL] TIMEOUT: {e}")
        return False
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def test_collector_workflow():
    """Test 7: iOSCollector full workflow test"""
    print("\n" + "=" * 60)
    print("[Test 7] iOSCollector Workflow")
    print("=" * 60)

    OUTPUT_DIR.mkdir(exist_ok=True)

    try:
        from collectors.ios_collector import iOSCollector

        def run_collector():
            collector = iOSCollector(OUTPUT_DIR)
            collector.select_backup(BACKUP_PATH)

            # Collect backup metadata
            results = list(collector.collect('mobile_ios_backup'))
            return results

        results = run_with_timeout(run_collector, DEFAULT_TIMEOUT * 2)

        print(f"  [OK] Collected {len(results)} items")
        for path, meta in results[:3]:
            print(f"      - {Path(path).name}: {meta.get('status', 'ok')}")

        return True

    except TimeoutError as e:
        print(f"  [FAIL] TIMEOUT: {e}")
        return False
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_kakaotalk_extraction():
    """Test 8: KakaoTalk data extraction test"""
    print("\n" + "=" * 60)
    print("[Test 8] Extract KakaoTalk Data")
    print("=" * 60)

    OUTPUT_DIR.mkdir(exist_ok=True)

    try:
        from collectors.ios_collector import iOSCollector

        def extract_kakaotalk():
            collector = iOSCollector(OUTPUT_DIR)
            collector.select_backup(BACKUP_PATH)
            results = list(collector.collect('mobile_ios_kakaotalk'))
            return results

        results = run_with_timeout(extract_kakaotalk, DEFAULT_TIMEOUT * 2)

        if results:
            print(f"  [OK] KakaoTalk: {len(results)} files extracted")
            for path, meta in results[:3]:
                status = meta.get('status', 'ok')
                if status == 'error':
                    print(f"      - Error: {meta.get('error', 'unknown')}")
                else:
                    print(f"      - {Path(path).name}")
        else:
            print(f"  [WARN] KakaoTalk not found in backup")

        return True

    except TimeoutError as e:
        print(f"  [FAIL] TIMEOUT: {e}")
        return False
    except Exception as e:
        print(f"  [FAIL] Error: {e}")
        return False


def run_all_tests():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("  iOS PARSER TEST SUITE (with Timeout Protection)")
    print(f"  Backup: {BACKUP_PATH.name}")
    print(f"  Timeout: {DEFAULT_TIMEOUT}s per operation")
    print("=" * 60)

    tests = [
        ("Module Import", test_import_modules),
        ("Backup Info", test_backup_info),
        ("List Files", test_list_files),
        ("List by Domain", test_list_files_by_domain),
        ("Extract SMS", test_extract_sms),
        ("Extract Contacts", test_extract_contacts),
        ("Collector Workflow", test_collector_workflow),
        ("KakaoTalk Extraction", test_kakaotalk_extraction),
    ]

    results = {"passed": 0, "failed": 0, "timeout": 0}

    for name, test_func in tests:
        try:
            # Global timeout for each test
            success = run_with_timeout(test_func, DEFAULT_TIMEOUT * 3)
            if success:
                results["passed"] += 1
            else:
                results["failed"] += 1
        except TimeoutError:
            print(f"\n  [FAIL] TEST TIMEOUT: {name}")
            results["timeout"] += 1
        except Exception as e:
            print(f"\n  [FAIL] TEST ERROR: {name} - {e}")
            results["failed"] += 1

    # Summary
    print("\n" + "=" * 60)
    print("  TEST SUMMARY")
    print("=" * 60)
    print(f"  [OK] Passed:  {results['passed']}")
    print(f"  [FAIL] Failed:  {results['failed']}")
    print(f"  [TIMEOUT] Timeout: {results['timeout']}")
    print(f"  Total:     {sum(results.values())}")
    print("=" * 60)

    return results["failed"] == 0 and results["timeout"] == 0


if __name__ == "__main__":
    try:
        success = run_all_tests()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n  [WARN] Test interrupted by user")
        sys.exit(130)
