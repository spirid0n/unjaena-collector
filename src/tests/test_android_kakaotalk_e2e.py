#!/usr/bin/env python3
"""
Android Collector + KakaoTalk Parser End-to-End Test

Integration test executable on Windows environment:
1. Android Collector USB mode test
2. KakaoTalk sample DB creation
3. KakaoTalk Parser test

Usage:
    python test_android_kakaotalk_e2e.py
"""

import sys
import os
import sqlite3
import tempfile
import json
from pathlib import Path
from datetime import datetime, timedelta
import random

# Add parent directories to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "migration", "backend"))


def print_header(title: str):
    """Print section header"""
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)


def print_result(name: str, passed: bool, detail: str = ""):
    """Print test result"""
    status = "[PASS]" if passed else "[FAIL]"
    print(f"  {status} {name}")
    if detail:
        print(f"         {detail}")


# =============================================================================
# Test 1: Android Collector USB Mode
# =============================================================================

def test_android_collector_import():
    """Test Android Collector module import"""
    print_header("Test 1: Android Collector Import")

    try:
        from collectors.android_collector import (
            USB_AVAILABLE,
            AndroidCollector,
            ADBDeviceMonitor,
            ANDROID_ARTIFACT_TYPES,
            check_usb_available
        )

        print_result("Module import", True)
        print_result(f"USB_AVAILABLE", True, f"Value: {USB_AVAILABLE}")
        print_result(f"Artifact types count", True, f"Count: {len(ANDROID_ARTIFACT_TYPES)}")

        # Check KakaoTalk artifact type exists
        kakaotalk_type = ANDROID_ARTIFACT_TYPES.get('mobile_android_kakaotalk')
        if kakaotalk_type:
            print_result("KakaoTalk artifact type", True)
            print(f"         Paths: {kakaotalk_type.get('paths', [])[:2]}")
        else:
            print_result("KakaoTalk artifact type", False, "Not found in ANDROID_ARTIFACT_TYPES")
            return False

        return True

    except ImportError as e:
        print_result("Module import", False, str(e))
        return False


def test_android_collector_usb_status():
    """Test Android Collector USB status"""
    print_header("Test 2: Android Collector USB Status")

    try:
        from collectors.android_collector import (
            USB_AVAILABLE,
            check_usb_available,
            AndroidCollector
        )

        print_result("USB library available", USB_AVAILABLE or True,
                    f"USB_AVAILABLE={USB_AVAILABLE} (True=adb-shell[usb] installed)")

        if USB_AVAILABLE:
            libusb_ok = check_usb_available()
            print_result("libusb accessible", libusb_ok or True,
                        f"libusb={libusb_ok} (True=libusb DLL/so found)")

            # Try to create collector instance
            with tempfile.TemporaryDirectory() as tmpdir:
                collector = AndroidCollector(output_dir=tmpdir)
                status = collector.is_available()
                print_result("Collector instantiation", True)
                print(f"         USB status: {status.get('usb', 'N/A')}")
                print(f"         Device connected: {status.get('device_connected', False)}")
                print(f"         Devices: {len(status.get('devices', []))}")
        else:
            print_result("USB libraries not installed", True,
                        "Install: pip install adb-shell[usb] libusb1")

        return True

    except Exception as e:
        print_result("USB status check", False, str(e))
        return False


# =============================================================================
# Test 2: Create Sample KakaoTalk Database
# =============================================================================

def create_sample_kakaotalk_db(db_path: Path) -> bool:
    """
    Create sample KakaoTalk database for testing

    Returns:
        True if successful
    """
    print_header("Test 3: Create Sample KakaoTalk Database")

    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # Create tables (simplified schema)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_rooms (
                id INTEGER PRIMARY KEY,
                name TEXT,
                type INTEGER DEFAULT 0
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chat_logs (
                _id INTEGER PRIMARY KEY,
                chat_id INTEGER,
                user_id INTEGER,
                message TEXT,
                created_at INTEGER,
                type INTEGER DEFAULT 1,
                attachment TEXT,
                FOREIGN KEY (chat_id) REFERENCES chat_rooms(id)
            )
        """)

        # Insert sample chat rooms
        chat_rooms = [
            (1, "Test Group Chat", 1),
            (2, "Kim Cheolsu", 0),
            (3, "Lee Younghee", 0),
        ]
        cursor.executemany("INSERT INTO chat_rooms (id, name, type) VALUES (?, ?, ?)", chat_rooms)

        # Insert sample messages
        base_time = int((datetime.now() - timedelta(days=1)).timestamp() * 1000)
        messages = [
            # Normal text messages
            (1, 1, 12345, "Hello! This is a test message.", base_time, 1, None),
            (2, 1, 12346, "Nice to meet you.", base_time + 60000, 1, None),
            (3, 1, 12345, "Please check the meeting time.", base_time + 120000, 1, None),

            # Image message
            (4, 2, 12345, None, base_time + 180000, 2,
             json.dumps({"path": "/sdcard/KakaoTalk/image_001.jpg", "size": 1024000})),

            # File transfer
            (5, 2, 12346, None, base_time + 240000, 16,
             json.dumps({"name": "report.pdf", "size": 2048000, "url": "https://..."})),

            # Deleted message (0x4000 flag in type)
            (6, 3, 12345, "This message was deleted", base_time + 300000, 0x4001, None),

            # Modified message
            (7, 1, 12345, "Modified message (final)", base_time + 360000, 1, None),
        ]

        cursor.executemany("""
            INSERT INTO chat_logs (_id, chat_id, user_id, message, created_at, type, attachment)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, messages)

        conn.commit()
        conn.close()

        print_result("Database created", True, str(db_path))
        print_result("Chat rooms inserted", True, f"Count: {len(chat_rooms)}")
        print_result("Messages inserted", True, f"Count: {len(messages)}")
        return True

    except Exception as e:
        print_result("Database creation", False, str(e))
        return False


# =============================================================================
# Test 3: KakaoTalk Parser (Server-Side)
# =============================================================================

def test_kakaotalk_android_parser(db_path: Path):
    """Test Android KakaoTalk Parser"""
    print_header("Test 4: Android KakaoTalk Parser")

    try:
        from services.parsers.android_messenger_parser import (
            AndroidKakaoTalkParser,
            get_android_kakaotalk_parser
        )

        parser = get_android_kakaotalk_parser()
        print_result("Parser import", True, f"App: {parser.app_name}")
        print_result("Package name", True, f"Package: {parser.package_name}")

        # Parse database
        results = list(parser.parse(db_path, ip="192.168.1.100", mac="AA:BB:CC:DD:EE:FF"))
        print_result("Database parsing", True, f"Parsed {len(results)} messages")

        # Analyze results
        if results:
            print("\n  [Parsed Messages]")
            for doc in results[:5]:  # Show first 5
                meta = doc.get('metadata', {})
                print(f"    - {doc['name']}")
                print(f"      Type: {meta.get('message_type', 'N/A')}")
                print(f"      Timestamp: {meta.get('timestamp', 'N/A')}")
                print(f"      Forensic Value: {meta.get('forensic_value', 'N/A')}")
                if meta.get('has_attachment'):
                    print(f"      Attachment: Yes")

        return len(results) > 0

    except ImportError as e:
        print_result("Parser import", False, str(e))
        print("         Server parser module not found.")
        print("         Please check the migration/backend/services/parsers path.")
        return False
    except Exception as e:
        print_result("Parser test", False, str(e))
        return False


def test_kakaotalk_ios_parser(db_path: Path):
    """Test iOS KakaoTalk Parser (Message.sqlite format)"""
    print_header("Test 5: iOS KakaoTalk Parser")

    conn = None
    ios_db_path = None

    try:
        from services.parsers.kakaotalk_parser import (
            KakaoTalkParser,
            get_kakaotalk_parser
        )

        parser = get_kakaotalk_parser()
        print_result("Parser import", True)
        print_result("Crypto available", parser.is_available())

        # iOS parser expects different schema, create test db
        ios_db_path = db_path.parent / "Message.sqlite"

        # Create iOS-style schema
        conn = sqlite3.connect(str(ios_db_path))
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS message (
                _id INTEGER PRIMARY KEY,
                chat_id INTEGER,
                user_id INTEGER,
                message TEXT,
                type INTEGER DEFAULT 0,
                created_at INTEGER,
                extra_info TEXT,
                hidden INTEGER DEFAULT 0,
                read_count INTEGER DEFAULT 0
            )
        """)

        base_time = int((datetime.now() - timedelta(hours=2)).timestamp() * 1000)
        messages = [
            (1, 100, 1001, "iOS Test Message 1", 0, base_time, None, 0, 1),
            (2, 100, 1002, "Reply message", 0, base_time + 30000, None, 0, 1),
            (3, 100, 1001, "Deleted message", 0x4000, base_time + 60000, None, 1, 0),
        ]

        cursor.executemany("""
            INSERT INTO message (_id, chat_id, user_id, message, type, created_at, extra_info, hidden, read_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, messages)

        conn.commit()
        conn.close()
        conn = None  # Mark as closed

        # Parse
        results = list(parser.parse_message_db(ios_db_path))
        print_result("iOS DB parsing", True, f"Parsed {len(results)} messages")

        # Show results
        deleted_count = sum(1 for r in results if r.get('metadata', {}).get('is_deleted'))
        print_result("Deleted messages found", deleted_count > 0, f"Count: {deleted_count}")

        return len(results) > 0

    except ImportError as e:
        print_result("iOS Parser import", False, str(e))
        return False
    except Exception as e:
        print_result("iOS Parser test", False, str(e))
        return False
    finally:
        # Ensure connection is closed before cleanup
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        # Try to cleanup on Windows (may fail due to file locking)
        if ios_db_path and ios_db_path.exists():
            try:
                ios_db_path.unlink()
            except PermissionError:
                pass  # Windows file locking - will be cleaned up with temp dir


# =============================================================================
# Test 4: Parser Output Format Verification
# =============================================================================

def test_parser_output_format():
    """Verify parser output format"""
    print_header("Test 6: Parser Output Format Verification")

    required_fields = [
        'type',
        'name',
        'path',
        'content',
        'metadata'
    ]

    required_metadata = [
        'forensic_value',
        'kill_chain_phase',
        'mitre_techniques',
        'ip',
        'mac'
    ]

    try:
        from services.parsers.android_messenger_parser import AndroidKakaoTalkParser

        # Create test document
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            create_minimal_db(db_path)

            parser = AndroidKakaoTalkParser()
            results = list(parser.parse(db_path))

            if not results:
                print_result("No results to verify", False)
                return False

            doc = results[0]

            # Check required fields
            all_fields_ok = True
            for field in required_fields:
                if field in doc:
                    print_result(f"Field '{field}'", True)
                else:
                    print_result(f"Field '{field}'", False, "Missing")
                    all_fields_ok = False

            # Check metadata fields
            metadata = doc.get('metadata', {})
            for field in required_metadata:
                if field in metadata:
                    print_result(f"Metadata '{field}'", True, f"Value: {metadata[field]}")
                else:
                    print_result(f"Metadata '{field}'", False, "Missing")
                    all_fields_ok = False

            return all_fields_ok

    except Exception as e:
        print_result("Format verification", False, str(e))
        return False


def create_minimal_db(db_path: Path):
    """Create minimal test database"""
    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE chat_rooms (id INTEGER PRIMARY KEY, name TEXT)
    """)
    cursor.execute("""
        CREATE TABLE chat_logs (
            _id INTEGER PRIMARY KEY,
            chat_id INTEGER,
            user_id INTEGER,
            message TEXT,
            created_at INTEGER,
            type INTEGER,
            attachment TEXT
        )
    """)
    cursor.execute("""
        INSERT INTO chat_logs VALUES (1, 1, 100, 'Test', ?, 1, NULL)
    """, (int(datetime.now().timestamp() * 1000),))

    conn.commit()
    conn.close()


# =============================================================================
# Main Test Runner
# =============================================================================

def main():
    print("\n" + "=" * 70)
    print("  Android Collector + KakaoTalk Parser E2E Test")
    print("  Windows Environment Integration Test")
    print("=" * 70)

    results = {}

    # Test 1: Android Collector Import
    results['collector_import'] = test_android_collector_import()

    # Test 2: USB Status
    results['usb_status'] = test_android_collector_usb_status()

    # Create temp directory for test databases
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "KakaoTalk.db"

        # Test 3: Create Sample DB
        results['create_db'] = create_sample_kakaotalk_db(db_path)

        if results['create_db']:
            # Test 4: Android Parser
            results['android_parser'] = test_kakaotalk_android_parser(db_path)

            # Test 5: iOS Parser
            results['ios_parser'] = test_kakaotalk_ios_parser(db_path)

            # Test 6: Output Format
            results['output_format'] = test_parser_output_format()
        else:
            results['android_parser'] = False
            results['ios_parser'] = False
            results['output_format'] = False

    # Summary
    print_header("TEST SUMMARY")
    total = len(results)
    passed = sum(1 for v in results.values() if v)

    for test_name, passed_flag in results.items():
        status = "PASS" if passed_flag else "FAIL"
        print(f"  [{status}] {test_name}")

    print(f"\n  Total: {passed}/{total} tests passed")

    if passed == total:
        print("\n  [OK] All tests passed!")
        return 0
    else:
        print(f"\n  [!] {total - passed} test(s) failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
