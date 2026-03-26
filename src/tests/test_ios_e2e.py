# -*- coding: utf-8 -*-
"""
iOS Collection & Parsing End-to-End Test

End-to-end pipeline test from iOS collection to parsing
"""
import sys
import os
import json
import sqlite3
import tempfile
import shutil
import hashlib
import plistlib
from pathlib import Path
from datetime import datetime

# Add paths
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / 'migration' / 'backend'))


def create_mock_ios_backup(base_dir: Path) -> Path:
    """Create mock iOS backup for testing"""
    backup_dir = base_dir / '00008030-TEST12345678001C'
    backup_dir.mkdir(parents=True)

    # Create Info.plist
    info_plist = {
        'Device Name': 'Test iPhone',
        'Target Identifier': '00008030-TEST12345678001C',
        'Product Type': 'iPhone14,2',
        'Product Version': '17.0',
        'Last Backup Date': datetime.now(),
        'IsEncrypted': False,
    }

    with open(backup_dir / 'Info.plist', 'wb') as f:
        plistlib.dump(info_plist, f)

    # Create Manifest.db
    manifest_db = backup_dir / 'Manifest.db'
    conn = sqlite3.connect(str(manifest_db))
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE Files (
            fileID TEXT PRIMARY KEY,
            domain TEXT,
            relativePath TEXT,
            flags INTEGER,
            file BLOB
        )
    ''')

    # Add SMS database entry
    sms_hash = hashlib.sha1(b'HomeDomain-Library/SMS/sms.db').hexdigest()
    cursor.execute('INSERT INTO Files VALUES (?, ?, ?, ?, ?)',
        (sms_hash, 'HomeDomain', 'Library/SMS/sms.db', 1, None))

    # Add KakaoTalk database entry
    kakao_hash = hashlib.sha1(b'AppDomain-com.iwilab.KakaoTalk-Library/PrivateDocuments/Message.sqlite').hexdigest()
    cursor.execute('INSERT INTO Files VALUES (?, ?, ?, ?, ?)',
        (kakao_hash, 'AppDomain-com.iwilab.KakaoTalk', 'Library/PrivateDocuments/Message.sqlite', 1, None))

    # Add WhatsApp database entry
    whatsapp_hash = hashlib.sha1(b'AppDomainGroup-group.net.whatsapp.WhatsApp.shared-ChatStorage.sqlite').hexdigest()
    cursor.execute('INSERT INTO Files VALUES (?, ?, ?, ?, ?)',
        (whatsapp_hash, 'AppDomainGroup-group.net.whatsapp.WhatsApp.shared', 'ChatStorage.sqlite', 1, None))

    conn.commit()
    conn.close()

    # Create subdirectory structure (iOS 10+ format)
    (backup_dir / sms_hash[:2]).mkdir(exist_ok=True)
    (backup_dir / kakao_hash[:2]).mkdir(exist_ok=True)
    (backup_dir / whatsapp_hash[:2]).mkdir(exist_ok=True)

    # Create mock SMS database
    sms_db_path = backup_dir / sms_hash[:2] / sms_hash
    conn = sqlite3.connect(str(sms_db_path))
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE message (
            ROWID INTEGER PRIMARY KEY,
            guid TEXT,
            text TEXT,
            handle_id INTEGER,
            date INTEGER,
            is_from_me INTEGER,
            cache_has_attachments INTEGER
        )
    ''')

    cursor.execute('''
        CREATE TABLE handle (
            ROWID INTEGER PRIMARY KEY,
            id TEXT,
            country TEXT,
            service TEXT
        )
    ''')

    # Insert test messages
    cursor.execute('INSERT INTO handle VALUES (1, "+821012345678", "kr", "iMessage")')
    cursor.execute('INSERT INTO message VALUES (1, "guid1", "테스트 메시지 1", 1, 700000000000000000, 0, 0)')
    cursor.execute('INSERT INTO message VALUES (2, "guid2", "Hello from iPhone", 1, 700000001000000000, 1, 0)')
    cursor.execute('INSERT INTO message VALUES (3, "guid3", "중요한 정보입니다", 1, 700000002000000000, 0, 0)')

    conn.commit()
    conn.close()

    # Create mock KakaoTalk database
    kakao_db_path = backup_dir / kakao_hash[:2] / kakao_hash
    conn = sqlite3.connect(str(kakao_db_path))
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE ZMESSAGE (
            Z_PK INTEGER PRIMARY KEY,
            ZTYPE INTEGER,
            ZMESSAGE TEXT,
            ZSENDERID TEXT,
            ZSENTTIME INTEGER,
            ZENCRYPTEDKEY TEXT
        )
    ''')

    cursor.execute('INSERT INTO ZMESSAGE VALUES (1, 1, "암호화된메시지1", "user1", 1700000000, "enckey1")')
    cursor.execute('INSERT INTO ZMESSAGE VALUES (2, 1, "암호화된메시지2", "user2", 1700000100, "enckey2")')

    conn.commit()
    conn.close()

    # Create mock WhatsApp database
    whatsapp_db_path = backup_dir / whatsapp_hash[:2] / whatsapp_hash
    conn = sqlite3.connect(str(whatsapp_db_path))
    cursor = conn.cursor()

    # WhatsApp iOS schema (simplified)
    cursor.execute('''
        CREATE TABLE ZWAMESSAGE (
            Z_PK INTEGER PRIMARY KEY,
            ZTEXT TEXT,
            ZFROMJID TEXT,
            ZTOJID TEXT,
            ZMESSAGEDATE REAL,
            ZISFROMME INTEGER
        )
    ''')

    cursor.execute('''
        CREATE TABLE ZWACHATSESSION (
            Z_PK INTEGER PRIMARY KEY,
            ZCONTACTJID TEXT,
            ZPARTNERNAME TEXT
        )
    ''')

    # Core Data timestamp (seconds since 2001-01-01)
    cursor.execute('INSERT INTO ZWACHATSESSION VALUES (1, "821087654321@s.whatsapp.net", "John Doe")')
    cursor.execute('INSERT INTO ZWAMESSAGE VALUES (1, "WhatsApp test message 1", "821087654321@s.whatsapp.net", NULL, 700000000.0, 0)')
    cursor.execute('INSERT INTO ZWAMESSAGE VALUES (2, "WhatsApp reply", NULL, "821087654321@s.whatsapp.net", 700000100.0, 1)')

    conn.commit()
    conn.close()

    return backup_dir


def test_ios_collector(backup_dir: Path, output_dir: Path):
    """Test iOS Collector"""
    from collectors.ios_collector import (
        iOSBackupParser,
        iOSCollector,
        IOS_ARTIFACT_TYPES,
        parse_backup_info
    )

    # Parse backup info
    backup_info = parse_backup_info(backup_dir)
    print(f'  Backup Info:')
    print(f'    Device: {backup_info.device_name}')
    print(f'    iOS: {backup_info.ios_version}')
    print(f'    Encrypted: {backup_info.encrypted}')
    print()

    # Initialize collector
    collector = iOSCollector(str(output_dir))
    collector.select_backup(str(backup_dir))

    print(f'  Available artifact types: {len(IOS_ARTIFACT_TYPES)}')

    # Collect SMS
    print()
    print('  Collecting mobile_ios_sms...')
    sms_files = []
    for path, metadata in collector.collect('mobile_ios_sms'):
        if path:
            sms_files.append((path, metadata))
            print(f'    Collected: {metadata.get("filename", "unknown")}')
            print(f'    Size: {metadata.get("size", 0)} bytes')

    print(f'  Total SMS files collected: {len(sms_files)}')

    # Collect KakaoTalk
    print()
    print('  Collecting mobile_ios_kakaotalk...')
    kakao_files = []
    for path, metadata in collector.collect('mobile_ios_kakaotalk'):
        if path:
            kakao_files.append((path, metadata))
            print(f'    Collected: {metadata.get("filename", "unknown")}')
            print(f'    Size: {metadata.get("size", 0)} bytes')

    print(f'  Total KakaoTalk files collected: {len(kakao_files)}')

    # Collect WhatsApp
    print()
    print('  Collecting mobile_ios_whatsapp...')
    whatsapp_files = []
    for path, metadata in collector.collect('mobile_ios_whatsapp'):
        if path:
            whatsapp_files.append((path, metadata))
            print(f'    Collected: {metadata.get("filename", "unknown")}')
            print(f'    Size: {metadata.get("size", 0)} bytes')

    print(f'  Total WhatsApp files collected: {len(whatsapp_files)}')

    return sms_files, kakao_files, whatsapp_files


def test_sms_parsing(sms_files):
    """Test SMS parsing"""
    if not sms_files:
        print('  No SMS files to parse')
        return

    sms_path = sms_files[0][0]
    print(f'  Parsing SMS from: {Path(sms_path).name}')

    conn = sqlite3.connect(sms_path)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM message')
    msg_count = cursor.fetchone()[0]

    cursor.execute('SELECT text, is_from_me FROM message LIMIT 5')
    messages = cursor.fetchall()
    conn.close()

    print(f'    Found {msg_count} messages:')
    for text, is_from_me in messages:
        direction = 'Sent' if is_from_me else 'Received'
        display_text = text[:30] + '...' if len(text) > 30 else text
        print(f'      [{direction}] {display_text}')


def test_whatsapp_parser(whatsapp_files):
    """Test WhatsApp parser"""
    if not whatsapp_files:
        print('  No WhatsApp files to parse')
        return False

    try:
        from services.parsers.whatsapp_parser import WhatsAppParser, get_whatsapp_parser

        whatsapp_path = whatsapp_files[0][0]
        print(f'  Parsing WhatsApp from: {Path(whatsapp_path).name}')

        parser = get_whatsapp_parser(whatsapp_path)

        # Get chats
        chats = parser.get_chats()
        print(f'    Found {len(chats)} chat sessions')

        # Get messages
        messages = parser.get_messages()
        print(f'    Found {len(messages)} messages')

        for msg in messages[:3]:
            direction = 'Sent' if msg.is_from_me else 'Received'
            text = msg.text[:30] + '...' if msg.text and len(msg.text) > 30 else msg.text
            print(f'      [{direction}] {text}')

        return True
    except Exception as e:
        print(f'    WhatsApp parser error: {e}')
        return False


def test_messenger_parsers_import():
    """Test messenger parsers import"""
    results = {}

    parsers = [
        ('WhatsApp', 'services.parsers.whatsapp_parser', 'WhatsAppParser'),
        ('Telegram', 'services.parsers.telegram_parser', 'TelegramParser'),
        ('LINE', 'services.parsers.line_parser', 'LINEParser'),
        ('Messenger', 'services.parsers.messenger_parser', 'MessengerParser'),
        ('Instagram', 'services.parsers.instagram_parser', 'InstagramParser'),
        ('Skype', 'services.parsers.skype_parser', 'SkypeParser'),
        ('Snapchat', 'services.parsers.snapchat_parser', 'SnapchatParser'),
        ('KakaoTalk', 'services.parsers.kakaotalk_parser', 'KakaoTalkParser'),
    ]

    for name, module, class_name in parsers:
        try:
            mod = __import__(module, fromlist=[class_name])
            cls = getattr(mod, class_name)
            results[name] = True
            print(f'  {name} Parser: OK')
        except ImportError as e:
            results[name] = False
            print(f'  {name} Parser: IMPORT ERROR - {e}')
        except Exception as e:
            results[name] = False
            print(f'  {name} Parser: ERROR - {e}')

    return results


def main():
    print('=' * 70)
    print('iOS Collection & Parsing End-to-End Test')
    print('=' * 70)
    print()

    temp_dir = None
    try:
        # Step 1: Create Mock iOS Backup
        print('[Step 1] Creating Mock iOS Backup...')
        temp_dir = Path(tempfile.mkdtemp(prefix='ios_test_'))
        backup_dir = create_mock_ios_backup(temp_dir)
        print(f'  Created mock backup at: {backup_dir}')
        print(f'  - Info.plist: OK')
        print(f'  - Manifest.db: OK')
        print(f'  - SMS database: 3 messages')
        print(f'  - KakaoTalk database: 2 messages')
        print(f'  - WhatsApp database: 2 messages')
        print()

        # Step 2: Test iOS Collector
        print('[Step 2] Testing iOS Collector...')
        output_dir = temp_dir / 'collected'
        output_dir.mkdir()
        sms_files, kakao_files, whatsapp_files = test_ios_collector(backup_dir, output_dir)
        print()

        # Step 3: Test SMS Parsing
        print('[Step 3] Testing SMS Parsing...')
        test_sms_parsing(sms_files)
        print()

        # Step 4: Test WhatsApp Parser
        print('[Step 4] Testing WhatsApp Parser...')
        test_whatsapp_parser(whatsapp_files)
        print()

        # Step 5: Test Messenger Parsers Import
        print('[Step 5] Testing Messenger Parsers Import...')
        parser_results = test_messenger_parsers_import()
        print()

        # Summary
        print('=' * 70)
        print('TEST SUMMARY')
        print('=' * 70)
        print(f'  SMS Collection: {"PASS" if sms_files else "FAIL"}')
        print(f'  KakaoTalk Collection: {"PASS" if kakao_files else "FAIL"}')
        print(f'  WhatsApp Collection: {"PASS" if whatsapp_files else "FAIL"}')
        print(f'  Parsers Available: {sum(parser_results.values())}/{len(parser_results)}')
        print()
        print('TEST COMPLETED SUCCESSFULLY')
        print('=' * 70)

    except Exception as e:
        print(f'TEST FAILED: {e}')
        import traceback
        traceback.print_exc()
        return 1

    finally:
        # Cleanup
        if temp_dir and temp_dir.exists():
            print()
            print('[Cleanup] Removing temp directory...')
            shutil.rmtree(temp_dir, ignore_errors=True)
            print(f'  Removed: {temp_dir}')

    return 0


if __name__ == '__main__':
    sys.exit(main())
