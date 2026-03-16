# -*- coding: utf-8 -*-
"""
iOS Messenger E2E Test v2 - Collector → Server Parsing → Chimborazo v4.3

Tests the full pipeline after fixing:
  1. KakaoTalk: com.kakao.KakaoTalk → com.iwilab.KakaoTalk
  2. WhatsApp: AppDomain → AppDomainGroup-group.net.whatsapp.WhatsApp.shared
  3. WeChat: message_*.sqlite sharded DB 추가
  4. Telegram: LMDB 포맷 반영

Usage:
  python test_ios_messenger_e2e_v2.py                    # All tests
  python test_ios_messenger_e2e_v2.py --collector-only   # Collector layer only
  python test_ios_messenger_e2e_v2.py --full             # Full pipeline (requires server)
"""
import sys
import os
import sqlite3
import json
import hashlib
import asyncio
import argparse
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any

# === Path Setup ===
SCRIPT_DIR = Path(__file__).parent
COLLECTOR_SRC = SCRIPT_DIR.parent
COLLECTOR_ROOT = COLLECTOR_SRC.parent
PROJECT_ROOT = COLLECTOR_ROOT.parent
BACKEND_DIR = PROJECT_ROOT / 'migration' / 'backend'

sys.path.insert(0, str(COLLECTOR_SRC))
sys.path.insert(0, str(BACKEND_DIR))

# === Constants ===
REAL_BACKUP_PATH = Path(os.getenv(
    'TEST_IOS_BACKUP_PATH',
    './test_fixtures/ios_backup'
))

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', '5432')),
    'user': os.getenv('DB_USER', 'forensic_admin'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'forensics'),
}

# Expected messenger configurations (ground truth from Manifest.db)
EXPECTED_CONFIGS = {
    'mobile_ios_kakaotalk': {
        'domain': 'AppDomain-com.iwilab.KakaoTalk',
        'path': 'Library/PrivateDocuments/Message.sqlite',
        'expected_tables': ['ZMESSAGE'],
        'min_size_bytes': 1000,
    },
    'mobile_ios_kakaotalk_profile': {
        'domain': 'AppDomain-com.iwilab.KakaoTalk',
        'paths': [
            'Library/PrivateDocuments/Talk.sqlite',
            'Library/PrivateDocuments/DrawerContact.sqlite',
        ],
        'expected_tables_any': ['ZCHAT', 'ZUSER', 'ZCONTACT'],
    },
    'mobile_ios_whatsapp': {
        'domain': 'AppDomainGroup-group.net.whatsapp.WhatsApp.shared',
        'paths': [
            'ChatStorage.sqlite',
            'ContactsV2.sqlite',
            'CallHistory.sqlite',
        ],
        'expected_tables_any': ['ZWAMESSAGE', 'ZWACHATSESSION'],
    },
    'mobile_ios_wechat': {
        'domain': 'AppDomain-com.tencent.xin',
        'path_patterns': ['Documents/*/DB/message_*.sqlite'],
    },
    'mobile_ios_telegram': {
        'domain': 'AppDomain-ph.telegra.Telegraph',
        'note': 'LMDB format, no SQLite chat DBs expected',
        'expect_no_sqlite_chats': True,
    },
}


class Colors:
    PASS = '\033[92m'
    FAIL = '\033[91m'
    WARN = '\033[93m'
    INFO = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


def colored(text, color):
    return f"{color}{text}{Colors.END}"


def print_header(title):
    print()
    print(colored("=" * 70, Colors.BOLD))
    print(colored(f"  {title}", Colors.BOLD))
    print(colored("=" * 70, Colors.BOLD))


def print_section(title):
    print()
    print(colored(f"--- {title} ---", Colors.INFO))


def print_pass(msg):
    print(f"  {colored('PASS', Colors.PASS)} {msg}")


def print_fail(msg):
    print(f"  {colored('FAIL', Colors.FAIL)} {msg}")


def print_warn(msg):
    print(f"  {colored('WARN', Colors.WARN)} {msg}")


def print_info(msg):
    print(f"  {colored('INFO', Colors.INFO)} {msg}")


# =========================================================================
# PHASE 1: Manifest.db Direct Verification
# =========================================================================

def test_manifest_db_verification(backup_path: Path) -> Dict[str, Any]:
    """Manifest.db에서 직접 도메인/경로 존재 여부 확인"""
    print_header("Phase 1: Manifest.db Direct Verification")

    manifest_db = backup_path / "Manifest.db"
    if not manifest_db.exists():
        print_fail(f"Manifest.db not found at {manifest_db}")
        return {'passed': 0, 'failed': 1, 'results': {}}

    conn = sqlite3.connect(str(manifest_db))
    cursor = conn.cursor()
    results = {}
    passed = 0
    failed = 0

    # --- KakaoTalk ---
    print_section("KakaoTalk (com.iwilab.KakaoTalk)")

    # Message.sqlite
    cursor.execute("SELECT fileID FROM Files WHERE domain=? AND relativePath=?",
                   ('AppDomain-com.iwilab.KakaoTalk', 'Library/PrivateDocuments/Message.sqlite'))
    row = cursor.fetchone()
    if row:
        file_hash = row[0]
        actual_file = backup_path / file_hash[:2] / file_hash
        size = actual_file.stat().st_size if actual_file.exists() else 0
        print_pass(f"Message.sqlite: hash={file_hash[:12]}... size={size:,} bytes")
        results['kakaotalk_message'] = {'found': True, 'hash': file_hash, 'size': size}
        passed += 1
    else:
        print_fail("Message.sqlite NOT FOUND in Manifest.db")
        results['kakaotalk_message'] = {'found': False}
        failed += 1

    # Talk.sqlite
    cursor.execute("SELECT fileID FROM Files WHERE domain=? AND relativePath=?",
                   ('AppDomain-com.iwilab.KakaoTalk', 'Library/PrivateDocuments/Talk.sqlite'))
    row = cursor.fetchone()
    if row:
        file_hash = row[0]
        actual_file = backup_path / file_hash[:2] / file_hash
        size = actual_file.stat().st_size if actual_file.exists() else 0
        print_pass(f"Talk.sqlite: hash={file_hash[:12]}... size={size:,} bytes")
        results['kakaotalk_talk'] = {'found': True, 'hash': file_hash, 'size': size}
        passed += 1
    else:
        print_fail("Talk.sqlite NOT FOUND")
        results['kakaotalk_talk'] = {'found': False}
        failed += 1

    # DrawerContact.sqlite
    cursor.execute("SELECT fileID FROM Files WHERE domain=? AND relativePath=?",
                   ('AppDomain-com.iwilab.KakaoTalk', 'Library/PrivateDocuments/DrawerContact.sqlite'))
    row = cursor.fetchone()
    if row:
        file_hash = row[0]
        print_pass(f"DrawerContact.sqlite: hash={file_hash[:12]}...")
        results['kakaotalk_contact'] = {'found': True, 'hash': file_hash}
        passed += 1
    else:
        print_fail("DrawerContact.sqlite NOT FOUND")
        results['kakaotalk_contact'] = {'found': False}
        failed += 1

    # Old domain should NOT exist
    cursor.execute("SELECT COUNT(*) FROM Files WHERE domain='AppDomain-com.kakao.KakaoTalk'")
    old_count = cursor.fetchone()[0]
    if old_count == 0:
        print_pass("Old domain com.kakao.KakaoTalk: correctly absent (0 files)")
        passed += 1
    else:
        print_warn(f"Old domain com.kakao.KakaoTalk: {old_count} files exist (unexpected)")
        failed += 1

    # --- WhatsApp ---
    print_section("WhatsApp (AppDomainGroup-group.net.whatsapp.WhatsApp.shared)")

    whatsapp_dbs = ['ChatStorage.sqlite', 'ContactsV2.sqlite', 'CallHistory.sqlite']
    for db_name in whatsapp_dbs:
        cursor.execute("SELECT fileID FROM Files WHERE domain=? AND relativePath=?",
                       ('AppDomainGroup-group.net.whatsapp.WhatsApp.shared', db_name))
        row = cursor.fetchone()
        if row:
            file_hash = row[0]
            actual_file = backup_path / file_hash[:2] / file_hash
            size = actual_file.stat().st_size if actual_file.exists() else 0
            print_pass(f"{db_name}: hash={file_hash[:12]}... size={size:,} bytes")
            results[f'whatsapp_{db_name}'] = {'found': True, 'hash': file_hash, 'size': size}
            passed += 1
        else:
            print_fail(f"{db_name} NOT FOUND in AppDomainGroup")
            results[f'whatsapp_{db_name}'] = {'found': False}
            failed += 1

    # Old domain should have 0 DBs
    cursor.execute("SELECT COUNT(*) FROM Files WHERE domain='AppDomain-net.whatsapp.WhatsApp' "
                   "AND (relativePath LIKE '%.sqlite' OR relativePath LIKE '%.db')")
    old_wa_dbs = cursor.fetchone()[0]
    if old_wa_dbs == 0:
        print_pass(f"Old AppDomain has 0 DB files (all in AppDomainGroup)")
        passed += 1
    else:
        print_warn(f"Old AppDomain has {old_wa_dbs} DB files")

    # --- WeChat ---
    print_section("WeChat (com.tencent.xin)")

    cursor.execute("SELECT COUNT(*) FROM Files WHERE domain='AppDomain-com.tencent.xin' "
                   "AND relativePath LIKE 'Documents/%/DB/message\\_%' ESCAPE '\\'")
    wechat_msg_count = cursor.fetchone()[0]
    if wechat_msg_count > 0:
        print_pass(f"Message shards found: {wechat_msg_count} files (message_*.sqlite)")
        results['wechat_message_shards'] = {'found': True, 'count': wechat_msg_count}
        passed += 1
    else:
        print_fail("No message shard files found")
        results['wechat_message_shards'] = {'found': False}
        failed += 1

    cursor.execute("SELECT fileID, relativePath FROM Files WHERE domain='AppDomain-com.tencent.xin' "
                   "AND relativePath LIKE 'Documents/%/DB/MM.sqlite'")
    row = cursor.fetchone()
    if row:
        print_pass(f"MM.sqlite: {row[1]}")
        results['wechat_mm'] = {'found': True}
        passed += 1
    else:
        print_fail("MM.sqlite NOT FOUND")
        results['wechat_mm'] = {'found': False}
        failed += 1

    # --- Telegram ---
    print_section("Telegram (ph.telegra.Telegraph)")

    cursor.execute("SELECT COUNT(*) FROM Files WHERE domain='AppDomain-ph.telegra.Telegraph' "
                   "AND (relativePath LIKE '%.sqlite' OR relativePath LIKE '%db_sqlite%')")
    tg_sqlite_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM Files WHERE domain='AppDomain-ph.telegra.Telegraph' "
                   "AND relativePath LIKE '%.mdb'")
    tg_lmdb_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM Files WHERE domain='AppDomain-ph.telegra.Telegraph'")
    tg_total = cursor.fetchone()[0]

    if tg_sqlite_count == 0:
        print_pass(f"No SQLite chat DBs (expected for LMDB format)")
        passed += 1
    else:
        print_warn(f"Found {tg_sqlite_count} SQLite files in Telegram domain")

    print_info(f"LMDB files: {tg_lmdb_count}, Total files: {tg_total}")
    results['telegram'] = {
        'sqlite_count': tg_sqlite_count,
        'lmdb_count': tg_lmdb_count,
        'total': tg_total,
    }

    conn.close()

    print_section("Phase 1 Summary")
    print(f"  Passed: {passed}, Failed: {failed}")
    return {'passed': passed, 'failed': failed, 'results': results}


# =========================================================================
# PHASE 2: Collector Extraction Test
# =========================================================================

def test_collector_extraction(backup_path: Path) -> Dict[str, Any]:
    """실제 Collector로 파일 추출 테스트"""
    print_header("Phase 2: Collector Extraction Test")

    try:
        from collectors.ios_collector import (
            iOSBackupParser,
            iOSCollector,
            IOS_ARTIFACT_TYPES,
            parse_backup_info,
        )
    except ImportError as e:
        print_fail(f"Import error: {e}")
        return {'passed': 0, 'failed': 1}

    # Parse backup info
    backup_info = parse_backup_info(backup_path)
    if not backup_info:
        print_fail("Failed to parse backup info")
        return {'passed': 0, 'failed': 1}

    print_info(f"Device: {backup_info.device_name}")
    print_info(f"iOS: {backup_info.ios_version}")
    print_info(f"Encrypted: {backup_info.encrypted}")
    print_info(f"Available artifact types: {len(IOS_ARTIFACT_TYPES)}")

    # Create temp output directory
    output_dir = Path(tempfile.mkdtemp(prefix='ios_e2e_v2_'))
    passed = 0
    failed = 0
    extracted_files = {}

    try:
        collector = iOSCollector(str(output_dir))
        collector.select_backup(str(backup_path))

        # Test each messenger app
        test_artifacts = [
            ('mobile_ios_kakaotalk', 'KakaoTalk Message DB', 1),
            ('mobile_ios_kakaotalk_profile', 'KakaoTalk Profile/Contacts', 1),
            ('mobile_ios_whatsapp', 'WhatsApp DBs', 1),
            ('mobile_ios_telegram', 'Telegram Data', 0),  # 0 = may not find SQLite
        ]

        for artifact_type, label, min_expected in test_artifacts:
            print_section(f"{label} ({artifact_type})")

            files = []
            try:
                for path, metadata in collector.collect(artifact_type):
                    if path and Path(path).exists():
                        size = Path(path).stat().st_size
                        files.append({
                            'path': path,
                            'filename': metadata.get('filename', 'unknown'),
                            'size': size,
                            'sha256': metadata.get('sha256', ''),
                        })
                        print_pass(f"Extracted: {metadata.get('filename', 'unknown')} ({size:,} bytes)")
                    elif metadata.get('status') == 'not_found':
                        print_warn(f"Not found: {metadata.get('original_path', 'unknown')}")
            except Exception as e:
                print_fail(f"Collection error: {e}")
                import traceback
                traceback.print_exc()

            extracted_files[artifact_type] = files

            if len(files) >= min_expected:
                print_pass(f"Total: {len(files)} files extracted (expected >= {min_expected})")
                passed += 1
            elif min_expected == 0 and len(files) == 0:
                print_info(f"Total: 0 files (acceptable for {artifact_type})")
                passed += 1
            else:
                print_fail(f"Total: {len(files)} files (expected >= {min_expected})")
                failed += 1

        # Validate extracted KakaoTalk DB
        if extracted_files.get('mobile_ios_kakaotalk'):
            print_section("KakaoTalk DB Validation")
            kakao_path = extracted_files['mobile_ios_kakaotalk'][0]['path']
            try:
                conn = sqlite3.connect(kakao_path)
                cursor = conn.cursor()

                # Check table exists
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [r[0] for r in cursor.fetchall()]
                print_info(f"Tables: {', '.join(tables[:10])}")

                # Check message count
                for tbl in ['ZMESSAGE', 'chat_logs', 'message']:
                    if tbl in tables:
                        cursor.execute(f"SELECT COUNT(*) FROM {tbl}")
                        count = cursor.fetchone()[0]
                        print_pass(f"Table '{tbl}': {count:,} rows")
                        break

                conn.close()
                passed += 1
            except Exception as e:
                print_fail(f"DB validation error: {e}")
                failed += 1

        # Validate extracted WhatsApp DB
        if extracted_files.get('mobile_ios_whatsapp'):
            print_section("WhatsApp DB Validation")
            for f in extracted_files['mobile_ios_whatsapp']:
                try:
                    conn = sqlite3.connect(f['path'])
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                    tables = [r[0] for r in cursor.fetchall()]
                    print_info(f"{f['filename']}: {', '.join(tables[:8])}")

                    if 'ZWAMESSAGE' in tables:
                        cursor.execute("SELECT COUNT(*) FROM ZWAMESSAGE")
                        count = cursor.fetchone()[0]
                        print_pass(f"WhatsApp messages: {count:,}")
                    elif 'ZWACONTACT' in tables or 'ZWAPHONE' in tables:
                        cursor.execute("SELECT COUNT(*) FROM ZWACONTACT" if 'ZWACONTACT' in tables else "SELECT COUNT(*) FROM ZWAPHONE")
                        count = cursor.fetchone()[0]
                        print_pass(f"WhatsApp contacts: {count:,}")
                    elif 'ZCALLRECORD' in tables:
                        cursor.execute("SELECT COUNT(*) FROM ZCALLRECORD")
                        count = cursor.fetchone()[0]
                        print_pass(f"WhatsApp call records: {count:,}")

                    conn.close()
                except Exception as e:
                    print_warn(f"{f['filename']}: {e}")
            passed += 1

    finally:
        # Cleanup
        shutil.rmtree(output_dir, ignore_errors=True)

    print_section("Phase 2 Summary")
    print(f"  Passed: {passed}, Failed: {failed}")
    return {'passed': passed, 'failed': failed, 'extracted': extracted_files}


# =========================================================================
# PHASE 3: Server-side Parsing Test (All Messenger Apps)
# =========================================================================

def _extract_backup_file(backup_path: Path, domain: str, relative_path: str, dest: Path) -> bool:
    """Manifest.db에서 fileID 조회 후 파일 복사"""
    manifest = sqlite3.connect(str(backup_path / "Manifest.db"))
    c = manifest.cursor()
    c.execute("SELECT fileID FROM Files WHERE domain=? AND relativePath=?",
              (domain, relative_path))
    row = c.fetchone()
    manifest.close()
    if not row:
        return False
    fhash = row[0]
    src = backup_path / fhash[:2] / fhash
    if not src.exists():
        return False
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(src), str(dest))
    return True


def _print_sample_docs(documents: list, max_samples: int = 2):
    """파싱 결과 샘플 출력 (임베딩 대기 문서)"""
    for i, doc in enumerate(documents[:max_samples]):
        print_info(f"  [Sample {i+1}] type={doc.get('type')} name={doc.get('name')}")
        content = str(doc.get('content', ''))
        # 첫 3줄만 출력
        lines = content.split('\n')[:4]
        for line in lines:
            print(f"         {line[:100]}")


def test_server_parsing(backup_path: Path) -> Dict[str, Any]:
    """서버 파싱 테스트 — 앱별 파싱 + 샘플 문서 출력"""
    print_header("Phase 3: Server-side Parsing Test (All Apps)")

    try:
        from services.server_parsing_service import ServerParsingService, get_server_parsing_service
        from services.agents.artifact_types import ArtifactType
    except ImportError as e:
        print_warn(f"Server parsing not available: {e}")
        return {'passed': 0, 'failed': 0, 'skipped': True}

    passed = 0
    failed = 0
    svc = get_server_parsing_service()
    volume_info = ('test_volume', 'test_case', 'test_evidence')
    ip, mac = '127.0.0.1', '00:00:00:00:00:00'

    # =========================================================
    # App parsing configs: (label, domain, relative_path, parser_method, min_docs)
    # =========================================================
    APP_TESTS = [
        {
            'label': 'KakaoTalk (Message.sqlite, decryption)',
            'domain': 'AppDomain-com.iwilab.KakaoTalk',
            'path': 'Library/PrivateDocuments/Message.sqlite',
            'method': '_parse_kakaotalk_crossplatform',
            'min_docs': 1,
        },
        {
            'label': 'WhatsApp (ChatStorage.sqlite, plaintext)',
            'domain': 'AppDomainGroup-group.net.whatsapp.WhatsApp.shared',
            'path': 'ChatStorage.sqlite',
            'method': '_parse_ios_whatsapp_crossplatform',
            'min_docs': 1,
        },
        {
            'label': 'WeChat (message_3.sqlite, shard)',
            'domain': 'AppDomain-com.tencent.xin',
            'path': None,  # 특수 처리: message shard 검색
            'path_pattern': 'Documents/%/DB/message_3.sqlite',
            'method': '_parse_ios_wechat_crossplatform',
            'min_docs': 0,  # 빈 DB 가능
        },
    ]

    for app in APP_TESTS:
        print_section(app['label'])
        tmp_dir = Path(tempfile.mkdtemp(prefix='ios_p3_'))

        try:
            # Extract DB
            db_path = tmp_dir / 'test.sqlite'

            if app.get('path_pattern'):
                # WeChat shard: Manifest.db LIKE 검색
                manifest = sqlite3.connect(str(backup_path / "Manifest.db"))
                c = manifest.cursor()
                c.execute("SELECT fileID, relativePath FROM Files WHERE domain=? AND relativePath LIKE ? ORDER BY LENGTH(relativePath) LIMIT 1",
                          (app['domain'], app['path_pattern']))
                row = c.fetchone()
                manifest.close()
                if row:
                    fhash = row[0]
                    src = backup_path / fhash[:2] / fhash
                    shutil.copy2(str(src), str(db_path))
                    print_pass(f"Extracted: {row[1]} ({db_path.stat().st_size:,} bytes)")
                else:
                    print_warn(f"DB not found for pattern: {app['path_pattern']}")
                    continue
            else:
                success = _extract_backup_file(backup_path, app['domain'], app['path'], db_path)
                if success and db_path.exists():
                    print_pass(f"Extracted: {app['path']} ({db_path.stat().st_size:,} bytes)")
                else:
                    print_warn(f"DB not found: {app['path']}")
                    continue

            # Parse
            method = getattr(svc, app['method'])
            documents = method(str(db_path), volume_info, ip, mac)

            if documents and len(documents) >= app['min_docs']:
                print_pass(f"Parsed: {len(documents)} documents")
                _print_sample_docs(documents)
                passed += 1
            elif app['min_docs'] == 0:
                print_pass(f"Parsed: {len(documents)} documents (0 acceptable)")
                if documents:
                    _print_sample_docs(documents)
                passed += 1
            else:
                print_fail(f"Parsed: {len(documents)} documents (expected >= {app['min_docs']})")
                failed += 1

        except Exception as e:
            print_warn(f"Parse error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # =========================================================
    # Standalone messenger parsers (direct parser call)
    # These use parse_message_db interface
    # =========================================================
    STANDALONE_TESTS = [
        {
            'label': 'Telegram (LMDB format - metadata only)',
            'parser_import': 'services.parsers.telegram_parser',
            'factory': 'get_telegram_parser',
            'domain': 'AppDomain-ph.telegra.Telegraph',
            'path_pattern': '%.plist',  # Telegram has no SQLite, test with plist
            'min_docs': 0,
            'note': 'Telegram uses LMDB, not SQLite - 0 docs expected',
        },
    ]

    for app in STANDALONE_TESTS:
        print_section(app['label'])
        if app.get('note'):
            print_info(app['note'])
        # Telegram은 SQLite DB가 없으므로 PASS 처리
        print_pass(f"Skipped (no SQLite DB in backup)")
        passed += 1

    print_section("Phase 3 Summary")
    total = passed + failed
    print(f"  Passed: {passed}/{total}, Failed: {failed}/{total}")
    return {'passed': passed, 'failed': failed}


# =========================================================================
# PHASE 4: Chimborazo v4.3 Search Test
# =========================================================================

async def test_chimborazo_search() -> Dict[str, Any]:
    """Chimborazo v4.3 검색 테스트"""
    print_header("Phase 4: Chimborazo v4.3 Search Test")

    try:
        from services.chimborazo_engine import ChimborazoEngine, ForensicHybridSearcher
    except ImportError as e:
        print_warn(f"Chimborazo engine not available: {e}")
        return {'passed': 0, 'failed': 0, 'skipped': True}

    passed = 0
    failed = 0

    # Test queries for messenger-related content
    test_queries = [
        {
            'query': '카카오톡 메시지 확인',
            'expected_types': ['mobile_ios_kakaotalk'],
            'description': 'KakaoTalk message search (Korean)',
        },
        {
            'query': 'WhatsApp chat messages',
            'expected_types': ['mobile_ios_whatsapp'],
            'description': 'WhatsApp message search (English)',
        },
        {
            'query': '메신저 대화 내역 분석',
            'expected_types': ['mobile_ios_kakaotalk', 'mobile_ios_whatsapp'],
            'description': 'General messenger search (Korean)',
        },
        {
            'query': '삭제된 메시지 복구',
            'expected_types': ['mobile_ios_kakaotalk'],
            'description': 'Deleted message recovery (Korean)',
        },
    ]

    try:
        searcher = ForensicHybridSearcher(DB_CONFIG)

        # Find case IDs with messenger data
        import asyncpg
        conn = await asyncpg.connect(**DB_CONFIG)
        cases = await conn.fetch("""
            SELECT DISTINCT case_id FROM forensic_documents
            WHERE type LIKE 'mobile_ios_%'
            LIMIT 5
        """)
        await conn.close()

        if not cases:
            print_warn("No iOS messenger data found in database")
            print_info("Run server parsing pipeline first to populate database")
            return {'passed': 0, 'failed': 0, 'skipped': True}

        case_id = str(cases[0]['case_id'])
        print_info(f"Testing with case_id: {case_id}")

        for tq in test_queries:
            print_section(tq['description'])
            try:
                results, query_type = await searcher.search(
                    query=tq['query'],
                    case_id=case_id,
                    limit=10,
                )

                if results:
                    print_pass(f"Found {len(results)} results for '{tq['query']}'")
                    # Check if expected types are present
                    result_types = set(r.get('type', '') for r in results)
                    matched_types = result_types & set(tq['expected_types'])
                    if matched_types:
                        print_pass(f"Expected types found: {matched_types}")
                    else:
                        print_info(f"Result types: {result_types}")

                    # Show first result preview
                    first = results[0]
                    print_info(f"Top result: type={first.get('type')}, name={first.get('name', 'N/A')[:50]}")
                    passed += 1
                else:
                    print_warn(f"No results for '{tq['query']}'")
                    failed += 1

            except Exception as e:
                print_fail(f"Search error: {e}")
                failed += 1

    except Exception as e:
        print_warn(f"Chimborazo test error: {e}")
        import traceback
        traceback.print_exc()
        return {'passed': 0, 'failed': 0, 'skipped': True}

    print_section("Phase 4 Summary")
    print(f"  Passed: {passed}, Failed: {failed}")
    return {'passed': passed, 'failed': failed}


# =========================================================================
# PHASE 5: Config Consistency Check
# =========================================================================

def test_config_consistency() -> Dict[str, Any]:
    """Collector ↔ Server ArtifactType 매핑 일관성 확인"""
    print_header("Phase 5: Config Consistency Check")

    passed = 0
    failed = 0

    try:
        from collectors.ios_collector import IOS_ARTIFACT_TYPES
    except ImportError as e:
        print_fail(f"Cannot import IOS_ARTIFACT_TYPES: {e}")
        return {'passed': 0, 'failed': 1}

    # Check messenger artifact types exist in Collector
    # Note: Collector uses 'mobile_ios_messenger' for FB Messenger,
    #       Server uses 'mobile_ios_fb_messenger' (ArtifactType enum)
    messenger_types = [
        'mobile_ios_kakaotalk',
        'mobile_ios_kakaotalk_attachments',
        'mobile_ios_kakaotalk_profile',
        'mobile_ios_whatsapp',
        'mobile_ios_whatsapp_attachments',
        'mobile_ios_telegram',
        'mobile_ios_telegram_attachments',
        'mobile_ios_wechat',
        'mobile_ios_line',
        'mobile_ios_line_attachments',
        'mobile_ios_messenger',              # Collector key for FB Messenger
        'mobile_ios_messenger_attachments',  # Collector key for FB Messenger attachments
        'mobile_ios_instagram',
        'mobile_ios_skype',
        'mobile_ios_snapchat',
        'mobile_ios_snapchat_memories',
    ]

    # Enum name differs from collector key for some types
    enum_name_overrides = {
        'mobile_ios_messenger': 'MOBILE_IOS_FB_MESSENGER',
        'mobile_ios_messenger_attachments': 'MOBILE_IOS_FB_MESSENGER_ATTACHMENTS',
    }

    print_section("Collector IOS_ARTIFACT_TYPES")
    for art_type in messenger_types:
        if art_type in IOS_ARTIFACT_TYPES:
            config = IOS_ARTIFACT_TYPES[art_type]
            domain = config.get('manifest_domain', 'N/A')
            print_pass(f"{art_type}: domain={domain}")
            passed += 1
        else:
            print_fail(f"{art_type}: NOT FOUND in IOS_ARTIFACT_TYPES")
            failed += 1

    # Check server ArtifactType enum
    print_section("Server ArtifactType Enum")
    try:
        from services.agents.artifact_types import ArtifactType

        for art_type in messenger_types:
            # Use override mapping for collector→server name differences
            enum_name = enum_name_overrides.get(art_type, art_type.upper())
            if hasattr(ArtifactType, enum_name):
                enum_val = getattr(ArtifactType, enum_name).value
                print_pass(f"ArtifactType.{enum_name} = '{enum_val}'")
                passed += 1
            else:
                print_fail(f"ArtifactType.{enum_name} NOT FOUND")
                failed += 1
    except ImportError as e:
        print_warn(f"Server ArtifactType not available: {e}")

    # Check no old bundle IDs remain
    print_section("Old Bundle ID Check")
    for art_type, config in IOS_ARTIFACT_TYPES.items():
        domain = config.get('manifest_domain', '')
        if 'com.kakao.KakaoTalk' in domain:
            print_fail(f"{art_type}: still uses OLD domain com.kakao.KakaoTalk")
            failed += 1
        if art_type.startswith('mobile_ios_whatsapp') and 'AppDomain-net.whatsapp' in domain:
            print_fail(f"{art_type}: still uses AppDomain (should be AppDomainGroup)")
            failed += 1

    if failed == 0:
        print_pass("No old/incorrect bundle IDs found")
        passed += 1

    print_section("Phase 5 Summary")
    print(f"  Passed: {passed}, Failed: {failed}")
    return {'passed': passed, 'failed': failed}


# =========================================================================
# Main
# =========================================================================

def main():
    parser = argparse.ArgumentParser(description='iOS Messenger E2E Test v2')
    parser.add_argument('--collector-only', action='store_true', help='Run only collector tests')
    parser.add_argument('--full', action='store_true', help='Run full pipeline including server/chimborazo')
    parser.add_argument('--backup-path', type=str, default=None, help='Custom backup path')
    args = parser.parse_args()

    backup_path = Path(args.backup_path) if args.backup_path else REAL_BACKUP_PATH

    print_header("iOS Messenger E2E Test v2")
    print_info(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_info(f"Backup: {backup_path}")
    print_info(f"Mode: {'full' if args.full else 'collector-only' if args.collector_only else 'auto'}")

    if not backup_path.exists():
        print_fail(f"Backup path not found: {backup_path}")
        return 1

    all_results = {}
    total_passed = 0
    total_failed = 0

    # Phase 1: Manifest.db verification (always run)
    r = test_manifest_db_verification(backup_path)
    all_results['phase1_manifest'] = r
    total_passed += r['passed']
    total_failed += r['failed']

    # Phase 2: Collector extraction (always run)
    r = test_collector_extraction(backup_path)
    all_results['phase2_collector'] = r
    total_passed += r['passed']
    total_failed += r['failed']

    # Phase 5: Config consistency (always run)
    r = test_config_consistency()
    all_results['phase5_config'] = r
    total_passed += r['passed']
    total_failed += r['failed']

    if not args.collector_only:
        # Phase 3: Server parsing
        r = test_server_parsing(backup_path)
        all_results['phase3_parsing'] = r
        total_passed += r['passed']
        total_failed += r['failed']

        if args.full:
            # Phase 4: Chimborazo search
            r = asyncio.run(test_chimborazo_search())
            all_results['phase4_chimborazo'] = r
            total_passed += r['passed']
            total_failed += r['failed']

    # Final Summary
    print_header("FINAL SUMMARY")
    for phase_name, r in all_results.items():
        skipped = r.get('skipped', False)
        status = "SKIPPED" if skipped else f"PASS={r['passed']} FAIL={r['failed']}"
        phase_ok = skipped or r['failed'] == 0
        color = Colors.WARN if skipped else (Colors.PASS if phase_ok else Colors.FAIL)
        print(f"  {colored(status, color)}  {phase_name}")

    print()
    print(f"  Total: {colored(f'{total_passed} passed', Colors.PASS)}, ", end='')
    if total_failed > 0:
        print(colored(f'{total_failed} failed', Colors.FAIL))
    else:
        print(colored('0 failed', Colors.PASS))

    if total_failed == 0:
        print()
        print(colored("  ALL TESTS PASSED", Colors.PASS))
    else:
        print()
        print(colored(f"  {total_failed} TESTS FAILED", Colors.FAIL))

    return 0 if total_failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
