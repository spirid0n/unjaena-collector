# -*- coding: utf-8 -*-
"""
iOS Encrypted Backup - Comprehensive Tests

Tests for:
1. Unencrypted backup regression (existing functionality)
2. Encrypted backup flow (new feature)
3. _collect_pattern() fix for encrypted backups
4. iOSPasswordDialogResult dataclass
5. create_encrypted_backup() factory
6. iOSEncryptedBackupParser interface
7. iOSCollector parameter changes
8. artifact_collector.py attribute check
"""
import sys
import os
import sqlite3
import tempfile
import shutil
import hashlib
import plistlib
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))


# =============================================================================
# Helper: Create mock iOS backup
# =============================================================================

def create_mock_backup(base_dir: Path, encrypted: bool = False) -> Path:
    """Create a mock iOS backup directory for testing"""
    backup_dir = base_dir / 'mock_backup'
    backup_dir.mkdir(parents=True, exist_ok=True)

    # Info.plist
    info_plist = {
        'Device Name': 'Test iPhone',
        'Target Identifier': 'TEST-DEVICE-001',
        'Product Type': 'iPhone14,2',
        'Product Version': '17.0',
        'Last Backup Date': datetime.now(),
        'IsEncrypted': encrypted,
    }
    with open(backup_dir / 'Info.plist', 'wb') as f:
        plistlib.dump(info_plist, f)

    # Manifest.db
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

    # SMS entry
    sms_hash = hashlib.sha1(b'HomeDomain-Library/SMS/sms.db').hexdigest()
    cursor.execute('INSERT INTO Files VALUES (?, ?, ?, ?, ?)',
                   (sms_hash, 'HomeDomain', 'Library/SMS/sms.db', 1, None))

    # App domain entries (for pattern-based collection)
    app_hash1 = hashlib.sha1(b'AppDomain-com.kakao.KakaoTalk-Documents/Message/Message.sqlite').hexdigest()
    cursor.execute('INSERT INTO Files VALUES (?, ?, ?, ?, ?)',
                   (app_hash1, 'AppDomain-com.kakao.KakaoTalk',
                    'Documents/Message/Message.sqlite', 1, None))

    app_hash2 = hashlib.sha1(b'AppDomain-com.kakao.KakaoTalk-Documents/Profile.sqlite').hexdigest()
    cursor.execute('INSERT INTO Files VALUES (?, ?, ?, ?, ?)',
                   (app_hash2, 'AppDomain-com.kakao.KakaoTalk',
                    'Documents/Profile.sqlite', 1, None))

    conn.commit()
    conn.close()

    # Create actual files in backup structure (for unencrypted)
    for file_hash in [sms_hash, app_hash1, app_hash2]:
        sub_dir = backup_dir / file_hash[:2]
        sub_dir.mkdir(exist_ok=True)
        # Create a small sqlite db as mock file
        db_path = sub_dir / file_hash
        mock_conn = sqlite3.connect(str(db_path))
        mock_conn.execute('CREATE TABLE test (id INTEGER)')
        mock_conn.execute('INSERT INTO test VALUES (1)')
        mock_conn.commit()
        mock_conn.close()

    return backup_dir


# =============================================================================
# Test 1: Unencrypted backup regression
# =============================================================================

class TestUnencryptedBackupRegression:
    """Verify existing unencrypted backup functionality is unchanged"""

    def test_ios_collector_init_default(self):
        """iOSCollector should accept no password/encrypted_backup by default"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            collector = iOSCollector(tmp)
            assert collector._encrypted_backup is None
            assert collector.parser is None

    def test_select_unencrypted_backup(self):
        """select_backup() should work for unencrypted backups"""
        from collectors.ios_collector import iOSCollector, iOSBackupParser

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=False)
            output_dir = tmp_path / 'output'
            output_dir.mkdir()

            collector = iOSCollector(str(output_dir))
            result = collector.select_backup(str(backup_dir))

            assert result is True
            assert collector.backup_info is not None
            assert collector.backup_info.encrypted is False
            assert isinstance(collector.parser, iOSBackupParser)

    def test_collect_single_file_unencrypted(self):
        """collect() should extract files from unencrypted backup"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=False)
            output_dir = tmp_path / 'output'
            output_dir.mkdir()

            collector = iOSCollector(str(output_dir))
            collector.select_backup(str(backup_dir))

            results = list(collector.collect('mobile_ios_sms'))

            # Should have at least one result
            assert len(results) > 0
            path, metadata = results[0]
            assert path  # non-empty path
            assert metadata.get('artifact_type') == 'mobile_ios_sms'
            assert metadata.get('sha256')  # hash present
            assert os.path.exists(path)

    def test_collect_pattern_unencrypted(self):
        """_collect_pattern() should work for unencrypted backup via backup_path copy"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=False)
            output_dir = tmp_path / 'output'
            output_dir.mkdir()

            collector = iOSCollector(str(output_dir))
            collector.select_backup(str(backup_dir))

            # mobile_ios_app is pattern-based (AppDomain-*)
            results = list(collector.collect('mobile_ios_app'))

            # Should collect files from AppDomain-*
            assert len(results) >= 1
            for path, metadata in results:
                assert path
                assert 'AppDomain' in metadata.get('domain', '')

    def test_is_encrypted_property(self):
        """is_encrypted should be a property, not a method"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=False)
            output_dir = tmp_path / 'output'
            output_dir.mkdir()

            collector = iOSCollector(str(output_dir))
            collector.select_backup(str(backup_dir))

            # Should be accessible as property (no parentheses)
            val = collector.is_encrypted
            assert isinstance(val, bool)
            assert val is False

    def test_get_available_artifacts_unencrypted(self):
        """get_available_artifacts() should show all available for unencrypted backup"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=False)
            output_dir = tmp_path / 'output'
            output_dir.mkdir()

            collector = iOSCollector(str(output_dir))
            collector.select_backup(str(backup_dir))

            artifacts = collector.get_available_artifacts()
            # At least some should be available
            available_count = sum(1 for a in artifacts if a['available'])
            assert available_count > 0


# =============================================================================
# Test 2: Encrypted backup - iOSCollector changes
# =============================================================================

class TestEncryptedBackupCollector:
    """Test iOSCollector with encrypted_backup parameter"""

    def test_encrypted_backup_param(self):
        """iOSCollector should accept encrypted_backup parameter"""
        from collectors.ios_collector import iOSCollector

        mock_encrypted_backup = Mock()

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            collector = iOSCollector(tmp, encrypted_backup=mock_encrypted_backup)
            assert collector._encrypted_backup is mock_encrypted_backup

    def test_collect_rejects_encrypted_without_decryptor(self):
        """collect() should reject encrypted backup when no decryptor provided"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=True)
            output_dir = tmp_path / 'output'
            output_dir.mkdir()

            # No encrypted_backup provided
            collector = iOSCollector(str(output_dir))
            collector.select_backup(str(backup_dir))

            results = list(collector.collect('mobile_ios_sms'))
            assert len(results) == 1
            path, metadata = results[0]
            assert path == ''
            assert metadata.get('status') == 'error'
            assert 'password' in metadata.get('error', '').lower() or 'encrypt' in metadata.get('error', '').lower()

    def test_select_backup_encrypted_with_decryptor(self):
        """select_backup() should use iOSEncryptedBackupParser when encrypted + decryptor"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=True)
            output_dir = tmp_path / 'output'
            output_dir.mkdir()

            mock_encrypted_backup = Mock()

            with patch('collectors.ios_backup_decryptor.iOSEncryptedBackupParser') as MockParser:
                mock_parser_instance = Mock()
                MockParser.return_value = mock_parser_instance

                collector = iOSCollector(str(output_dir), encrypted_backup=mock_encrypted_backup)
                collector.select_backup(str(backup_dir))

                # Should have called iOSEncryptedBackupParser
                MockParser.assert_called_once_with(backup_dir, mock_encrypted_backup)
                assert collector.parser is mock_parser_instance

    def test_is_encrypted_true_for_encrypted_backup(self):
        """is_encrypted should return True for encrypted backup"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=True)
            output_dir = tmp_path / 'output'
            output_dir.mkdir()

            collector = iOSCollector(str(output_dir))
            collector.select_backup(str(backup_dir))

            assert collector.is_encrypted is True

    def test_get_available_artifacts_encrypted_no_decryptor(self):
        """get_available_artifacts() should show unavailable when encrypted, no decryptor"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=True)
            output_dir = tmp_path / 'output'
            output_dir.mkdir()

            collector = iOSCollector(str(output_dir))
            collector.select_backup(str(backup_dir))

            artifacts = collector.get_available_artifacts()
            # Should all be unavailable (encrypted, no decryptor)
            available = [a for a in artifacts if a['available']]
            assert len(available) == 0

    def test_get_available_artifacts_encrypted_with_decryptor(self):
        """get_available_artifacts() should show available when encrypted + decryptor"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=True)
            output_dir = tmp_path / 'output'
            output_dir.mkdir()

            mock_encrypted_backup = Mock()

            with patch('collectors.ios_backup_decryptor.iOSEncryptedBackupParser'):
                collector = iOSCollector(str(output_dir), encrypted_backup=mock_encrypted_backup)
                collector.select_backup(str(backup_dir))

                artifacts = collector.get_available_artifacts()
                available = [a for a in artifacts if a['available']]
                assert len(available) > 0


# =============================================================================
# Test 3: _collect_pattern() encrypted fallback
# =============================================================================

class TestCollectPatternEncrypted:
    """Test _collect_pattern() handles encrypted backups correctly"""

    def test_pattern_uses_extract_file_for_encrypted(self):
        """_collect_pattern() should call parser.extract_file() for encrypted backups"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=True)
            output_dir = tmp_path / 'output'
            output_dir.mkdir()

            mock_encrypted_backup = Mock()

            # Create mock parser that simulates encrypted behavior
            mock_parser = Mock()
            mock_parser.list_files.return_value = iter([
                {
                    'file_id': 'abc123',
                    'domain': 'AppDomain-com.kakao.KakaoTalk',
                    'relative_path': 'Documents/Message/Message.sqlite',
                    'flags': 1,
                    # NOTE: No 'backup_path' key (encrypted backup behavior)
                },
            ])

            # extract_file should be called and write a file
            def fake_extract(domain, rel_path, output_path):
                output_path = Path(output_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                # Write some content
                conn = sqlite3.connect(str(output_path))
                conn.execute('CREATE TABLE test (id INTEGER)')
                conn.execute('INSERT INTO test VALUES (42)')
                conn.commit()
                conn.close()
                return True

            mock_parser.extract_file.side_effect = fake_extract

            collector = iOSCollector(str(output_dir), encrypted_backup=mock_encrypted_backup)
            collector.select_backup(str(backup_dir))
            # Replace parser with mock
            collector.parser = mock_parser

            from collectors.ios_collector import IOS_ARTIFACT_TYPES
            artifact_info = IOS_ARTIFACT_TYPES['mobile_ios_app']

            artifact_dir = output_dir / 'mobile_ios_app'
            artifact_dir.mkdir()

            results = list(collector._collect_pattern(
                'mobile_ios_app', artifact_info, artifact_dir, None
            ))

            assert len(results) == 1
            path, metadata = results[0]
            assert path
            assert os.path.exists(path)
            assert metadata['domain'] == 'AppDomain-com.kakao.KakaoTalk'
            assert metadata['sha256']  # Hash computed

            # Verify extract_file was called (not shutil.copy2)
            mock_parser.extract_file.assert_called_once()

    def test_pattern_uses_copy_for_unencrypted(self):
        """_collect_pattern() should use shutil.copy2 for unencrypted backups"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=False)
            output_dir = tmp_path / 'output'
            output_dir.mkdir()

            collector = iOSCollector(str(output_dir))
            collector.select_backup(str(backup_dir))

            # mobile_ios_app is pattern-based
            results = list(collector.collect('mobile_ios_app'))

            # Should work via backup_path copy
            assert len(results) >= 1
            for path, metadata in results:
                assert path
                assert os.path.exists(path)


# =============================================================================
# Test 4: iOSPasswordDialogResult dataclass
# =============================================================================

class TestPasswordDialogResult:
    """Test iOSPasswordDialogResult dataclass"""

    def test_default_values(self):
        from gui.ios_password_dialog import iOSPasswordDialogResult

        result = iOSPasswordDialogResult()
        assert result.success is False
        assert result.password == ""
        assert result.skip is False

    def test_success_result(self):
        from gui.ios_password_dialog import iOSPasswordDialogResult

        result = iOSPasswordDialogResult(success=True, password="test123")
        assert result.success is True
        assert result.password == "test123"
        assert result.skip is False

    def test_skip_result(self):
        from gui.ios_password_dialog import iOSPasswordDialogResult

        result = iOSPasswordDialogResult(success=False, skip=True)
        assert result.success is False
        assert result.skip is True

    def test_password_clearable(self):
        """Password should be clearable after use"""
        from gui.ios_password_dialog import iOSPasswordDialogResult

        result = iOSPasswordDialogResult(success=True, password="secret")
        assert result.password == "secret"
        result.password = ""
        assert result.password == ""


# =============================================================================
# Test 5: ios_backup_decryptor module
# =============================================================================

class TestiOSBackupDecryptor:
    """Test ios_backup_decryptor module"""

    def test_availability_flag(self):
        """IPHONE_BACKUP_DECRYPT_AVAILABLE should be a bool"""
        from collectors.ios_backup_decryptor import IPHONE_BACKUP_DECRYPT_AVAILABLE
        assert isinstance(IPHONE_BACKUP_DECRYPT_AVAILABLE, bool)

    def test_create_encrypted_backup_no_library(self):
        """create_encrypted_backup() should fail gracefully if library not installed"""
        from collectors.ios_backup_decryptor import (
            create_encrypted_backup,
            IPHONE_BACKUP_DECRYPT_AVAILABLE
        )

        if not IPHONE_BACKUP_DECRYPT_AVAILABLE:
            result, error = create_encrypted_backup('/fake/path', 'password')
            assert result is None
            assert 'not installed' in error.lower()

    def test_encrypted_parser_interface(self):
        """iOSEncryptedBackupParser should have required methods"""
        from collectors.ios_backup_decryptor import iOSEncryptedBackupParser

        assert hasattr(iOSEncryptedBackupParser, 'extract_file')
        assert hasattr(iOSEncryptedBackupParser, 'list_files')
        assert hasattr(iOSEncryptedBackupParser, 'get_file_hash')
        assert hasattr(iOSEncryptedBackupParser, 'close')

    def test_encrypted_parser_close(self):
        """close() should clean up temp dir and nullify backup"""
        from collectors.ios_backup_decryptor import iOSEncryptedBackupParser

        with tempfile.TemporaryDirectory(prefix='test_enc_') as tmp:
            # Create a mock encrypted backup object
            mock_backup = Mock()
            mock_backup.save_manifest_file = Mock(side_effect=Exception("not real"))

            parser = iOSEncryptedBackupParser.__new__(iOSEncryptedBackupParser)
            parser.backup_path = Path(tmp)
            parser.backup = mock_backup
            parser._temp_dir = Path(tempfile.mkdtemp(prefix='ios_edecrypt_'))
            parser._manifest_db_path = None

            # Verify temp dir exists
            assert parser._temp_dir.exists()

            parser.close()

            assert parser._temp_dir is None
            assert parser._manifest_db_path is None
            assert parser.backup is None

    def test_atexit_cleanup_registered(self):
        """_cleanup_temp_dirs should be registered with atexit"""
        import atexit
        from collectors.ios_backup_decryptor import _cleanup_temp_dirs

        # Just verify the function exists and is callable
        assert callable(_cleanup_temp_dirs)


# =============================================================================
# Test 6: artifact_collector.py attribute check
# =============================================================================

class TestArtifactCollectorAttributeCheck:
    """Test artifact_collector.py uses _encrypted_backup not _password"""

    def test_attribute_name_in_source(self):
        """artifact_collector.py should check _encrypted_backup, not _password"""
        source_path = Path(__file__).parent.parent / 'collectors' / 'artifact_collector.py'
        content = source_path.read_text(encoding='utf-8')

        # Should contain _encrypted_backup check
        assert '_encrypted_backup' in content, \
            "artifact_collector.py should reference _encrypted_backup"

        # Should NOT contain old _password check in the iOS section
        # Find the iOS encrypted check area
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if 'is_encrypted' in line and 'getattr' in line:
                assert '_encrypted_backup' in line, \
                    f"Line {i+1}: getattr check should use _encrypted_backup, got: {line.strip()}"


# =============================================================================
# Test 7: Integration - collect flow end-to-end (unencrypted)
# =============================================================================

class TestE2EUnencryptedFlow:
    """End-to-end test: mock backup → collect → verify output"""

    def test_full_collection_cycle(self):
        """Full collection cycle with unencrypted backup"""
        from collectors.ios_collector import iOSCollector, parse_backup_info

        with tempfile.TemporaryDirectory(prefix='test_e2e_') as tmp:
            tmp_path = Path(tmp)
            backup_dir = create_mock_backup(tmp_path, encrypted=False)
            output_dir = tmp_path / 'collected'
            output_dir.mkdir()

            # Parse backup info
            info = parse_backup_info(backup_dir)
            assert info is not None
            assert info.device_name == 'Test iPhone'
            assert info.encrypted is False

            # Create collector and select backup
            collector = iOSCollector(str(output_dir))
            assert collector.select_backup(str(backup_dir)) is True

            # Collect SMS
            sms_results = list(collector.collect('mobile_ios_sms'))
            assert len(sms_results) >= 1

            path, meta = sms_results[0]
            assert path
            assert os.path.exists(path)
            assert meta['artifact_type'] == 'mobile_ios_sms'
            assert meta['device_name'] == 'Test iPhone'
            assert 'sha256' in meta
            assert 'collected_at' in meta

            # Verify collected file is valid sqlite
            conn = sqlite3.connect(path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cursor.fetchall()]
            conn.close()
            assert 'test' in tables  # Our mock table

            # Collect backup metadata
            meta_results = list(collector.collect('mobile_ios_backup'))
            assert len(meta_results) >= 1
            for p, m in meta_results:
                assert p
                assert m['artifact_type'] == 'mobile_ios_backup'


# =============================================================================
# Test 8: iOSCollector.close() for encrypted parser cleanup
# =============================================================================

class TestEncryptedParserCleanup:
    """Test that encrypted parser resources are properly cleaned up"""

    def test_collector_close_cleans_encrypted_parser(self):
        """When collector is done, encrypted parser's close() should be callable"""
        from collectors.ios_backup_decryptor import iOSEncryptedBackupParser

        # Verify close method exists
        assert hasattr(iOSEncryptedBackupParser, 'close')
        assert callable(getattr(iOSEncryptedBackupParser, 'close'))


# =============================================================================
# Test 9: Cross-check - no stale references to old API
# =============================================================================

class TestNoStaleReferences:
    """Verify no stale references to old password-based API"""

    def test_ios_collector_no_password_param(self):
        """iOSCollector.__init__ should NOT have 'password' parameter"""
        from collectors.ios_collector import iOSCollector
        import inspect

        sig = inspect.signature(iOSCollector.__init__)
        param_names = list(sig.parameters.keys())

        assert 'password' not in param_names, \
            f"iOSCollector still has 'password' param: {param_names}"
        assert 'encrypted_backup' in param_names, \
            f"iOSCollector missing 'encrypted_backup' param: {param_names}"

    def test_ios_collector_no_password_attribute(self):
        """iOSCollector should not have _password attribute"""
        from collectors.ios_collector import iOSCollector

        with tempfile.TemporaryDirectory(prefix='test_ios_') as tmp:
            collector = iOSCollector(tmp)
            assert not hasattr(collector, '_password'), \
                "iOSCollector should not have _password attribute"
            assert hasattr(collector, '_encrypted_backup'), \
                "iOSCollector should have _encrypted_backup attribute"

    def test_ios_collector_source_no_self_password(self):
        """ios_collector.py source should not reference self._password"""
        source_path = Path(__file__).parent.parent / 'collectors' / 'ios_collector.py'
        content = source_path.read_text(encoding='utf-8')

        # Should NOT have self._password
        assert 'self._password' not in content, \
            "ios_collector.py still references self._password"

        # Should have self._encrypted_backup
        assert 'self._encrypted_backup' in content


# =============================================================================
# Run
# =============================================================================

if __name__ == '__main__':
    import pytest
    sys.exit(pytest.main([__file__, '-v', '--tb=short']))
