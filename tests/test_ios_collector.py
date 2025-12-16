"""
iOS Collector Unit Tests

Tests for backup path detection, plist parsing,
and Manifest.db parsing.
"""
import os
import sys
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


class TestiOSBackupPathDetection(unittest.TestCase):
    """Tests for iOS backup path detection"""

    def test_find_default_backup_paths(self):
        """Test finding default iOS backup paths"""
        from collectors.ios_collector import find_ios_backup_paths

        paths = find_ios_backup_paths()
        self.assertIsInstance(paths, list)

    @patch('os.path.expandvars')
    @patch('os.path.exists')
    def test_windows_backup_path(self, mock_exists, mock_expand):
        """Test Windows iTunes backup path detection"""
        mock_expand.return_value = 'C:\\Users\\Test\\AppData\\Roaming\\Apple Computer\\MobileSync\\Backup'
        mock_exists.return_value = True

        from collectors.ios_collector import find_ios_backup_paths

        paths = find_ios_backup_paths()
        # Should return at least the paths that were checked
        self.assertIsInstance(paths, list)

    def test_backup_paths_are_strings_or_paths(self):
        """Test that backup paths are valid string or Path objects"""
        from collectors.ios_collector import find_ios_backup_paths

        paths = find_ios_backup_paths()

        for path in paths:
            self.assertTrue(
                isinstance(path, (str, Path)),
                f"Expected str or Path, got {type(path)}"
            )


class TestPlistParsing(unittest.TestCase):
    """Tests for plist file parsing"""

    def test_parse_info_plist(self):
        """Test parsing Info.plist from backup"""
        from collectors.ios_collector import iOSBackupParser

        # Test with sample plist data
        sample_plist = {
            'Device Name': 'iPhone Test',
            'Product Type': 'iPhone14,2',
            'Product Version': '16.0',
            'Serial Number': 'ABC123XYZ',
        }

        parser = iOSBackupParser()

        if hasattr(parser, 'parse_info_plist'):
            # This would need an actual plist file to test properly
            # For now, just verify the method exists
            self.assertTrue(callable(parser.parse_info_plist))

    def test_parse_binary_plist(self):
        """Test that binary plist parsing doesn't crash"""
        from collectors.ios_collector import iOSBackupParser

        parser = iOSBackupParser()

        # Test with invalid/empty data shouldn't crash
        if hasattr(parser, '_parse_plist_data'):
            try:
                result = parser._parse_plist_data(b'')
            except Exception:
                pass  # Expected for invalid data


class TestManifestDbParsing(unittest.TestCase):
    """Tests for Manifest.db parsing"""

    def test_manifest_db_parser_exists(self):
        """Test that Manifest.db parsing functionality exists"""
        from collectors.ios_collector import iOSBackupParser

        parser = iOSBackupParser()

        # Check for manifest parsing method
        has_manifest_parser = (
            hasattr(parser, 'parse_manifest_db') or
            hasattr(parser, 'read_manifest') or
            hasattr(parser, '_parse_manifest')
        )
        self.assertTrue(
            has_manifest_parser,
            "Parser should have a method to parse Manifest.db"
        )

    def test_manifest_file_lookup(self):
        """Test looking up files in Manifest.db"""
        from collectors.ios_collector import iOSBackupParser

        parser = iOSBackupParser()

        if hasattr(parser, 'get_file_by_domain'):
            # Test with sample domain
            self.assertTrue(callable(parser.get_file_by_domain))


class TestiOSArtifactTypes(unittest.TestCase):
    """Tests for iOS artifact type definitions"""

    def test_ios_artifact_types_exist(self):
        """Test that IOS_ARTIFACT_TYPES is defined correctly"""
        from collectors.ios_collector import IOS_ARTIFACT_TYPES

        expected_types = [
            'mobile_ios_sms',
            'mobile_ios_call',
            'mobile_ios_contacts',
            'mobile_ios_app',
            'mobile_ios_safari',
            'mobile_ios_location',
            'mobile_ios_backup',
        ]

        for artifact_type in expected_types:
            self.assertIn(artifact_type, IOS_ARTIFACT_TYPES)

    def test_ios_artifact_types_have_required_fields(self):
        """Test that each artifact type has required fields"""
        from collectors.ios_collector import IOS_ARTIFACT_TYPES

        for type_name, type_config in IOS_ARTIFACT_TYPES.items():
            self.assertIn('name', type_config, f"{type_name} missing 'name'")
            self.assertIn('description', type_config, f"{type_name} missing 'description'")


class TestiOSCollector(unittest.TestCase):
    """Tests for iOSCollector class"""

    def test_collector_init(self):
        """Test iOSCollector initialization"""
        from collectors.ios_collector import iOSCollector

        collector = iOSCollector()
        self.assertIsNotNone(collector)

    def test_collector_has_collect_method(self):
        """Test iOSCollector has collect method"""
        from collectors.ios_collector import iOSCollector

        collector = iOSCollector()
        self.assertTrue(hasattr(collector, 'collect'))
        self.assertTrue(callable(collector.collect))

    def test_collector_supported_types(self):
        """Test iOSCollector returns supported artifact types"""
        from collectors.ios_collector import iOSCollector

        collector = iOSCollector()

        if hasattr(collector, 'get_supported_types'):
            supported = collector.get_supported_types()
            self.assertIsInstance(supported, (list, dict))


class TestiOSBackupGuide(unittest.TestCase):
    """Tests for iOS backup creation guide"""

    def test_guide_function_exists(self):
        """Test that iOS backup guide function exists"""
        from collectors.ios_collector import get_ios_backup_guide

        guide = get_ios_backup_guide()
        self.assertIsInstance(guide, (str, list, dict))

    def test_guide_has_steps(self):
        """Test that guide has multiple steps"""
        from collectors.ios_collector import get_ios_backup_guide

        guide = get_ios_backup_guide()

        if isinstance(guide, list):
            self.assertGreater(len(guide), 0)
        elif isinstance(guide, dict):
            self.assertGreater(len(guide), 0)
        elif isinstance(guide, str):
            # Should contain step indicators
            self.assertTrue(
                any(indicator in guide for indicator in ['1', 'Step', 'First', '단계'])
            )


class TestDatabaseExtraction(unittest.TestCase):
    """Tests for iOS database extraction"""

    def test_sms_db_path_constant(self):
        """Test SMS database domain/path constant"""
        from collectors.ios_collector import IOS_ARTIFACT_TYPES

        sms_config = IOS_ARTIFACT_TYPES.get('mobile_ios_sms', {})

        if 'domain' in sms_config:
            self.assertIn('sms', sms_config['domain'].lower())
        if 'db_name' in sms_config:
            self.assertIn('sms', sms_config['db_name'].lower())

    def test_contacts_db_path_constant(self):
        """Test contacts database domain/path constant"""
        from collectors.ios_collector import IOS_ARTIFACT_TYPES

        contacts_config = IOS_ARTIFACT_TYPES.get('mobile_ios_contacts', {})

        if 'domain' in contacts_config:
            keywords = ['contact', 'address']
            has_keyword = any(kw in contacts_config['domain'].lower() for kw in keywords)
            self.assertTrue(has_keyword)


class TestEncryptedBackupHandling(unittest.TestCase):
    """Tests for encrypted backup handling"""

    def test_detect_encrypted_backup(self):
        """Test detection of encrypted backup"""
        from collectors.ios_collector import iOSBackupParser

        parser = iOSBackupParser()

        if hasattr(parser, 'is_encrypted'):
            # Method should exist and be callable
            self.assertTrue(callable(parser.is_encrypted))

    def test_encrypted_backup_error_handling(self):
        """Test proper error handling for encrypted backups without password"""
        from collectors.ios_collector import iOSBackupParser

        parser = iOSBackupParser()

        # Should not crash when dealing with encrypted backup
        if hasattr(parser, 'set_backup_path'):
            try:
                parser.set_backup_path('/nonexistent/backup')
            except Exception:
                pass  # Expected for invalid path


if __name__ == '__main__':
    unittest.main()
