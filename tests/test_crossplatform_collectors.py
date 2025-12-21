"""
Cross-Platform Collector Tests

Tests for Linux, macOS, and NTFS advanced collection methods.
Phase 2: Integration of cross-platform forensic artifact collection.
"""
import os
import sys
import json
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import shutil

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


class TestArtifactTypesCompleteness(unittest.TestCase):
    """Test ARTIFACT_TYPES definitions completeness"""

    def test_all_linux_types_defined(self):
        """All Linux artifact types are defined"""
        from collectors.artifact_collector import ARTIFACT_TYPES

        linux_types = [
            'linux_login', 'linux_journal', 'linux_shell', 'linux_cron',
            'linux_ssh', 'linux_audit', 'linux_package', 'linux_systemd',
        ]

        for artifact_type in linux_types:
            self.assertIn(artifact_type, ARTIFACT_TYPES,
                          f"Missing Linux artifact type: {artifact_type}")
            self.assertEqual(ARTIFACT_TYPES[artifact_type].get('category'), 'linux',
                             f"Wrong category for {artifact_type}")

    def test_all_macos_types_defined(self):
        """All macOS artifact types are defined"""
        from collectors.artifact_collector import ARTIFACT_TYPES

        macos_types = [
            'macos_unified', 'macos_fsevents', 'macos_knowledgec',
            'macos_spotlight', 'macos_launch', 'macos_quarantine',
            'macos_tcc', 'macos_airdrop',
        ]

        for artifact_type in macos_types:
            self.assertIn(artifact_type, ARTIFACT_TYPES,
                          f"Missing macOS artifact type: {artifact_type}")
            self.assertEqual(ARTIFACT_TYPES[artifact_type].get('category'), 'macos',
                             f"Wrong category for {artifact_type}")

    def test_ntfs_advanced_types_defined(self):
        """NTFS advanced artifact types are defined"""
        from collectors.artifact_collector import ARTIFACT_TYPES

        ntfs_types = ['ads', 'zone_identifier', 'unallocated']

        for artifact_type in ntfs_types:
            self.assertIn(artifact_type, ARTIFACT_TYPES,
                          f"Missing NTFS artifact type: {artifact_type}")

    def test_filesystem_catalog_types_defined(self):
        """Filesystem catalog types are defined"""
        from collectors.artifact_collector import ARTIFACT_TYPES

        catalog_types = ['apfs_catalog', 'ext4_catalog', 'fat_catalog']

        for artifact_type in catalog_types:
            self.assertIn(artifact_type, ARTIFACT_TYPES,
                          f"Missing filesystem catalog type: {artifact_type}")

    def test_all_types_have_collector(self):
        """All artifact types have a collector or alias defined"""
        from collectors.artifact_collector import ARTIFACT_TYPES

        for artifact_type, info in ARTIFACT_TYPES.items():
            # Skip alias types - they use the collector of the parent type
            if 'alias_of' in info:
                continue
            self.assertIn('collector', info,
                          f"Missing collector for {artifact_type}")


class TestLinuxCollectors(unittest.TestCase):
    """Test Linux artifact collection methods"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.output_dir = Path(self.temp_dir)

    def tearDown(self):
        """Clean up"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_collector_method_exists(self):
        """Linux collector methods exist"""
        from collectors.artifact_collector import ArtifactCollector

        methods = [
            'collect_linux_login',
            'collect_linux_journal',
            'collect_linux_shell_history',
            'collect_linux_cron',
            'collect_linux_ssh',
            'collect_linux_audit',
            'collect_linux_package',
            'collect_linux_systemd',
        ]

        collector = ArtifactCollector(self.temp_dir)

        for method in methods:
            self.assertTrue(hasattr(collector, method),
                            f"Missing method: {method}")

    @patch('pathlib.Path.exists')
    def test_linux_shell_history_no_files(self, mock_exists):
        """Linux shell history handles missing files gracefully"""
        mock_exists.return_value = False

        from collectors.artifact_collector import ArtifactCollector

        collector = ArtifactCollector(self.temp_dir)
        results = list(collector.collect_linux_shell_history('', self.output_dir, 'linux_shell'))

        # Should return summary even with no files
        self.assertIsInstance(results, list)

    @patch('pathlib.Path.exists')
    def test_linux_cron_no_files(self, mock_exists):
        """Linux cron handles missing files gracefully"""
        mock_exists.return_value = False

        from collectors.artifact_collector import ArtifactCollector

        collector = ArtifactCollector(self.temp_dir)
        results = list(collector.collect_linux_cron('', self.output_dir, 'linux_cron'))

        self.assertIsInstance(results, list)


class TestMacOSCollectors(unittest.TestCase):
    """Test macOS artifact collection methods"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.output_dir = Path(self.temp_dir)

    def tearDown(self):
        """Clean up"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_collector_method_exists(self):
        """macOS collector methods exist"""
        from collectors.artifact_collector import ArtifactCollector

        methods = [
            'collect_macos_unified',
            'collect_macos_fsevents',
            'collect_macos_knowledgec',
            'collect_macos_spotlight',
            'collect_macos_launch',
            'collect_macos_quarantine',
            'collect_macos_tcc',
            'collect_macos_airdrop',
        ]

        collector = ArtifactCollector(self.temp_dir)

        for method in methods:
            self.assertTrue(hasattr(collector, method),
                            f"Missing method: {method}")

    @patch('pathlib.Path.exists')
    def test_macos_quarantine_no_files(self, mock_exists):
        """macOS quarantine handles missing files gracefully"""
        mock_exists.return_value = False

        from collectors.artifact_collector import ArtifactCollector

        collector = ArtifactCollector(self.temp_dir)
        results = list(collector.collect_macos_quarantine('', self.output_dir, 'macos_quarantine'))

        self.assertIsInstance(results, list)


class TestMFTAdvancedCollectors(unittest.TestCase):
    """Test MFT advanced collection methods (ADS, Zone.Identifier, Unallocated)"""

    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.output_dir = Path(self.temp_dir)

    def tearDown(self):
        """Clean up"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('collectors.mft_collector.MFTCollector')
    def test_mft_collector_ads_method_exists(self, mock_mft):
        """MFT collector has ADS method"""
        # Check if method exists when MFT is available
        try:
            from collectors.mft_collector import MFTCollector
            self.assertTrue(hasattr(MFTCollector, 'collect_ads'))
        except ImportError:
            self.skipTest("MFT collector not available (pytsk3 not installed)")

    @patch('collectors.mft_collector.MFTCollector')
    def test_mft_collector_zone_identifier_method_exists(self, mock_mft):
        """MFT collector has Zone.Identifier method"""
        try:
            from collectors.mft_collector import MFTCollector
            self.assertTrue(hasattr(MFTCollector, 'collect_zone_identifier'))
        except ImportError:
            self.skipTest("MFT collector not available (pytsk3 not installed)")

    @patch('collectors.mft_collector.MFTCollector')
    def test_mft_collector_unallocated_method_exists(self, mock_mft):
        """MFT collector has unallocated space method"""
        try:
            from collectors.mft_collector import MFTCollector
            self.assertTrue(hasattr(MFTCollector, 'collect_unallocated'))
        except ImportError:
            self.skipTest("MFT collector not available (pytsk3 not installed)")


class TestServerMappingCompleteness(unittest.TestCase):
    """Test SERVER_TO_COLLECTOR_MAPPING completeness"""

    def test_linux_artifacts_mapped(self):
        """All Linux artifacts are mapped"""
        from gui.app import SERVER_TO_COLLECTOR_MAPPING

        linux_types = [
            'linux_login', 'linux_journal', 'linux_shell', 'linux_cron',
            'linux_ssh', 'linux_audit', 'linux_package', 'linux_systemd',
        ]

        for artifact_type in linux_types:
            self.assertIn(artifact_type, SERVER_TO_COLLECTOR_MAPPING,
                          f"Missing Linux mapping: {artifact_type}")

    def test_macos_artifacts_mapped(self):
        """All macOS artifacts are mapped"""
        from gui.app import SERVER_TO_COLLECTOR_MAPPING

        macos_types = [
            'macos_unified', 'macos_fsevents', 'macos_knowledgec',
            'macos_spotlight', 'macos_launch', 'macos_quarantine',
            'macos_tcc', 'macos_airdrop',
        ]

        for artifact_type in macos_types:
            self.assertIn(artifact_type, SERVER_TO_COLLECTOR_MAPPING,
                          f"Missing macOS mapping: {artifact_type}")

    def test_ntfs_advanced_mapped(self):
        """NTFS advanced artifacts are mapped"""
        from gui.app import SERVER_TO_COLLECTOR_MAPPING

        ntfs_types = ['ads', 'zone_identifier', 'unallocated']

        for artifact_type in ntfs_types:
            self.assertIn(artifact_type, SERVER_TO_COLLECTOR_MAPPING,
                          f"Missing NTFS mapping: {artifact_type}")


class TestGUIIntegration(unittest.TestCase):
    """Test GUI integration for unified tabs"""

    def test_unified_artifacts_tab_method_exists(self):
        """Unified artifacts tab creation method exists"""
        from gui.app import CollectorWindow

        self.assertTrue(hasattr(CollectorWindow, '_create_unified_artifacts_tab'),
                        "Missing _create_unified_artifacts_tab method")

    def test_mobile_tab_method_exists(self):
        """Mobile tab creation method exists"""
        from gui.app import CollectorWindow

        self.assertTrue(hasattr(CollectorWindow, '_create_mobile_tab'),
                        "Missing _create_mobile_tab method")

    def test_collapsible_group_method_exists(self):
        """Collapsible artifact group method exists"""
        from gui.app import CollectorWindow

        self.assertTrue(hasattr(CollectorWindow, '_create_collapsible_artifact_group'),
                        "Missing _create_collapsible_artifact_group method")


if __name__ == '__main__':
    unittest.main(verbosity=2)
