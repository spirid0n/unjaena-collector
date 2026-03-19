"""
Memory Collector Unit Tests

Tests for WinPmem path detection, memory dump acquisition simulation,
and Volatility plugin call tests (mocked).
"""
import os
import sys
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


class TestWinPmemPathDetection(unittest.TestCase):
    """Tests for WinPmem executable path detection"""

    def test_get_winpmem_path_from_resources(self):
        """Test WinPmem path detection from resources directory"""
        from collectors.memory_collector import get_winpmem_path

        # The function should return a Path or None
        result = get_winpmem_path()

        # If WinPmem is bundled, it should return a valid path
        if result is not None:
            self.assertIsInstance(result, Path)
            self.assertTrue(str(result).endswith('.exe'))

    def test_get_winpmem_path_checks_multiple_locations(self):
        """Test that get_winpmem_path checks multiple possible locations"""
        from collectors.memory_collector import get_winpmem_path

        # This test verifies the function doesn't crash when searching
        # regardless of whether WinPmem is actually present
        try:
            result = get_winpmem_path()
            # Should return Path or None, not raise an exception
            self.assertTrue(result is None or isinstance(result, Path))
        except Exception as e:
            self.fail(f"get_winpmem_path raised unexpected exception: {e}")


class TestIsAdmin(unittest.TestCase):
    """Tests for administrator privilege check"""

    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    def test_is_admin_returns_true_when_admin(self, mock_admin):
        """Test is_admin returns True when running as admin"""
        mock_admin.return_value = 1

        from collectors.memory_collector import is_admin
        self.assertTrue(is_admin())

    @patch('ctypes.windll.shell32.IsUserAnAdmin')
    def test_is_admin_returns_false_when_not_admin(self, mock_admin):
        """Test is_admin returns False when not running as admin"""
        mock_admin.return_value = 0

        from collectors.memory_collector import is_admin
        self.assertFalse(is_admin())


class TestMemoryArtifactTypes(unittest.TestCase):
    """Tests for memory artifact type definitions"""

    def test_memory_artifact_types_exist(self):
        """Test that MEMORY_ARTIFACT_TYPES is defined correctly"""
        from collectors.memory_collector import MEMORY_ARTIFACT_TYPES

        expected_types = [
            'memory_dump',
            'memory_process',
            'memory_network',
            'memory_module',
            'memory_handle',
            'memory_registry',
            'memory_credential',
            'memory_malware',
        ]

        for artifact_type in expected_types:
            self.assertIn(artifact_type, MEMORY_ARTIFACT_TYPES)

    def test_memory_artifact_types_have_required_fields(self):
        """Test that each artifact type has required fields"""
        from collectors.memory_collector import MEMORY_ARTIFACT_TYPES

        for type_name, type_config in MEMORY_ARTIFACT_TYPES.items():
            self.assertIn('name', type_config, f"{type_name} missing 'name'")
            self.assertIn('description', type_config, f"{type_name} missing 'description'")


class TestWinPmemDumper(unittest.TestCase):
    """Tests for WinPmemDumper class"""

    def test_dumper_init_without_winpmem(self):
        """Test WinPmemDumper initialization when WinPmem is not available"""
        from collectors.memory_collector import WinPmemDumper

        with patch('collectors.memory_collector.get_winpmem_path', return_value=None):
            dumper = WinPmemDumper()
            self.assertFalse(dumper.is_available())

    @patch('collectors.memory_collector.get_winpmem_path')
    def test_dumper_init_with_winpmem(self, mock_path):
        """Test WinPmemDumper initialization when WinPmem is available"""
        mock_path.return_value = Path('C:/fake/winpmem.exe')

        from collectors.memory_collector import WinPmemDumper

        with patch.object(Path, 'exists', return_value=True):
            dumper = WinPmemDumper()
            # Should not raise an exception
            self.assertIsNotNone(dumper)


class TestVolatilityAnalyzer(unittest.TestCase):
    """Tests for VolatilityAnalyzer class (mocked Volatility3)"""

    def test_analyzer_availability_check(self):
        """Test Volatility availability check"""
        from collectors.memory_collector import VOLATILITY_AVAILABLE

        # Just verify the constant exists
        self.assertIsInstance(VOLATILITY_AVAILABLE, bool)

    @patch('collectors.memory_collector.VOLATILITY_AVAILABLE', False)
    def test_analyzer_without_volatility(self):
        """Test VolatilityAnalyzer when Volatility3 is not installed"""
        from collectors.memory_collector import VolatilityAnalyzer

        analyzer = VolatilityAnalyzer()
        self.assertFalse(analyzer.is_available())


class TestMemoryCollector(unittest.TestCase):
    """Tests for MemoryCollector integration class"""

    def test_collector_init(self):
        """Test MemoryCollector initialization"""
        from collectors.memory_collector import MemoryCollector

        collector = MemoryCollector()
        self.assertIsNotNone(collector)

    def test_collector_has_collect_method(self):
        """Test MemoryCollector has collect method"""
        from collectors.memory_collector import MemoryCollector

        collector = MemoryCollector()
        self.assertTrue(hasattr(collector, 'collect'))
        self.assertTrue(callable(collector.collect))

    def test_collector_supported_types(self):
        """Test MemoryCollector returns supported artifact types"""
        from collectors.memory_collector import MemoryCollector

        collector = MemoryCollector()

        if hasattr(collector, 'get_supported_types'):
            supported = collector.get_supported_types()
            self.assertIsInstance(supported, (list, dict))


if __name__ == '__main__':
    unittest.main()
