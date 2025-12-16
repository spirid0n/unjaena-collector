"""
Android Collector Unit Tests

Tests for ADB connection detection, device info parsing,
and artifact collection path tests.
"""
import os
import sys
import unittest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


class TestADBDeviceMonitor(unittest.TestCase):
    """Tests for ADBDeviceMonitor class"""

    def test_monitor_init(self):
        """Test ADBDeviceMonitor initialization"""
        from collectors.android_collector import ADBDeviceMonitor

        callback = Mock()
        monitor = ADBDeviceMonitor(callback=callback)
        self.assertIsNotNone(monitor)
        self.assertEqual(monitor.callback, callback)

    def test_monitor_not_running_initially(self):
        """Test monitor is not running after initialization"""
        from collectors.android_collector import ADBDeviceMonitor

        monitor = ADBDeviceMonitor(callback=Mock())
        self.assertFalse(monitor.monitoring)

    @patch('subprocess.run')
    def test_check_adb_available_success(self, mock_run):
        """Test ADB availability check when ADB is installed"""
        mock_run.return_value = Mock(returncode=0, stdout='Android Debug Bridge')

        from collectors.android_collector import ADBDeviceMonitor

        monitor = ADBDeviceMonitor(callback=Mock())

        if hasattr(monitor, 'check_adb_available'):
            result = monitor.check_adb_available()
            self.assertTrue(result)

    @patch('subprocess.run')
    def test_check_adb_available_failure(self, mock_run):
        """Test ADB availability check when ADB is not installed"""
        mock_run.side_effect = FileNotFoundError()

        from collectors.android_collector import ADBDeviceMonitor

        monitor = ADBDeviceMonitor(callback=Mock())

        if hasattr(monitor, 'check_adb_available'):
            result = monitor.check_adb_available()
            self.assertFalse(result)


class TestDeviceInfoParsing(unittest.TestCase):
    """Tests for Android device info parsing"""

    def test_parse_device_list_output(self):
        """Test parsing ADB devices output"""
        from collectors.android_collector import ADBDeviceMonitor

        # Sample ADB devices output
        adb_output = """List of devices attached
ABC123DEF456	device
XYZ789GHI012	unauthorized
"""

        monitor = ADBDeviceMonitor(callback=Mock())

        if hasattr(monitor, '_parse_device_list'):
            devices = monitor._parse_device_list(adb_output)
            self.assertIsInstance(devices, list)
            # Should find at least one authorized device
            authorized = [d for d in devices if d.get('status') == 'device']
            self.assertGreaterEqual(len(authorized), 1)

    def test_parse_device_properties(self):
        """Test parsing device properties from getprop output"""
        from collectors.android_collector import ADBDeviceMonitor

        # Sample getprop output
        props_output = """[ro.product.model]: [Pixel 6]
[ro.build.version.release]: [13]
[ro.product.manufacturer]: [Google]
[ro.serialno]: [ABC123DEF456]
"""

        monitor = ADBDeviceMonitor(callback=Mock())

        if hasattr(monitor, '_parse_device_properties'):
            props = monitor._parse_device_properties(props_output)
            self.assertIsInstance(props, dict)


class TestAndroidArtifactTypes(unittest.TestCase):
    """Tests for Android artifact type definitions"""

    def test_android_artifact_types_exist(self):
        """Test that ANDROID_ARTIFACT_TYPES is defined correctly"""
        from collectors.android_collector import ANDROID_ARTIFACT_TYPES

        expected_types = [
            'mobile_android_sms',
            'mobile_android_call',
            'mobile_android_contacts',
            'mobile_android_app',
            'mobile_android_wifi',
            'mobile_android_location',
            'mobile_android_media',
        ]

        for artifact_type in expected_types:
            self.assertIn(artifact_type, ANDROID_ARTIFACT_TYPES)

    def test_android_artifact_types_have_required_fields(self):
        """Test that each artifact type has required fields"""
        from collectors.android_collector import ANDROID_ARTIFACT_TYPES

        for type_name, type_config in ANDROID_ARTIFACT_TYPES.items():
            self.assertIn('name', type_config, f"{type_name} missing 'name'")
            self.assertIn('description', type_config, f"{type_name} missing 'description'")


class TestAndroidCollector(unittest.TestCase):
    """Tests for AndroidCollector class"""

    def test_collector_init(self):
        """Test AndroidCollector initialization"""
        from collectors.android_collector import AndroidCollector

        collector = AndroidCollector()
        self.assertIsNotNone(collector)

    def test_collector_has_collect_method(self):
        """Test AndroidCollector has collect method"""
        from collectors.android_collector import AndroidCollector

        collector = AndroidCollector()
        self.assertTrue(hasattr(collector, 'collect'))
        self.assertTrue(callable(collector.collect))

    def test_collector_supported_types(self):
        """Test AndroidCollector returns supported artifact types"""
        from collectors.android_collector import AndroidCollector

        collector = AndroidCollector()

        if hasattr(collector, 'get_supported_types'):
            supported = collector.get_supported_types()
            self.assertIsInstance(supported, (list, dict))


class TestUSBDebuggingGuide(unittest.TestCase):
    """Tests for USB debugging guide functionality"""

    def test_guide_function_exists(self):
        """Test that USB debugging guide function exists"""
        from collectors.android_collector import get_usb_debugging_guide

        guide = get_usb_debugging_guide()
        self.assertIsInstance(guide, (str, list, dict))

    def test_guide_contains_steps(self):
        """Test that guide contains setup steps"""
        from collectors.android_collector import get_usb_debugging_guide

        guide = get_usb_debugging_guide()

        if isinstance(guide, str):
            # Should contain relevant keywords
            keywords = ['USB', 'debug', 'developer', 'setting']
            has_keywords = any(kw.lower() in guide.lower() for kw in keywords)
            self.assertTrue(has_keywords)
        elif isinstance(guide, (list, dict)):
            # Should have at least one step
            self.assertGreater(len(guide), 0)


class TestArtifactPaths(unittest.TestCase):
    """Tests for Android artifact collection paths"""

    def test_sms_database_path(self):
        """Test SMS database path constant"""
        from collectors.android_collector import ANDROID_ARTIFACT_TYPES

        sms_config = ANDROID_ARTIFACT_TYPES.get('mobile_android_sms', {})

        if 'db_path' in sms_config:
            self.assertIn('mmssms', sms_config['db_path'].lower())

    def test_contacts_database_path(self):
        """Test contacts database path constant"""
        from collectors.android_collector import ANDROID_ARTIFACT_TYPES

        contacts_config = ANDROID_ARTIFACT_TYPES.get('mobile_android_contacts', {})

        if 'db_path' in contacts_config:
            self.assertIn('contacts', contacts_config['db_path'].lower())


if __name__ == '__main__':
    unittest.main()
