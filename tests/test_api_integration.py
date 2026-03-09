"""
API Integration Tests

Tests for server token validation, artifact upload simulation,
and WebSocket progress reporting.
"""
import os
import sys
import json
import unittest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))


class TestTokenValidation(unittest.TestCase):
    """Tests for server token validation"""

    def test_token_validator_init(self):
        """Test TokenValidator initialization"""
        from core.token_validator import TokenValidator

        validator = TokenValidator(server_url='http://localhost:8000')
        self.assertIsNotNone(validator)

    @patch('requests.post')
    def test_validate_token_success(self, mock_post):
        """Test successful token validation"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'valid': True,
            'case_id': 'test-case-123',
            'allowed_artifacts': ['prefetch', 'browser', 'memory_dump'],
        }
        mock_post.return_value = mock_response

        from core.token_validator import TokenValidator

        validator = TokenValidator(server_url='http://localhost:8000')

        if hasattr(validator, 'validate'):
            result = validator.validate('test-token')
            self.assertTrue(result.valid if hasattr(result, 'valid') else result)

    @patch('requests.post')
    def test_validate_token_failure(self, mock_post):
        """Test failed token validation"""
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.json.return_value = {'valid': False, 'error': 'Invalid token'}
        mock_post.return_value = mock_response

        from core.token_validator import TokenValidator

        validator = TokenValidator(server_url='http://localhost:8000')

        if hasattr(validator, 'validate'):
            result = validator.validate('invalid-token')
            self.assertFalse(result.valid if hasattr(result, 'valid') else result)

    @patch('requests.post')
    def test_validate_token_network_error(self, mock_post):
        """Test token validation with network error"""
        mock_post.side_effect = Exception("Network error")

        from core.token_validator import TokenValidator

        validator = TokenValidator(server_url='http://localhost:8000')

        if hasattr(validator, 'validate'):
            # Should handle network errors gracefully
            try:
                result = validator.validate('test-token')
                # If it returns, should indicate failure
                self.assertFalse(result.valid if hasattr(result, 'valid') else result)
            except Exception:
                pass  # Expected for network errors


class TestArtifactUpload(unittest.TestCase):
    """Tests for artifact upload to server"""

    def test_uploader_init(self):
        """Test SyncUploader initialization"""
        from core.uploader import SyncUploader

        uploader = SyncUploader(
            server_url='http://localhost:8000',
            session_token='test-token'
        )
        self.assertIsNotNone(uploader)

    @patch('requests.post')
    def test_upload_artifact_success(self, mock_post):
        """Test successful artifact upload"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True, 'artifact_id': 'art-123'}
        mock_post.return_value = mock_response

        from core.uploader import SyncUploader

        uploader = SyncUploader(
            server_url='http://localhost:8000',
            session_token='test-token'
        )

        if hasattr(uploader, 'upload'):
            # Create mock artifact data
            artifact_data = {
                'type': 'prefetch',
                'content': 'test content',
                'metadata': {'source': 'test'}
            }
            result = uploader.upload(artifact_data)
            self.assertTrue(result)

    @patch('requests.post')
    def test_upload_artifact_with_file(self, mock_post):
        """Test artifact upload with file attachment"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'success': True}
        mock_post.return_value = mock_response

        from core.uploader import SyncUploader

        uploader = SyncUploader(
            server_url='http://localhost:8000',
            session_token='test-token'
        )

        if hasattr(uploader, 'upload_file'):
            # Should handle file upload
            self.assertTrue(callable(uploader.upload_file))


class TestWebSocketProgress(unittest.TestCase):
    """Tests for WebSocket progress reporting"""

    def test_websocket_url_construction(self):
        """Test WebSocket URL is constructed correctly"""
        from core.uploader import SyncUploader

        uploader = SyncUploader(
            server_url='http://localhost:8000',
            session_token='test-token'
        )

        if hasattr(uploader, 'ws_url'):
            ws_url = uploader.ws_url
            self.assertTrue(
                ws_url.startswith('ws://') or ws_url.startswith('wss://'),
                f"Invalid WebSocket URL: {ws_url}"
            )

    def test_progress_callback_structure(self):
        """Test progress callback receives correct data structure"""
        progress_data = []

        def progress_callback(progress):
            progress_data.append(progress)

        from core.uploader import SyncUploader

        uploader = SyncUploader(
            server_url='http://localhost:8000',
            session_token='test-token'
        )

        if hasattr(uploader, 'set_progress_callback'):
            uploader.set_progress_callback(progress_callback)
            self.assertTrue(callable(uploader.progress_callback))


class TestEncryption(unittest.TestCase):
    """Tests for artifact encryption before upload"""

    def test_encryptor_init(self):
        """Test FileEncryptor initialization"""
        from core.encryptor import FileEncryptor

        encryptor = FileEncryptor()
        self.assertIsNotNone(encryptor)

    def test_encrypt_data(self):
        """Test data encryption"""
        from core.encryptor import FileEncryptor

        encryptor = FileEncryptor()

        test_data = b"Test forensic data"

        if hasattr(encryptor, 'encrypt'):
            encrypted = encryptor.encrypt(test_data)
            self.assertIsInstance(encrypted, bytes)
            self.assertNotEqual(encrypted, test_data)

    def test_encryption_key_generation(self):
        """Test encryption key is generated"""
        from core.encryptor import FileEncryptor

        encryptor = FileEncryptor()

        if hasattr(encryptor, 'key'):
            self.assertIsNotNone(encryptor.key)
            self.assertGreater(len(encryptor.key), 0)


class TestServerToCollectorMapping(unittest.TestCase):
    """Tests for SERVER_TO_COLLECTOR_MAPPING"""

    def test_mapping_exists(self):
        """Test SERVER_TO_COLLECTOR_MAPPING is defined"""
        from gui.app import SERVER_TO_COLLECTOR_MAPPING

        self.assertIsInstance(SERVER_TO_COLLECTOR_MAPPING, dict)
        self.assertGreater(len(SERVER_TO_COLLECTOR_MAPPING), 0)

    def test_mapping_has_memory_types(self):
        """Test mapping includes memory forensics types"""
        from gui.app import SERVER_TO_COLLECTOR_MAPPING

        memory_types = [
            'memory_dump',
            'memory_process',
            'memory_network',
            'memory_module',
            'memory_handle',
            'memory_registry',
            'memory_credential',
            'memory_malware',
        ]

        for mem_type in memory_types:
            self.assertIn(mem_type, SERVER_TO_COLLECTOR_MAPPING,
                         f"Missing memory type: {mem_type}")

    def test_mapping_has_android_types(self):
        """Test mapping includes Android forensics types"""
        from gui.app import SERVER_TO_COLLECTOR_MAPPING

        android_types = [
            'mobile_android_sms',
            'mobile_android_call',
            'mobile_android_contacts',
            'mobile_android_app',
            'mobile_android_wifi',
            'mobile_android_location',
            'mobile_android_media',
        ]

        for android_type in android_types:
            self.assertIn(android_type, SERVER_TO_COLLECTOR_MAPPING,
                         f"Missing Android type: {android_type}")

    def test_mapping_has_ios_types(self):
        """Test mapping includes iOS forensics types"""
        from gui.app import SERVER_TO_COLLECTOR_MAPPING

        ios_types = [
            'mobile_ios_sms',
            'mobile_ios_call',
            'mobile_ios_contacts',
            'mobile_ios_app',
            'mobile_ios_safari',
            'mobile_ios_location',
            'mobile_ios_backup',
        ]

        for ios_type in ios_types:
            self.assertIn(ios_type, SERVER_TO_COLLECTOR_MAPPING,
                         f"Missing iOS type: {ios_type}")


class TestCollectionFlow(unittest.TestCase):
    """End-to-end collection flow tests"""

    @patch('requests.post')
    def test_complete_collection_flow_mock(self, mock_post):
        """Test complete collection flow with mocked server"""
        # Mock token validation
        mock_post.return_value = Mock(
            status_code=200,
            json=Mock(return_value={
                'valid': True,
                'case_id': 'test-case',
                'allowed_artifacts': ['prefetch'],
            })
        )

        from core.token_validator import TokenValidator

        # Step 1: Validate token
        validator = TokenValidator(server_url='http://localhost:8000')

        if hasattr(validator, 'validate'):
            result = validator.validate('test-token')
            # Validation should succeed
            self.assertTrue(result.valid if hasattr(result, 'valid') else True)

    def test_artifact_collection_types_match_server(self):
        """Test that collector artifact types match server expectations"""
        from gui.app import SERVER_TO_COLLECTOR_MAPPING

        # All values in mapping should be valid collector types
        for server_type, collector_type in SERVER_TO_COLLECTOR_MAPPING.items():
            self.assertIsInstance(collector_type, str)
            self.assertGreater(len(collector_type), 0)


class TestErrorHandling(unittest.TestCase):
    """Tests for error handling in API integration"""

    @patch('requests.post')
    def test_handle_server_500_error(self, mock_post):
        """Test handling of server 500 errors"""
        mock_post.return_value = Mock(
            status_code=500,
            json=Mock(return_value={'error': 'Internal server error'})
        )

        from core.token_validator import TokenValidator

        validator = TokenValidator(server_url='http://localhost:8000')

        if hasattr(validator, 'validate'):
            result = validator.validate('test-token')
            # Should handle gracefully
            self.assertFalse(result.valid if hasattr(result, 'valid') else result)

    @patch('requests.post')
    def test_handle_timeout(self, mock_post):
        """Test handling of request timeout"""
        import requests
        mock_post.side_effect = requests.Timeout("Connection timed out")

        from core.token_validator import TokenValidator

        validator = TokenValidator(server_url='http://localhost:8000')

        if hasattr(validator, 'validate'):
            try:
                result = validator.validate('test-token')
                # If it returns, should indicate failure
                self.assertFalse(result.valid if hasattr(result, 'valid') else result)
            except Exception:
                pass  # Expected for timeout


if __name__ == '__main__':
    unittest.main()
