# -*- coding: utf-8 -*-
"""
BitLocker Unlock Flow Tests

Tests the full BitLocker decryption pipeline:
  BitLockerBackend creation -> set key -> unlock -> read decrypted data

Since constructing a real BitLocker volume requires Windows-specific crypto
structures (FVE metadata, AES-XTS encrypted sectors, FVEK wrapped in VMK, etc.)
that cannot feasibly be synthesized in-process, these tests use unittest.mock
to verify the correct call sequence against dissect.fve's BDE API.

Verified behaviors:
  1. Full unlock flow: BDE(fh) -> unlock_with_recovery_password(key) -> open() -> stream
  2. Password unlock:  BDE(fh) -> unlock_with_passphrase(pw) -> open() -> stream
  3. BEK file unlock:  BDE(fh) -> unlock_with_bek(fh) -> open() -> stream
  4. Decrypted read:    stream.seek(offset) + stream.read(size)
  5. Error propagation: ValueError from dissect.fve -> BitLockerError with message
  6. PartitionSliceReader.size property and boundary behavior
  7. Volume info loading on construction
  8. Close/cleanup lifecycle
"""

import io
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock, call

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from utils.bitlocker.bitlocker_backend import (
    BitLockerBackend,
    BitLockerKeyType,
    BitLockerVolumeInfo,
    PartitionSliceReader,
)
from utils.bitlocker.unified_disk_reader import BitLockerError


# =============================================================================
# Helpers
# =============================================================================

def _make_mock_bde(unlocked=False, has_recovery=True, has_passphrase=False):
    """Create a mock BDE instance that mimics dissect.fve.bde.BDE behavior."""
    mock_bde = MagicMock()
    mock_bde.unlocked = unlocked

    # BDE.open() returns a BitlockerStream-like object
    mock_stream = MagicMock()
    mock_stream.size = 1024 * 1024 * 100  # 100 MB
    mock_stream.seek = MagicMock()
    mock_stream.read = MagicMock(return_value=b'\x00' * 4096)
    mock_bde.open.return_value = mock_stream

    # unlock methods return self (BDE) for chaining
    mock_bde.unlock_with_recovery_password.return_value = mock_bde
    mock_bde.unlock_with_passphrase.return_value = mock_bde
    mock_bde.unlock_with_bek.return_value = mock_bde

    # Capability queries
    mock_bde.has_recovery_password.return_value = has_recovery
    mock_bde.has_passphrase.return_value = has_passphrase

    return mock_bde, mock_stream


def _make_partition_reader(data, offset=0, size=None):
    """Build a PartitionSliceReader over a FakeBackend wrapping `data`."""

    class FakeBackend:
        def read(self, off, sz):
            return data[off:off + sz]
        def get_size(self):
            return len(data)

    if size is None:
        size = len(data) - offset
    return PartitionSliceReader(FakeBackend(), offset, size)


# =============================================================================
# 1. Full Recovery-Password Unlock Flow
# =============================================================================

class TestRecoveryPasswordUnlockFlow:
    """BDE(fh) -> unlock_with_recovery_password(key) -> open() -> stream"""

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_full_unlock_sequence(self, mock_bde_cls):
        """Verify the exact call sequence for recovery password unlock."""
        mock_bde, mock_stream = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        fh = io.BytesIO(b'\x00' * 512)
        backend = BitLockerBackend(fh)

        # Step 1: BDE constructor was called with the file handle
        mock_bde_cls.assert_called_once_with(fh)

        # Step 2: Set recovery password
        recovery_key = "123456-234567-345678-456789-567890-678901-789012-890123"
        backend.set_recovery_password(recovery_key)
        assert backend._key_type_used == BitLockerKeyType.RECOVERY_PASSWORD
        assert backend._pending_key == ('recovery', recovery_key)

        # Step 3: Unlock
        result = backend.unlock()
        assert result is True

        # Verify dissect.fve calls in order
        mock_bde.unlock_with_recovery_password.assert_called_once_with(recovery_key)
        mock_bde.open.assert_called_once()

        # Step 4: Read from decrypted stream
        backend.read(0, 4096)
        mock_stream.seek.assert_called_with(0)
        mock_stream.read.assert_called_with(4096)

        # Volume should report unlocked
        assert backend.is_unlocked is True
        assert backend.is_locked() is False

        backend.close()

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_stream_size_captured_after_unlock(self, mock_bde_cls):
        """After unlock, disk_size should reflect the stream's size property."""
        mock_bde, mock_stream = _make_mock_bde()
        mock_stream.size = 500 * 1024 * 1024  # 500 MB
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        backend.set_recovery_password("111111-222222-333333-444444-555555-666666-777777-888888")
        backend.unlock()

        assert backend.get_size() == 500 * 1024 * 1024
        backend.close()

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_multiple_reads_at_different_offsets(self, mock_bde_cls):
        """Verify seek+read pairs for different offsets."""
        mock_bde, mock_stream = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        backend.set_recovery_password("111111-222222-333333-444444-555555-666666-777777-888888")
        backend.unlock()

        # Read at offset 0
        backend.read(0, 512)
        mock_stream.seek.assert_called_with(0)

        # Read at offset 1 MB
        backend.read(1024 * 1024, 512)
        mock_stream.seek.assert_called_with(1024 * 1024)

        # Read at offset 50 MB
        backend.read(50 * 1024 * 1024, 4096)
        mock_stream.seek.assert_called_with(50 * 1024 * 1024)
        mock_stream.read.assert_called_with(4096)

        backend.close()


# =============================================================================
# 2. Password Unlock Flow
# =============================================================================

class TestPasswordUnlockFlow:
    """BDE(fh) -> unlock_with_passphrase(pw) -> open() -> stream"""

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_password_unlock_calls_passphrase(self, mock_bde_cls):
        mock_bde, mock_stream = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        backend.set_password("MySecureP@ssw0rd!")
        assert backend._key_type_used == BitLockerKeyType.PASSWORD

        result = backend.unlock()
        assert result is True

        mock_bde.unlock_with_passphrase.assert_called_once_with("MySecureP@ssw0rd!")
        mock_bde.open.assert_called_once()
        backend.close()


# =============================================================================
# 3. BEK File Unlock Flow
# =============================================================================

class TestBEKFileUnlockFlow:
    """BDE(fh) -> unlock_with_bek(bek_fh) -> open() -> stream"""

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    @patch('builtins.open', create=True)
    def test_bek_unlock_opens_file_and_calls_bde(self, mock_open, mock_bde_cls):
        mock_bde, mock_stream = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        mock_bek_fh = MagicMock()
        mock_open.return_value.__enter__ = MagicMock(return_value=mock_bek_fh)
        mock_open.return_value.__exit__ = MagicMock(return_value=False)

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        backend.read_startup_key("/path/to/recovery.bek")
        assert backend._key_type_used == BitLockerKeyType.BEK_FILE

        result = backend.unlock()
        assert result is True

        # The unlock method opens the BEK path and passes the file handle
        mock_open.assert_called_with("/path/to/recovery.bek", 'rb')
        mock_bde.unlock_with_bek.assert_called_once()
        mock_bde.open.assert_called_once()
        backend.close()


# =============================================================================
# 4. Error Propagation
# =============================================================================

class TestErrorPropagation:
    """ValueError from dissect.fve -> BitLockerError with message"""

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_wrong_recovery_password_raises_bitlocker_error(self, mock_bde_cls):
        """dissect.fve raises ValueError on wrong key -> BitLockerError."""
        mock_bde, _ = _make_mock_bde()
        mock_bde.unlock_with_recovery_password.side_effect = ValueError(
            "Unable to unlock with given recovery password"
        )
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        backend.set_recovery_password("000000-000000-000000-000000-000000-000000-000000-000000")

        with pytest.raises(BitLockerError, match="Unable to unlock with given recovery password"):
            backend.unlock()

        assert backend.is_unlocked is False
        backend.close()

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_wrong_password_raises_bitlocker_error(self, mock_bde_cls):
        """Wrong passphrase -> BitLockerError."""
        mock_bde, _ = _make_mock_bde()
        mock_bde.unlock_with_passphrase.side_effect = ValueError(
            "Unable to unlock with given passphrase"
        )
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        backend.set_password("WrongPassword")

        with pytest.raises(BitLockerError, match="Unable to unlock with given passphrase"):
            backend.unlock()

        assert backend.is_unlocked is False
        backend.close()

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_no_key_set_raises_bitlocker_error(self, mock_bde_cls):
        """Calling unlock() without setting a key first raises BitLockerError."""
        mock_bde, _ = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))

        with pytest.raises(BitLockerError, match="No key set"):
            backend.unlock()

        backend.close()

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_read_while_locked_raises_bitlocker_error(self, mock_bde_cls):
        """Reading from a locked volume raises BitLockerError."""
        mock_bde, _ = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))

        with pytest.raises(BitLockerError, match="locked"):
            backend.read(0, 512)

        backend.close()

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_bde_constructor_failure_raises_bitlocker_error(self, mock_bde_cls):
        """If BDE(fh) itself raises, BitLockerBackend wraps it in BitLockerError."""
        mock_bde_cls.side_effect = Exception("Not a BDE volume")

        with pytest.raises(BitLockerError, match="Failed to open BitLocker volume"):
            BitLockerBackend(io.BytesIO(b'\x00' * 512))

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_generic_exception_during_unlock_wraps_in_bitlocker_error(self, mock_bde_cls):
        """Non-ValueError exceptions during unlock also become BitLockerError."""
        mock_bde, _ = _make_mock_bde()
        mock_bde.unlock_with_recovery_password.side_effect = RuntimeError("I/O error")
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        backend.set_recovery_password("111111-222222-333333-444444-555555-666666-777777-888888")

        with pytest.raises(BitLockerError, match="Unlock failed"):
            backend.unlock()

        backend.close()

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_read_exception_wraps_in_bitlocker_error(self, mock_bde_cls):
        """stream.seek or stream.read raising -> BitLockerError."""
        mock_bde, mock_stream = _make_mock_bde()
        mock_stream.seek.side_effect = OSError("Disk read fault")
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        backend.set_recovery_password("111111-222222-333333-444444-555555-666666-777777-888888")
        backend.unlock()

        with pytest.raises(BitLockerError, match="Failed to read decrypted data"):
            backend.read(0, 512)

        backend.close()


# =============================================================================
# 5. PartitionSliceReader
# =============================================================================

class TestPartitionSliceReaderExtended:
    """PartitionSliceReader.size property and boundary behavior."""

    def test_size_property(self):
        """The .size property is used by BitlockerStream in dissect.fve."""
        reader = _make_partition_reader(b'\x00' * 1000, offset=200, size=300)
        assert reader.size == 300

    def test_size_matches_get_size(self):
        reader = _make_partition_reader(b'\x00' * 500, offset=0, size=500)
        assert reader.size == reader.get_size()

    def test_seek_clamps_to_boundaries(self):
        """Seek past end or before start clamps to [0, size]."""
        reader = _make_partition_reader(b'\x00' * 200, offset=0, size=100)

        # Seek past end
        pos = reader.seek(999)
        assert pos == 100  # clamped to size

        # Seek before start
        pos = reader.seek(-10)
        assert pos == 0  # clamped to 0

    def test_read_returns_empty_at_end(self):
        """Reading at EOF returns empty bytes."""
        data = b'A' * 100
        reader = _make_partition_reader(data, offset=0, size=100)
        reader.seek(100)
        assert reader.read(10) == b''

    def test_read_from_offset_partition(self):
        """Reads respect the partition's base offset into the underlying data."""
        # Underlying data: 50 bytes of X, then 50 bytes of Y
        data = b'X' * 50 + b'Y' * 50
        reader = _make_partition_reader(data, offset=50, size=50)

        result = reader.read(10)
        assert result == b'Y' * 10

    def test_seek_whence_2_negative(self):
        """SEEK_END with negative offset positions relative to the end."""
        data = b'\x00' * 200
        reader = _make_partition_reader(data, offset=0, size=200)
        pos = reader.seek(-50, 2)
        assert pos == 150


# =============================================================================
# 6. Volume Info and Metadata
# =============================================================================

class TestVolumeInfoOnConstruction:
    """Volume info should be loaded during __init__."""

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_volume_info_populated(self, mock_bde_cls):
        mock_bde, _ = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        info = backend.get_volume_info()

        assert isinstance(info, BitLockerVolumeInfo)
        assert info.is_locked is True
        backend.close()

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_disk_info_after_unlock(self, mock_bde_cls):
        """DiskInfo should report source and size after unlock."""
        mock_bde, mock_stream = _make_mock_bde()
        mock_stream.size = 1024 * 1024 * 256  # 256 MB
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        backend.set_recovery_password("111111-222222-333333-444444-555555-666666-777777-888888")
        backend.unlock()

        disk_info = backend.get_disk_info()
        assert disk_info.total_size == 256 * 1024 * 1024
        assert disk_info.model == "BitLocker Decrypted Volume"
        assert disk_info.is_readonly is True
        backend.close()

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_size_zero_before_unlock(self, mock_bde_cls):
        """Before unlock, disk_size is 0 (stream not yet available)."""
        mock_bde, _ = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        assert backend.get_size() == 0
        backend.close()


# =============================================================================
# 7. Close / Cleanup Lifecycle
# =============================================================================

class TestCloseLifecycle:
    """Verify close() cleans up all resources."""

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_close_clears_stream_and_bde(self, mock_bde_cls):
        mock_bde, mock_stream = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        backend.set_recovery_password("111111-222222-333333-444444-555555-666666-777777-888888")
        backend.unlock()

        assert backend._stream is not None
        assert backend._bde is not None

        backend.close()

        assert backend._stream is None
        assert backend._bde is None
        assert backend.is_unlocked is False
        assert backend.is_open is False

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_close_without_unlock(self, mock_bde_cls):
        """Closing a backend that was never unlocked should not error."""
        mock_bde, _ = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        backend.close()  # should not raise

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_context_manager(self, mock_bde_cls):
        """BitLockerBackend supports 'with' statement via UnifiedDiskReader."""
        mock_bde, mock_stream = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        with BitLockerBackend(io.BytesIO(b'\x00' * 512)) as backend:
            backend.set_recovery_password("111111-222222-333333-444444-555555-666666-777777-888888")
            backend.unlock()
            backend.read(0, 512)

        # After exiting context, resources should be released
        assert backend._stream is None
        assert backend._bde is None


# =============================================================================
# 8. dissect.fve Not Available
# =============================================================================

class TestDissectFveNotAvailable:
    """When dissect.fve is not installed."""

    @patch('utils.bitlocker.bitlocker_backend._load_dissect_fve', return_value=False)
    def test_raises_when_fve_missing(self, mock_load):
        with pytest.raises(BitLockerError, match="dissect.fve is not installed"):
            BitLockerBackend(io.BytesIO(b'\x00' * 512))


# =============================================================================
# 9. dissect.fve Recovery Password Validation (real library)
# =============================================================================

class TestDissectRecoveryPasswordValidation:
    """Verify dissect.fve's check_recovery_password directly."""

    def test_valid_format_8_groups_of_6_digits(self):
        from dissect.fve.bde.key import check_recovery_password
        # Each block must: be 6 digits, be divisible by 11, pass checksum, < 720896
        # Pre-computed valid blocks: each block N satisfies N % 11 == 0 and checksum
        # Using known valid password format
        # Block validation: digits[0]-digits[1]+digits[2]-digits[3]+digits[4] % 11 == digits[5]
        # 162008: 1-6+2-0+0 = -3 % 11 = 8 -> last digit 8. 162008/11 = 14728. < 65536*11=720896. Valid.
        valid_password = "162008-162008-162008-162008-162008-162008-162008-162008"
        assert check_recovery_password(valid_password) is True

    def test_wrong_number_of_blocks_raises(self):
        from dissect.fve.bde.key import check_recovery_password
        with pytest.raises(ValueError, match="invalid length"):
            check_recovery_password("111111-222222-333333")

    def test_non_numeric_raises(self):
        from dissect.fve.bde.key import check_recovery_password
        with pytest.raises(ValueError, match="non-numeric"):
            check_recovery_password("abcdef-123456-123456-123456-123456-123456-123456-123456")

    def test_not_divisible_by_11_raises(self):
        from dissect.fve.bde.key import check_recovery_password
        with pytest.raises(ValueError, match="not divisible by 11"):
            check_recovery_password("123457-123457-123457-123457-123457-123457-123457-123457")

    def test_too_large_block_raises(self):
        from dissect.fve.bde.key import check_recovery_password
        # 720896 = 2^16 * 11, so 720907 (720896 + 11) should fail
        with pytest.raises(ValueError, match="larger than"):
            check_recovery_password("720907-720907-720907-720907-720907-720907-720907-720907")


# =============================================================================
# 10. Key Type Precedence
# =============================================================================

class TestKeyTypePrecedence:
    """Setting a new key type replaces the previous one."""

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_last_key_wins(self, mock_bde_cls):
        mock_bde, mock_stream = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))

        # Set recovery password first
        backend.set_recovery_password("111111-222222-333333-444444-555555-666666-777777-888888")
        assert backend._key_type_used == BitLockerKeyType.RECOVERY_PASSWORD

        # Override with password
        backend.set_password("SomePassword")
        assert backend._key_type_used == BitLockerKeyType.PASSWORD
        assert backend._pending_key == ('password', 'SomePassword')

        # Unlock should use the password path
        backend.unlock()
        mock_bde.unlock_with_passphrase.assert_called_once_with("SomePassword")
        mock_bde.unlock_with_recovery_password.assert_not_called()

        backend.close()

    @patch('utils.bitlocker.bitlocker_backend._bde_class')
    @patch('utils.bitlocker.bitlocker_backend._fve_available', True)
    def test_set_key_on_closed_volume_raises(self, mock_bde_cls):
        """Setting a key after close raises BitLockerError."""
        mock_bde, _ = _make_mock_bde()
        mock_bde_cls.return_value = mock_bde

        backend = BitLockerBackend(io.BytesIO(b'\x00' * 512))
        backend.close()

        with pytest.raises(BitLockerError, match="Volume not opened"):
            backend.set_recovery_password("111111-222222-333333-444444-555555-666666-777777-888888")


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
