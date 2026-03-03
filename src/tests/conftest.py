# -*- coding: utf-8 -*-
"""
Pytest Configuration and Fixtures

Defines common fixtures and configurations.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from typing import Generator
import sys

# Add project path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create and cleanup temporary directory"""
    temp_path = Path(tempfile.mkdtemp(prefix="test_collector_"))
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def sample_mft_entry() -> bytes:
    """Sample MFT entry data"""
    # Fake MFT entry starting with FILE signature
    entry = bytearray(1024)
    entry[0:4] = b'FILE'  # Signature
    entry[0x14:0x16] = (56).to_bytes(2, 'little')  # First attribute offset
    entry[0x16:0x18] = (1).to_bytes(2, 'little')  # Flags (in use)
    return bytes(entry)


@pytest.fixture
def sample_usn_record() -> bytes:
    """Sample USN record data"""
    import struct

    record = bytearray(64)
    record[0:4] = struct.pack('<I', 64)  # RecordLength
    record[4:6] = struct.pack('<H', 2)   # MajorVersion
    record[6:8] = struct.pack('<H', 0)   # MinorVersion
    # ... remaining fields
    return bytes(record)


@pytest.fixture
def sample_registry_data() -> bytes:
    """Sample registry hive data"""
    # regf signature
    data = bytearray(4096)
    data[0:4] = b'regf'
    return bytes(data)


# Test marker definitions
def pytest_configure(config):
    """Register custom markers"""
    config.addinivalue_line("markers", "slow: Slow tests (requires E01 image)")
    config.addinivalue_line("markers", "e2e: End-to-End tests")
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
