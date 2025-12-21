"""
ForensicDiskAccessor - Raw disk access for locked files

Provides direct sector-level access to NTFS volumes,
bypassing Windows filesystem locks.
"""

try:
    from .forensic_disk_accessor import ForensicDiskAccessor
    from .unified_disk_reader import DiskError, BitLockerError
    from .disk_backends import (
        PhysicalDiskBackend,
        E01DiskBackend,
        RAWImageBackend
    )
    from .file_content_extractor import FileContentExtractor
    FORENSIC_DISK_AVAILABLE = True
except ImportError as e:
    FORENSIC_DISK_AVAILABLE = False
    ForensicDiskAccessor = None
    DiskError = None
    BitLockerError = None
    _import_error = str(e)

__all__ = [
    'ForensicDiskAccessor',
    'DiskError',
    'BitLockerError',
    'PhysicalDiskBackend',
    'E01DiskBackend',
    'RAWImageBackend',
    'FileContentExtractor',
    'FORENSIC_DISK_AVAILABLE'
]
