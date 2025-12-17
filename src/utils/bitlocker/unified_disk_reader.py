# -*- coding: utf-8 -*-
"""
Unified Disk Reader - Abstract Base Class for Raw Disk Access

모든 디스크 소스(물리 디스크, E01, RAW 이미지)의 통합 인터페이스.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class DiskSourceType(Enum):
    """디스크 소스 타입"""
    PHYSICAL_DISK = "physical"
    E01_IMAGE = "e01"
    RAW_IMAGE = "raw"
    VHD_IMAGE = "vhd"
    VMDK_IMAGE = "vmdk"


@dataclass
class DiskInfo:
    """디스크 메타데이터"""
    source_type: DiskSourceType
    total_size: int
    sector_size: int = 512
    source_path: str = ""
    is_readonly: bool = True
    model: str = ""
    serial: str = ""


@dataclass
class PartitionInfo:
    """파티션 정보"""
    index: int
    partition_type: int
    type_guid: str = ""
    type_name: str = ""
    offset: int = 0
    size: int = 0
    lba_start: int = 0
    sector_count: int = 0
    filesystem: str = ""
    is_bootable: bool = False
    name: str = ""


class UnifiedDiskReader(ABC):
    """
    통합 디스크 리더 추상 베이스 클래스
    """

    def __init__(self):
        self._sector_size = 512
        self._disk_size = 0
        self._is_open = False

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes:
        """Raw 바이트 읽기"""
        pass

    @abstractmethod
    def get_disk_info(self) -> DiskInfo:
        """디스크 메타데이터 반환"""
        pass

    @abstractmethod
    def get_size(self) -> int:
        """디스크 전체 크기 (바이트)"""
        pass

    @abstractmethod
    def close(self) -> None:
        """리소스 해제"""
        pass

    def read_sectors(self, sector_offset: int, sector_count: int) -> bytes:
        """섹터 단위 읽기"""
        byte_offset = sector_offset * self._sector_size
        byte_size = sector_count * self._sector_size
        return self.read(byte_offset, byte_size)

    def read_aligned(self, offset: int, size: int) -> bytes:
        """섹터 정렬된 읽기"""
        start_sector = offset // self._sector_size
        end_byte = offset + size
        end_sector = (end_byte + self._sector_size - 1) // self._sector_size
        aligned_data = self.read_sectors(start_sector, end_sector - start_sector)
        start_in_sector = offset % self._sector_size
        return aligned_data[start_in_sector:start_in_sector + size]

    @property
    def sector_size(self) -> int:
        return self._sector_size

    @property
    def is_open(self) -> bool:
        return self._is_open

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


# 예외 클래스들
class DiskError(Exception):
    """디스크 작업 관련 기본 예외"""
    pass


class DiskNotFoundError(DiskError):
    """디스크를 찾을 수 없음"""
    pass


class DiskPermissionError(DiskError):
    """디스크 접근 권한 없음"""
    pass


class DiskReadError(DiskError):
    """디스크 읽기 오류"""
    pass


class PartitionError(DiskError):
    """파티션 테이블 파싱 오류"""
    pass


class FilesystemError(DiskError):
    """파일시스템 감지/파싱 오류"""
    pass


class BitLockerError(DiskError):
    """BitLocker 암호화된 볼륨"""
    pass


class BitLockerKeyRequired(BitLockerError):
    """BitLocker 키가 필요함"""
    def __init__(
        self,
        message: str = "BitLocker key required",
        partition_index: int = 0,
        partition_info: 'PartitionInfo' = None,
        encryption_info: dict = None
    ):
        super().__init__(message)
        self.partition_index = partition_index
        self.partition_info = partition_info
        self.encryption_info = encryption_info or {}


class BitLockerInvalidKey(BitLockerError):
    """잘못된 BitLocker 키"""
    pass


class BitLockerUnsupportedProtector(BitLockerError):
    """지원되지 않는 Key Protector"""
    pass
