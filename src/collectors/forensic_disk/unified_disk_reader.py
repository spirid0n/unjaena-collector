# -*- coding: utf-8 -*-
"""
Unified Disk Reader - Abstract Base Class for Raw Disk Access

모든 디스크 소스(물리 디스크, E01, RAW 이미지)의 통합 인터페이스.
FTK Imager, Autopsy, EnCase와 동일한 raw sector 기반 접근 방식.

Features:
- 물리 디스크 직접 접근 (\\\\.\\PhysicalDrive{N})
- E01 포렌식 이미지 (pyewf)
- RAW/DD 이미지 파일
- 섹터 정렬 자동 처리

Usage:
    from core.engine.collectors.filesystem.unified_disk_reader import UnifiedDiskReader
    from core.engine.collectors.filesystem.disk_backends import PhysicalDiskBackend

    with PhysicalDiskBackend(0) as disk:
        # MBR 읽기
        mbr = disk.read(0, 512)

        # 특정 섹터 읽기
        data = disk.read_sectors(2048, 8)  # 섹터 2048부터 8섹터

References:
- https://docs.microsoft.com/en-us/windows/win32/fileio/disk-devices
- https://github.com/libyal/libewf
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class DiskSourceType(Enum):
    """디스크 소스 타입"""
    PHYSICAL_DISK = "physical"    # \\.\PhysicalDrive{N}
    E01_IMAGE = "e01"             # E01/EWF 포렌식 이미지
    RAW_IMAGE = "raw"             # DD/RAW 이미지 파일
    VHD_IMAGE = "vhd"             # Virtual Hard Disk
    VMDK_IMAGE = "vmdk"           # VMware Disk


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
    partition_type: int           # MBR type (0x07=NTFS, 0x0B=FAT32, etc.)
    type_guid: str = ""           # GPT GUID
    type_name: str = ""           # 파일시스템 이름
    offset: int = 0               # 파티션 시작 오프셋 (바이트)
    size: int = 0                 # 파티션 크기 (바이트)
    lba_start: int = 0            # 시작 LBA 섹터
    sector_count: int = 0         # 섹터 수
    filesystem: str = ""          # 감지된 파일시스템 (NTFS, FAT32, etc.)
    is_bootable: bool = False     # 부팅 가능 플래그
    name: str = ""                # GPT 파티션 이름


class UnifiedDiskReader(ABC):
    """
    통합 디스크 리더 추상 베이스 클래스

    모든 디스크 소스(물리 디스크, E01, RAW 등)가 이 인터페이스를 구현합니다.
    raw sector 기반 접근으로 Windows 파일시스템을 완전히 우회합니다.

    Usage:
        # Context manager 사용 (권장)
        with PhysicalDiskBackend(0) as disk:
            data = disk.read(0, 512)

        # 직접 사용
        disk = PhysicalDiskBackend(0)
        try:
            data = disk.read(0, 512)
        finally:
            disk.close()
    """

    def __init__(self):
        self._sector_size = 512
        self._disk_size = 0
        self._is_open = False

    # ========== Abstract Methods (구현 필수) ==========

    @abstractmethod
    def read(self, offset: int, size: int) -> bytes:
        """
        Raw 바이트 읽기

        Args:
            offset: 절대 바이트 오프셋 (디스크 시작부터)
            size: 읽을 바이트 수

        Returns:
            Raw 바이트 데이터 (디스크 끝에서는 size보다 적을 수 있음)

        Raises:
            IOError: 읽기 실패
        """
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

    # ========== Implemented Methods ==========

    def read_sectors(self, sector_offset: int, sector_count: int) -> bytes:
        """
        섹터 단위 읽기

        Args:
            sector_offset: 시작 섹터 번호 (0-based)
            sector_count: 읽을 섹터 수

        Returns:
            Raw 섹터 데이터
        """
        byte_offset = sector_offset * self._sector_size
        byte_size = sector_count * self._sector_size
        return self.read(byte_offset, byte_size)

    def read_aligned(self, offset: int, size: int) -> bytes:
        """
        섹터 정렬된 읽기

        물리 디스크에서는 섹터 경계로 정렬된 읽기가 필요합니다.
        이 메서드는 자동으로 정렬을 처리합니다.

        Args:
            offset: 바이트 오프셋 (정렬 불필요)
            size: 읽을 바이트 수

        Returns:
            요청된 범위의 데이터 (정확한 크기)
        """
        # 정렬된 시작/끝 섹터 계산
        start_sector = offset // self._sector_size
        end_byte = offset + size
        end_sector = (end_byte + self._sector_size - 1) // self._sector_size

        # 정렬된 데이터 읽기
        aligned_data = self.read_sectors(start_sector, end_sector - start_sector)

        # 요청된 범위 추출
        start_in_sector = offset % self._sector_size
        return aligned_data[start_in_sector:start_in_sector + size]

    def read_cluster(self, cluster_number: int, cluster_size: int, partition_offset: int = 0) -> bytes:
        """
        클러스터 읽기 (파일시스템 레벨)

        Args:
            cluster_number: 클러스터 번호 (LCN)
            cluster_size: 클러스터 크기 (바이트)
            partition_offset: 파티션 시작 오프셋

        Returns:
            클러스터 데이터
        """
        offset = partition_offset + (cluster_number * cluster_size)
        return self.read(offset, cluster_size)

    def read_clusters(
        self,
        data_runs: List[Tuple[int, int]],
        cluster_size: int,
        partition_offset: int = 0,
        max_size: int = None
    ) -> bytes:
        """
        Data runs로부터 파일 데이터 읽기

        NTFS data runs 또는 FAT cluster chain을 따라 파일 내용을 읽습니다.

        Args:
            data_runs: [(lcn, cluster_count), ...] 리스트
            cluster_size: 클러스터 크기 (바이트)
            partition_offset: 파티션 시작 오프셋
            max_size: 최대 읽기 크기 (파일 크기 제한용)

        Returns:
            파일 데이터 (bytes)
        """
        data = bytearray()
        bytes_read = 0

        for lcn, cluster_count in data_runs:
            if max_size and bytes_read >= max_size:
                break

            if lcn is None:
                # Sparse run - 0으로 채움
                sparse_size = cluster_count * cluster_size
                if max_size:
                    sparse_size = min(sparse_size, max_size - bytes_read)
                data.extend(b'\x00' * sparse_size)
                bytes_read += sparse_size
            else:
                # 실제 클러스터 읽기
                run_offset = partition_offset + (lcn * cluster_size)
                run_size = cluster_count * cluster_size

                if max_size:
                    run_size = min(run_size, max_size - bytes_read)

                chunk = self.read(run_offset, run_size)
                data.extend(chunk)
                bytes_read += len(chunk)

        if max_size:
            return bytes(data[:max_size])
        return bytes(data)

    @property
    def sector_size(self) -> int:
        """섹터 크기 (보통 512 바이트)"""
        return self._sector_size

    @property
    def is_open(self) -> bool:
        """디스크가 열려있는지 여부"""
        return self._is_open

    # ========== Context Manager ==========

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class DiskError(Exception):
    """디스크 작업 관련 기본 예외"""
    pass


class DiskNotFoundError(DiskError):
    """디스크를 찾을 수 없음"""
    pass


class DiskPermissionError(DiskError):
    """디스크 접근 권한 없음 (관리자 권한 필요)"""
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
