# -*- coding: utf-8 -*-
"""
BitLocker Decryptor - 통합 BitLocker 복호화 클래스

물리 디스크, E01 이미지, RAW 이미지의 BitLocker 볼륨을 복호화하는
고수준 API를 제공합니다.

Usage:
    decryptor = BitLockerDecryptor.from_physical_disk(0, partition_index=0)
    result = decryptor.unlock_with_recovery_password("123456-234567-...")

    if result.success:
        reader = decryptor.get_decrypted_reader()
        data = reader.read(0, 512)
"""

from typing import Optional, Union, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum
import logging

from .bitlocker_backend import (
    BitLockerBackend, BitLockerKeyType, BitLockerVolumeInfo,
    PartitionSliceReader, is_pybde_available
)
from .unified_disk_reader import (
    UnifiedDiskReader, PartitionInfo, BitLockerError
)

logger = logging.getLogger(__name__)


@dataclass
class BitLockerUnlockResult:
    """BitLocker 잠금 해제 결과"""
    success: bool
    key_type: Optional[BitLockerKeyType] = None
    error_message: Optional[str] = None
    volume_info: Optional[Dict[str, Any]] = None

    def __bool__(self):
        return self.success


@dataclass
class BitLockerPartitionInfo:
    """BitLocker 파티션 정보"""
    partition_index: int
    offset: int
    size: int
    encryption_method: str = ""
    volume_identifier: str = ""
    key_protector_count: int = 0
    is_locked: bool = True
    supported_key_types: List[str] = field(default_factory=list)


class BitLockerDecryptor:
    """
    BitLocker 복호화 통합 클래스

    지원 키 타입:
    - Recovery Password (48자리 숫자)
    - Password (일반 비밀번호)
    - BEK File (.BEK 시작 키 파일)

    미지원:
    - TPM (하드웨어 의존)
    """

    def __init__(
        self,
        disk_backend: UnifiedDiskReader,
        partition_offset: int,
        partition_size: int,
        partition_index: int = 0
    ):
        self._disk_backend = disk_backend
        self._partition_offset = partition_offset
        self._partition_size = partition_size
        self._partition_index = partition_index

        self._bitlocker_backend: Optional[BitLockerBackend] = None
        self._partition_info: Optional[BitLockerPartitionInfo] = None

        self._initialize()

    def _initialize(self) -> None:
        if not is_pybde_available():
            raise BitLockerError(
                "pybde (libbde-python) is not installed. "
                "Install with: pip install libbde-python"
            )

        slice_reader = PartitionSliceReader(
            self._disk_backend,
            self._partition_offset,
            self._partition_size
        )

        try:
            self._bitlocker_backend = BitLockerBackend(slice_reader)
            self._load_partition_info()
        except Exception as e:
            raise BitLockerError(f"Failed to initialize BitLocker decryptor: {e}")

    def _load_partition_info(self) -> None:
        volume_info = self._bitlocker_backend.get_volume_info()
        protectors = self._bitlocker_backend.get_key_protectors()

        supported = set()
        for p in protectors:
            ptype = p.get('type', '').lower()
            if 'recovery' in ptype:
                supported.add('recovery_password')
            if 'password' in ptype and 'recovery' not in ptype:
                supported.add('password')
            if 'external' in ptype or 'startup' in ptype:
                supported.add('bek_file')
            if 'clear' in ptype:
                supported.add('clear_key')

        if not supported:
            supported = {'recovery_password', 'password', 'bek_file'}

        self._partition_info = BitLockerPartitionInfo(
            partition_index=self._partition_index,
            offset=self._partition_offset,
            size=self._partition_size,
            encryption_method=volume_info.encryption_method,
            volume_identifier=volume_info.volume_identifier,
            key_protector_count=volume_info.key_protector_count,
            is_locked=volume_info.is_locked,
            supported_key_types=list(supported)
        )

    # ========== Factory Methods ==========

    @classmethod
    def from_physical_disk(
        cls,
        drive_number: int,
        partition_index: int = 0
    ) -> 'BitLockerDecryptor':
        """물리 디스크에서 BitLockerDecryptor 생성"""
        from .disk_backends import PhysicalDiskBackend

        backend = PhysicalDiskBackend(drive_number)
        partitions = cls._detect_partitions(backend)

        if partition_index >= len(partitions):
            backend.close()
            raise BitLockerError(f"Partition {partition_index} not found")

        partition = partitions[partition_index]

        if partition.filesystem != 'BitLocker':
            backend.close()
            raise BitLockerError(
                f"Partition {partition_index} is not BitLocker encrypted "
                f"(filesystem: {partition.filesystem})"
            )

        return cls(
            disk_backend=backend,
            partition_offset=partition.offset,
            partition_size=partition.size,
            partition_index=partition_index
        )

    @classmethod
    def from_e01(
        cls,
        e01_path: str,
        partition_index: int = 0
    ) -> 'BitLockerDecryptor':
        """E01 이미지에서 BitLockerDecryptor 생성"""
        from .disk_backends import E01DiskBackend

        backend = E01DiskBackend(e01_path)
        partitions = cls._detect_partitions(backend)

        if partition_index >= len(partitions):
            backend.close()
            raise BitLockerError(f"Partition {partition_index} not found")

        partition = partitions[partition_index]

        if partition.filesystem != 'BitLocker':
            backend.close()
            raise BitLockerError(
                f"Partition {partition_index} is not BitLocker encrypted "
                f"(filesystem: {partition.filesystem})"
            )

        return cls(
            disk_backend=backend,
            partition_offset=partition.offset,
            partition_size=partition.size,
            partition_index=partition_index
        )

    @classmethod
    def from_raw_image(
        cls,
        image_path: str,
        partition_offset: int = 0,
        partition_size: int = None
    ) -> 'BitLockerDecryptor':
        """RAW/DD 이미지에서 BitLockerDecryptor 생성"""
        from .disk_backends import RAWImageBackend

        backend = RAWImageBackend(image_path)

        if partition_size is None:
            partition_size = backend.get_size() - partition_offset

        return cls(
            disk_backend=backend,
            partition_offset=partition_offset,
            partition_size=partition_size,
            partition_index=0
        )

    @classmethod
    def from_partition(
        cls,
        disk_backend: UnifiedDiskReader,
        partition_info: PartitionInfo
    ) -> 'BitLockerDecryptor':
        """파티션 정보로 BitLockerDecryptor 생성"""
        return cls(
            disk_backend=disk_backend,
            partition_offset=partition_info.offset,
            partition_size=partition_info.size,
            partition_index=partition_info.index
        )

    @staticmethod
    def _detect_partitions(backend: UnifiedDiskReader) -> List[PartitionInfo]:
        """파티션 테이블 탐지 (간단 구현)"""
        import struct
        partitions = []

        try:
            # MBR 읽기
            mbr = backend.read(0, 512)
            if len(mbr) < 512:
                return []

            # MBR 시그니처 확인
            signature = struct.unpack('<H', mbr[510:512])[0]
            if signature != 0xAA55:
                return []

            # 파티션 엔트리 파싱 (MBR)
            for i in range(4):
                entry_offset = 446 + i * 16
                entry = mbr[entry_offset:entry_offset + 16]

                partition_type = entry[4]
                if partition_type == 0:
                    continue

                lba_start = struct.unpack('<I', entry[8:12])[0]
                sector_count = struct.unpack('<I', entry[12:16])[0]

                # BitLocker 감지 (VBR 시그니처)
                partition_offset = lba_start * 512
                vbr = backend.read(partition_offset, 512)
                filesystem = cls._detect_filesystem(vbr)

                partitions.append(PartitionInfo(
                    index=i,
                    partition_type=partition_type,
                    offset=partition_offset,
                    size=sector_count * 512,
                    lba_start=lba_start,
                    sector_count=sector_count,
                    filesystem=filesystem,
                    is_bootable=(entry[0] & 0x80) != 0
                ))

        except Exception as e:
            logger.warning(f"Failed to detect partitions: {e}")

        return partitions

    @staticmethod
    def _detect_filesystem(vbr: bytes) -> str:
        """VBR에서 파일시스템 감지"""
        if len(vbr) < 512:
            return "Unknown"

        # BitLocker 시그니처: "-FVE-FS-" at offset 3
        if vbr[3:11] == b'-FVE-FS-':
            return "BitLocker"

        # NTFS 시그니처
        if vbr[3:7] == b'NTFS':
            return "NTFS"

        # FAT32 시그니처
        if vbr[82:90] == b'FAT32   ':
            return "FAT32"

        # exFAT 시그니처
        if vbr[3:11] == b'EXFAT   ':
            return "exFAT"

        return "Unknown"

    # ========== 잠금 해제 메서드 ==========

    def unlock_with_recovery_password(self, recovery_password: str) -> BitLockerUnlockResult:
        """Recovery Password로 잠금 해제"""
        if not self._bitlocker_backend:
            return BitLockerUnlockResult(
                success=False,
                error_message="BitLocker backend not initialized"
            )

        try:
            self._bitlocker_backend.set_recovery_password(recovery_password)
            success = self._bitlocker_backend.unlock()

            if success:
                return BitLockerUnlockResult(
                    success=True,
                    key_type=BitLockerKeyType.RECOVERY_PASSWORD,
                    volume_info=self._get_volume_info_dict()
                )
            else:
                return BitLockerUnlockResult(
                    success=False,
                    key_type=BitLockerKeyType.RECOVERY_PASSWORD,
                    error_message="Invalid recovery password"
                )

        except Exception as e:
            return BitLockerUnlockResult(
                success=False,
                key_type=BitLockerKeyType.RECOVERY_PASSWORD,
                error_message=str(e)
            )

    def unlock_with_password(self, password: str) -> BitLockerUnlockResult:
        """일반 비밀번호로 잠금 해제"""
        if not self._bitlocker_backend:
            return BitLockerUnlockResult(
                success=False,
                error_message="BitLocker backend not initialized"
            )

        try:
            self._bitlocker_backend.set_password(password)
            success = self._bitlocker_backend.unlock()

            if success:
                return BitLockerUnlockResult(
                    success=True,
                    key_type=BitLockerKeyType.PASSWORD,
                    volume_info=self._get_volume_info_dict()
                )
            else:
                return BitLockerUnlockResult(
                    success=False,
                    key_type=BitLockerKeyType.PASSWORD,
                    error_message="Invalid password"
                )

        except Exception as e:
            return BitLockerUnlockResult(
                success=False,
                key_type=BitLockerKeyType.PASSWORD,
                error_message=str(e)
            )

    def unlock_with_bek_file(self, bek_path: str) -> BitLockerUnlockResult:
        """.BEK 시작 키 파일로 잠금 해제"""
        if not self._bitlocker_backend:
            return BitLockerUnlockResult(
                success=False,
                error_message="BitLocker backend not initialized"
            )

        try:
            self._bitlocker_backend.read_startup_key(bek_path)
            success = self._bitlocker_backend.unlock()

            if success:
                return BitLockerUnlockResult(
                    success=True,
                    key_type=BitLockerKeyType.BEK_FILE,
                    volume_info=self._get_volume_info_dict()
                )
            else:
                return BitLockerUnlockResult(
                    success=False,
                    key_type=BitLockerKeyType.BEK_FILE,
                    error_message="Invalid BEK file"
                )

        except Exception as e:
            return BitLockerUnlockResult(
                success=False,
                key_type=BitLockerKeyType.BEK_FILE,
                error_message=str(e)
            )

    def unlock(
        self,
        key_type: BitLockerKeyType,
        key_value: str = "",
        bek_path: str = ""
    ) -> BitLockerUnlockResult:
        """통합 잠금 해제 메서드"""
        if key_type == BitLockerKeyType.RECOVERY_PASSWORD:
            return self.unlock_with_recovery_password(key_value)
        elif key_type == BitLockerKeyType.PASSWORD:
            return self.unlock_with_password(key_value)
        elif key_type == BitLockerKeyType.BEK_FILE:
            return self.unlock_with_bek_file(bek_path)
        else:
            return BitLockerUnlockResult(
                success=False,
                error_message=f"Unsupported key type: {key_type}"
            )

    # ========== 복호화된 볼륨 접근 ==========

    def get_decrypted_reader(self) -> UnifiedDiskReader:
        """복호화된 UnifiedDiskReader 반환"""
        if not self._bitlocker_backend:
            raise BitLockerError("BitLocker backend not initialized")

        if self._bitlocker_backend.is_locked():
            raise BitLockerError(
                "Volume is still locked. Call unlock_with_*() first."
            )

        return self._bitlocker_backend

    # ========== 정보 조회 ==========

    def get_partition_info(self) -> BitLockerPartitionInfo:
        return self._partition_info or BitLockerPartitionInfo(
            partition_index=self._partition_index,
            offset=self._partition_offset,
            size=self._partition_size
        )

    def is_locked(self) -> bool:
        if not self._bitlocker_backend:
            return True
        return self._bitlocker_backend.is_locked()

    def _get_volume_info_dict(self) -> Dict[str, Any]:
        if not self._bitlocker_backend:
            return {}

        vol_info = self._bitlocker_backend.get_volume_info()
        return {
            'encryption_method': vol_info.encryption_method,
            'volume_identifier': vol_info.volume_identifier,
            'decrypted_size': self._bitlocker_backend.get_size(),
            'partition_offset': self._partition_offset,
            'partition_size': self._partition_size
        }

    # ========== 리소스 관리 ==========

    def close(self) -> None:
        if self._bitlocker_backend:
            self._bitlocker_backend.close()
            self._bitlocker_backend = None

        if self._disk_backend:
            try:
                self._disk_backend.close()
            except:
                pass
            self._disk_backend = None

    def __enter__(self) -> 'BitLockerDecryptor':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        self.close()
        return False
