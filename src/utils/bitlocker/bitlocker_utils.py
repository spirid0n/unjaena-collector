# -*- coding: utf-8 -*-
"""
BitLocker Utilities - BitLocker 볼륨 감지 및 유틸리티 함수

수집 도구에서 BitLocker 암호화 볼륨을 감지하고 처리하기 위한 유틸리티.
"""

import struct
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class BitLockerVolumeDetectionResult:
    """BitLocker 볼륨 감지 결과"""
    is_encrypted: bool = False
    partition_index: int = 0
    partition_offset: int = 0
    partition_size: int = 0
    encryption_method: str = ""
    drive_letter: str = ""
    error: Optional[str] = None


def detect_bitlocker_on_system_drive() -> BitLockerVolumeDetectionResult:
    """
    시스템 드라이브(일반적으로 C:)에서 BitLocker 암호화 감지

    Returns:
        BitLockerVolumeDetectionResult
    """
    import sys
    if sys.platform != 'win32':
        return BitLockerVolumeDetectionResult(
            is_encrypted=False,
            error="BitLocker detection only supported on Windows"
        )

    try:
        # WMI를 통한 BitLocker 상태 확인
        result = _check_bitlocker_via_wmi()
        if result:
            return result

        # WMI 실패 시 직접 디스크 확인
        return _check_bitlocker_direct()

    except Exception as e:
        logger.error(f"BitLocker detection failed: {e}")
        return BitLockerVolumeDetectionResult(
            is_encrypted=False,
            error=str(e)
        )


def _check_bitlocker_via_wmi() -> Optional[BitLockerVolumeDetectionResult]:
    """WMI를 통한 BitLocker 상태 확인"""
    try:
        import wmi
        c = wmi.WMI(namespace="root\\cimv2\\Security\\MicrosoftVolumeEncryption")

        for volume in c.Win32_EncryptableVolume():
            protection_status = volume.ProtectionStatus
            drive_letter = volume.DriveLetter

            # ProtectionStatus: 0=Off, 1=On, 2=Unknown
            if protection_status == 1:
                return BitLockerVolumeDetectionResult(
                    is_encrypted=True,
                    drive_letter=drive_letter or "C:",
                    encryption_method=_get_encryption_method_wmi(volume)
                )

        return None

    except ImportError:
        logger.debug("WMI module not available, falling back to direct check")
        return None
    except Exception as e:
        logger.debug(f"WMI BitLocker check failed: {e}")
        return None


def _get_encryption_method_wmi(volume) -> str:
    """WMI 볼륨에서 암호화 방식 조회"""
    try:
        method_code = volume.EncryptionMethod
        methods = {
            0: "None",
            1: "AES-128-CBC + Diffuser",
            2: "AES-256-CBC + Diffuser",
            3: "AES-128-CBC",
            4: "AES-256-CBC",
            5: "AES-128-XTS",
            6: "AES-256-XTS",
            7: "XTS-AES-128",
            8: "XTS-AES-256"
        }
        return methods.get(method_code, f"Unknown ({method_code})")
    except:
        return "Unknown"


def _check_bitlocker_direct() -> BitLockerVolumeDetectionResult:
    """물리 디스크를 직접 읽어서 BitLocker 감지"""
    try:
        from .disk_backends import PhysicalDiskBackend

        # PhysicalDrive0 (시스템 디스크) 확인
        backend = PhysicalDiskBackend(0)

        try:
            # MBR 읽기
            mbr = backend.read(0, 512)
            if len(mbr) < 512:
                return BitLockerVolumeDetectionResult(is_encrypted=False)

            # MBR 시그니처 확인
            signature = struct.unpack('<H', mbr[510:512])[0]
            if signature != 0xAA55:
                # GPT 디스크 처리
                return _check_bitlocker_gpt(backend)

            # MBR 파티션 확인
            for i in range(4):
                entry_offset = 446 + i * 16
                entry = mbr[entry_offset:entry_offset + 16]

                partition_type = entry[4]
                if partition_type == 0:
                    continue

                lba_start = struct.unpack('<I', entry[8:12])[0]
                sector_count = struct.unpack('<I', entry[12:16])[0]
                partition_offset = lba_start * 512
                partition_size = sector_count * 512

                # VBR에서 BitLocker 시그니처 확인
                vbr = backend.read(partition_offset, 512)
                if _is_bitlocker_vbr(vbr):
                    return BitLockerVolumeDetectionResult(
                        is_encrypted=True,
                        partition_index=i,
                        partition_offset=partition_offset,
                        partition_size=partition_size
                    )

            return BitLockerVolumeDetectionResult(is_encrypted=False)

        finally:
            backend.close()

    except Exception as e:
        logger.warning(f"Direct BitLocker check failed: {e}")
        return BitLockerVolumeDetectionResult(
            is_encrypted=False,
            error=str(e)
        )


def _check_bitlocker_gpt(backend) -> BitLockerVolumeDetectionResult:
    """GPT 디스크에서 BitLocker 감지"""
    try:
        # GPT 헤더 (LBA 1)
        gpt_header = backend.read(512, 512)

        if gpt_header[:8] != b'EFI PART':
            return BitLockerVolumeDetectionResult(is_encrypted=False)

        # 파티션 엔트리 시작 LBA
        entries_lba = struct.unpack('<Q', gpt_header[72:80])[0]
        num_entries = struct.unpack('<I', gpt_header[80:84])[0]
        entry_size = struct.unpack('<I', gpt_header[84:88])[0]

        # 파티션 엔트리 읽기
        entries_offset = entries_lba * 512
        entries_data = backend.read(entries_offset, num_entries * entry_size)

        for i in range(min(num_entries, 128)):  # 최대 128개 확인
            entry_offset = i * entry_size
            entry = entries_data[entry_offset:entry_offset + entry_size]

            # 파티션 타입 GUID (offset 0-16)
            type_guid = entry[:16]

            # 빈 엔트리 스킵
            if type_guid == b'\x00' * 16:
                continue

            # 파티션 오프셋 및 크기
            first_lba = struct.unpack('<Q', entry[32:40])[0]
            last_lba = struct.unpack('<Q', entry[40:48])[0]
            partition_offset = first_lba * 512
            partition_size = (last_lba - first_lba + 1) * 512

            # VBR에서 BitLocker 시그니처 확인
            vbr = backend.read(partition_offset, 512)
            if _is_bitlocker_vbr(vbr):
                return BitLockerVolumeDetectionResult(
                    is_encrypted=True,
                    partition_index=i,
                    partition_offset=partition_offset,
                    partition_size=partition_size
                )

        return BitLockerVolumeDetectionResult(is_encrypted=False)

    except Exception as e:
        logger.warning(f"GPT BitLocker check failed: {e}")
        return BitLockerVolumeDetectionResult(is_encrypted=False, error=str(e))


def _is_bitlocker_vbr(vbr: bytes) -> bool:
    """VBR이 BitLocker 암호화되었는지 확인"""
    if len(vbr) < 512:
        return False

    # BitLocker 시그니처: "-FVE-FS-" at offset 3
    return vbr[3:11] == b'-FVE-FS-'


def detect_bitlocker_partitions(drive_number: int = 0) -> List[Dict[str, Any]]:
    """
    지정된 물리 드라이브에서 모든 BitLocker 암호화 파티션 감지

    Args:
        drive_number: 물리 드라이브 번호

    Returns:
        BitLocker 파티션 정보 리스트
    """
    from .disk_backends import PhysicalDiskBackend

    partitions = []

    try:
        backend = PhysicalDiskBackend(drive_number)

        try:
            # MBR 읽기
            mbr = backend.read(0, 512)

            # MBR 시그니처 확인
            signature = struct.unpack('<H', mbr[510:512])[0]

            if signature == 0xAA55:
                # MBR 파티션 테이블
                for i in range(4):
                    entry_offset = 446 + i * 16
                    entry = mbr[entry_offset:entry_offset + 16]

                    partition_type = entry[4]
                    if partition_type == 0:
                        continue

                    lba_start = struct.unpack('<I', entry[8:12])[0]
                    sector_count = struct.unpack('<I', entry[12:16])[0]
                    partition_offset = lba_start * 512
                    partition_size = sector_count * 512

                    vbr = backend.read(partition_offset, 512)
                    is_bitlocker = _is_bitlocker_vbr(vbr)

                    partitions.append({
                        'index': i,
                        'offset': partition_offset,
                        'size': partition_size,
                        'is_bitlocker': is_bitlocker,
                        'filesystem': 'BitLocker' if is_bitlocker else _detect_filesystem(vbr)
                    })
            else:
                # GPT 디스크 처리 (간략화)
                logger.info("GPT disk detected - scanning partitions")

        finally:
            backend.close()

    except Exception as e:
        logger.error(f"Failed to detect BitLocker partitions: {e}")

    return partitions


def _detect_filesystem(vbr: bytes) -> str:
    """VBR에서 파일시스템 감지"""
    if len(vbr) < 512:
        return "Unknown"

    if vbr[3:11] == b'-FVE-FS-':
        return "BitLocker"
    if vbr[3:7] == b'NTFS':
        return "NTFS"
    if vbr[82:90] == b'FAT32   ':
        return "FAT32"
    if vbr[3:11] == b'EXFAT   ':
        return "exFAT"

    return "Unknown"


def is_pybde_installed() -> bool:
    """pybde (libbde-python) 설치 여부 확인"""
    try:
        import pybde
        return True
    except ImportError:
        return False


def format_recovery_password(raw_input: str) -> str:
    """
    복구 키 입력값을 표준 형식으로 변환

    입력: "123456234567345678..." 또는 "123456-234567-345678-..."
    출력: "123456-234567-345678-456789-567890-678901-789012-890123"
    """
    # 숫자만 추출
    digits = ''.join(c for c in raw_input if c.isdigit())

    if len(digits) != 48:
        raise ValueError(
            f"Recovery password must be 48 digits, got {len(digits)}"
        )

    # 6자리씩 그룹화
    groups = [digits[i:i+6] for i in range(0, 48, 6)]
    return '-'.join(groups)


def validate_recovery_password(password: str) -> bool:
    """복구 키 형식 검증"""
    try:
        format_recovery_password(password)
        return True
    except ValueError:
        return False
