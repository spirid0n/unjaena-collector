"""
Hardware ID Generation Module

Creates a unique hardware identifier for device binding.
P0 보안 강화: 다중 하드웨어 요소 수집으로 변조 방지
"""
import hashlib
import subprocess
import platform
from typing import Dict, Optional, Tuple


class HardwareIdError(Exception):
    """하드웨어 ID 생성 오류"""
    pass


def _get_wmi():
    """WMI 객체 반환"""
    try:
        import wmi
        return wmi.WMI()
    except ImportError:
        raise HardwareIdError("WMI 모듈이 설치되지 않았습니다")
    except Exception as e:
        raise HardwareIdError(f"WMI 초기화 실패: {e}")


def get_cpu_id() -> Optional[str]:
    """CPU ID 조회"""
    try:
        c = _get_wmi()
        cpu = c.Win32_Processor()[0]
        cpu_id = cpu.ProcessorId.strip() if cpu.ProcessorId else None
        return cpu_id if cpu_id else None
    except Exception:
        return None


def get_disk_serial() -> Optional[str]:
    """디스크 시리얼 번호 조회"""
    try:
        c = _get_wmi()
        disk = c.Win32_DiskDrive()[0]
        serial = disk.SerialNumber.strip() if disk.SerialNumber else None
        return serial if serial else None
    except Exception:
        return None


def get_mac_address() -> Optional[str]:
    """MAC 주소 조회"""
    try:
        c = _get_wmi()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            mac = nic.MACAddress
            if mac:
                return mac
        return None
    except Exception:
        return None


def get_bios_serial() -> Optional[str]:
    """BIOS 시리얼 번호 조회 (P0 추가)"""
    try:
        c = _get_wmi()
        bios = c.Win32_BIOS()[0]
        serial = bios.SerialNumber.strip() if bios.SerialNumber else None
        # 가상화 환경에서 'None' 또는 'To Be Filled' 등 제외
        if serial and serial.lower() not in ['none', 'to be filled by o.e.m.', 'default string']:
            return serial
        return None
    except Exception:
        return None


def get_baseboard_serial() -> Optional[str]:
    """메인보드 시리얼 번호 조회 (P0 추가)"""
    try:
        c = _get_wmi()
        board = c.Win32_BaseBoard()[0]
        serial = board.SerialNumber.strip() if board.SerialNumber else None
        if serial and serial.lower() not in ['none', 'to be filled by o.e.m.', 'default string']:
            return serial
        return None
    except Exception:
        return None


def get_volume_serial() -> Optional[str]:
    """C 드라이브 볼륨 시리얼 번호 조회 (P0 추가)"""
    try:
        c = _get_wmi()
        for vol in c.Win32_LogicalDisk():
            if vol.DeviceID == 'C:':
                serial = vol.VolumeSerialNumber
                return serial if serial else None
        return None
    except Exception:
        return None


def get_hardware_components() -> Dict[str, Optional[str]]:
    """
    모든 하드웨어 식별자 수집 (P0 보안 강화)

    Returns:
        dict: 각 하드웨어 구성요소의 식별자
    """
    return {
        'cpu_id': get_cpu_id(),
        'disk_serial': get_disk_serial(),
        'mac_address': get_mac_address(),
        'bios_serial': get_bios_serial(),
        'baseboard_serial': get_baseboard_serial(),
        'volume_serial': get_volume_serial(),
    }


def get_hardware_id(require_minimum: int = 3) -> str:
    """
    Generate a unique hardware identifier.
    P0 보안 강화: 다중 요소 수집 및 최소 요건 검증

    Uses:
    - CPU ID
    - Disk Serial Number
    - MAC Address
    - BIOS Serial Number (추가)
    - Baseboard Serial Number (추가)
    - Volume Serial Number (추가)

    Args:
        require_minimum: 최소 유효 구성요소 수 (기본 3)

    Returns:
        str: SHA256 hash of combined hardware identifiers (first 32 chars)

    Raises:
        HardwareIdError: 최소 요건 미충족 시
    """
    try:
        components = get_hardware_components()

        # 유효한 구성요소만 필터링
        valid_components = {k: v for k, v in components.items() if v}

        if len(valid_components) < require_minimum:
            raise HardwareIdError(
                f"충분한 하드웨어 식별자를 수집할 수 없습니다. "
                f"필요: {require_minimum}개, 수집됨: {len(valid_components)}개 "
                f"(수집된 요소: {list(valid_components.keys())})"
            )

        # 정렬된 값으로 해시 생성 (일관성 유지)
        combined = '-'.join(sorted(valid_components.values()))
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    except HardwareIdError:
        raise
    except Exception as e:
        # [보안 경고] Fallback 사용 - 약한 하드웨어 바인딩
        import logging
        logger = logging.getLogger(__name__)
        logger.error(
            f"[HardwareID] WMI 접근 실패 - 약한 fallback 사용됨!\n"
            f"  원인: {e}\n"
            f"  위험: 하드웨어 바인딩이 약해져 보안이 저하될 수 있습니다.\n"
            f"  해결: WMI 서비스 활성화 또는 관리자 권한 실행 필요"
        )
        print("=" * 50)
        print("[보안 경고] 하드웨어 ID 생성에 fallback 사용됨")
        print("  WMI 접근이 필요합니다. 관리자 권한으로 실행하세요.")
        print("=" * 50)
        fallback = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        return hashlib.sha256(fallback.encode()).hexdigest()[:32]


def get_hardware_id_with_components(require_minimum: int = 3) -> Tuple[str, Dict[str, Optional[str]]]:
    """
    하드웨어 ID와 개별 구성요소 반환 (서버 바인딩용)

    Returns:
        tuple: (hardware_id, components_dict)
    """
    components = get_hardware_components()
    valid_components = {k: v for k, v in components.items() if v}

    if len(valid_components) < require_minimum:
        raise HardwareIdError(
            f"충분한 하드웨어 식별자를 수집할 수 없습니다. "
            f"필요: {require_minimum}개, 수집됨: {len(valid_components)}개"
        )

    combined = '-'.join(sorted(valid_components.values()))
    hardware_id = hashlib.sha256(combined.encode()).hexdigest()[:32]

    return hardware_id, components


def get_system_info() -> dict:
    """
    Get system information for logging.

    Returns:
        dict: System information
    """
    try:
        c = _get_wmi()

        os_info = c.Win32_OperatingSystem()[0]
        cpu_info = c.Win32_Processor()[0]

        return {
            'os_name': os_info.Caption,
            'os_version': os_info.Version,
            'cpu_name': cpu_info.Name,
            'cpu_cores': cpu_info.NumberOfCores,
            'hostname': platform.node(),
            'platform': platform.platform(),
            'hardware_id': get_hardware_id(),
            'hardware_components': get_hardware_components(),  # P0 추가
        }
    except Exception as e:
        return {
            'hostname': platform.node(),
            'platform': platform.platform(),
            'hardware_id': get_hardware_id(),
            'error': str(e),
        }
