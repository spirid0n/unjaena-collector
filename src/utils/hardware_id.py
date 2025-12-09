"""
Hardware ID Generation Module

Creates a unique hardware identifier for device binding.
"""
import hashlib
import subprocess
import platform


def get_hardware_id() -> str:
    """
    Generate a unique hardware identifier.

    Uses:
    - CPU ID
    - Disk Serial Number
    - MAC Address

    Returns:
        str: SHA256 hash of combined hardware identifiers (first 32 chars)
    """
    try:
        import wmi
        c = wmi.WMI()

        # CPU ID
        cpu = c.Win32_Processor()[0]
        cpu_id = cpu.ProcessorId.strip() if cpu.ProcessorId else ''

        # Disk Serial
        disk = c.Win32_DiskDrive()[0]
        disk_serial = disk.SerialNumber.strip() if disk.SerialNumber else ''

        # MAC Address
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            mac = nic.MACAddress
            if mac:
                break
        else:
            mac = ''

        # Combine and hash
        combined = f"{cpu_id}-{disk_serial}-{mac}"
        return hashlib.sha256(combined.encode()).hexdigest()[:32]

    except Exception as e:
        # Fallback: use hostname + platform info
        fallback = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
        return hashlib.sha256(fallback.encode()).hexdigest()[:32]


def get_system_info() -> dict:
    """
    Get system information for logging.

    Returns:
        dict: System information
    """
    try:
        import wmi
        c = wmi.WMI()

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
        }
    except Exception as e:
        return {
            'hostname': platform.node(),
            'platform': platform.platform(),
            'hardware_id': get_hardware_id(),
            'error': str(e),
        }
