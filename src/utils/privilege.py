"""
Privilege Management Module

Handles Windows administrator privilege checks and elevation.
"""
import sys
import ctypes
import os


def is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_as_admin():
    """Restart the application with administrator privileges."""
    if sys.platform == 'win32':
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            " ".join([f'"{arg}"' for arg in sys.argv]),
            None,
            1  # SW_SHOWNORMAL
        )


def get_current_user() -> str:
    """Get the current Windows username."""
    return os.getlogin()


def get_computer_name() -> str:
    """Get the computer name."""
    return os.environ.get('COMPUTERNAME', 'UNKNOWN')
