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


def run_as_admin() -> bool:
    """
    Restart the application with administrator privileges.

    Returns:
        bool: True if elevation was requested, False otherwise
    """
    if sys.platform != 'win32':
        return False

    try:
        # Handle PyInstaller frozen executable
        if getattr(sys, 'frozen', False):
            # Running as compiled EXE
            executable = sys.executable
            # For frozen apps, sys.argv[0] is the exe path
            args = sys.argv[1:] if len(sys.argv) > 1 else []
        else:
            # Running as script
            executable = sys.executable
            args = sys.argv

        # Build argument string
        if args:
            arg_string = " ".join([f'"{arg}"' for arg in args])
        else:
            arg_string = ""

        # Request elevation via ShellExecuteW
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            executable,
            arg_string,
            None,
            1  # SW_SHOWNORMAL
        )

        # ShellExecuteW returns > 32 on success
        return result > 32
    except Exception as e:
        print(f"Failed to request elevation: {e}")
        return False


def get_current_user() -> str:
    """Get the current Windows username."""
    return os.getlogin()


def get_computer_name() -> str:
    """Get the computer name."""
    return os.environ.get('COMPUTERNAME', 'UNKNOWN')
