#!/usr/bin/env python3
"""
Digital Forensics Collector - Main Entry Point

This tool collects forensic artifacts from Windows systems
and uploads them to the forensics server for analysis.
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt

from gui.app import CollectorWindow
from utils.privilege import is_admin, run_as_admin


# Configuration
CONFIG = {
    'server_url': 'http://localhost:8000',
    'ws_url': 'ws://localhost:8000',
    'version': '1.0.0',
    'app_name': 'Digital Forensics Collector',
}


def check_admin_privilege():
    """Check if running as administrator"""
    if not is_admin():
        reply = QMessageBox.question(
            None,
            "Administrator Required",
            "This tool requires administrator privileges to collect forensic artifacts.\n\n"
            "Do you want to restart as administrator?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            run_as_admin()
        sys.exit(0)


def main():
    """Main entry point"""
    # High DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName(CONFIG['app_name'])
    app.setApplicationVersion(CONFIG['version'])

    # Check admin privilege
    check_admin_privilege()

    # Create and show main window
    window = CollectorWindow(CONFIG)
    window.show()

    sys.exit(app.exec())


if __name__ == '__main__':
    main()
