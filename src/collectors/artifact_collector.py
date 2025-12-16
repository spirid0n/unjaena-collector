"""
Artifact Collector Module

디지털 포렌식 아티팩트 수집 모듈.
MFT (Master File Table) 기반 수집을 우선 사용하며,
MFT 사용이 불가능한 경우 레거시 방식으로 폴백합니다.

수집 방식:
- MFT 기반: pytsk3를 이용한 raw disk 접근 (권장)
- 레거시: glob.glob + shutil.copy2 (폴백)

Note: MFT 기반 수집은 관리자 권한 필요
"""
import os
import glob
import shutil
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Generator, Tuple, Dict, Any, Optional, List

# Try to import MFT collector
try:
    from collectors.mft_collector import (
        MFTCollector, MFT_ARTIFACT_TYPES,
        is_mft_available, check_admin_privileges
    )
    MFT_AVAILABLE = is_mft_available()
except ImportError:
    MFT_AVAILABLE = False
    MFTCollector = None

# Try to import Memory collector
try:
    from collectors.memory_collector import (
        MemoryCollector, MEMORY_ARTIFACT_TYPES,
        is_admin as is_memory_admin,
        get_winpmem_path, VOLATILITY_AVAILABLE
    )
    MEMORY_AVAILABLE = get_winpmem_path() is not None
except ImportError:
    MEMORY_AVAILABLE = False
    MEMORY_ARTIFACT_TYPES = {}
    VOLATILITY_AVAILABLE = False

# Try to import Android collector
try:
    from collectors.android_collector import (
        AndroidCollector, ANDROID_ARTIFACT_TYPES,
        ADBDeviceMonitor, DeviceInfo,
        check_adb_available, ADB_AVAILABLE
    )
except ImportError:
    ADB_AVAILABLE = False
    ANDROID_ARTIFACT_TYPES = {}
    AndroidCollector = None
    ADBDeviceMonitor = None
    DeviceInfo = None

# Try to import iOS collector
try:
    from collectors.ios_collector import (
        iOSCollector, IOS_ARTIFACT_TYPES,
        find_ios_backups, BackupInfo, BIPLIST_AVAILABLE
    )
    IOS_AVAILABLE = True
except ImportError:
    IOS_AVAILABLE = False
    IOS_ARTIFACT_TYPES = {}
    iOSCollector = None
    find_ios_backups = None
    BackupInfo = None


# Artifact type definitions
ARTIFACT_TYPES = {
    'prefetch': {
        'name': 'Prefetch Files',
        'description': 'Program execution history',
        'paths': [r'C:\Windows\Prefetch\*.pf'],
        'mft_config': {
            'base_path': 'Windows/Prefetch',
            'pattern': '*.pf',
        },
        'requires_admin': True,
        'collector': 'collect_glob',
    },
    'eventlog': {
        'name': 'Event Logs',
        'description': 'Windows event logs (Security, System, Application)',
        'paths': [
            r'C:\Windows\System32\winevt\Logs\Security.evtx',
            r'C:\Windows\System32\winevt\Logs\System.evtx',
            r'C:\Windows\System32\winevt\Logs\Application.evtx',
            r'C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx',
        ],
        'mft_config': {
            'base_path': 'Windows/System32/winevt/Logs',
            'pattern': '*.evtx',
        },
        'requires_admin': True,
        'collector': 'collect_files',
    },
    'registry': {
        'name': 'Registry Hives',
        'description': 'System registry hives (SYSTEM, SOFTWARE, SAM)',
        'paths': [
            r'C:\Windows\System32\config\SYSTEM',
            r'C:\Windows\System32\config\SOFTWARE',
            r'C:\Windows\System32\config\SAM',
            r'C:\Windows\System32\config\SECURITY',
        ],
        'mft_config': {
            'base_path': 'Windows/System32/config',
            'files': ['SYSTEM', 'SOFTWARE', 'SAM', 'SECURITY'],
        },
        'requires_admin': True,
        'collector': 'collect_locked_files',
    },
    'amcache': {
        'name': 'Amcache',
        'description': 'Application compatibility cache',
        'paths': [r'C:\Windows\AppCompat\Programs\Amcache.hve'],
        'mft_config': {
            'base_path': 'Windows/AppCompat/Programs',
            'files': ['Amcache.hve'],
        },
        'requires_admin': True,
        'collector': 'collect_locked_files',
    },
    'userassist': {
        'name': 'UserAssist',
        'description': 'User activity tracking (NTUSER.DAT)',
        'paths': [],  # Dynamic paths per user
        'mft_config': {
            'user_path': 'NTUSER.DAT',
        },
        'requires_admin': False,
        'collector': 'collect_ntuser',
    },
    'browser': {
        'name': 'Browser Data',
        'description': 'Chrome, Edge, Firefox history, downloads, and cookies',
        'browsers': {
            'chrome': {
                'name': 'Google Chrome',
                'paths': [
                    r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\History',
                    r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Downloads',
                    r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies',
                    r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data',
                ],
                'mft_path': 'AppData/Local/Google/Chrome/User Data/Default',
                'files': ['History', 'Downloads', 'Cookies', 'Login Data'],
            },
            'edge': {
                'name': 'Microsoft Edge',
                'paths': [
                    r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History',
                    r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Downloads',
                    r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies',
                    r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data',
                ],
                'mft_path': 'AppData/Local/Microsoft/Edge/User Data/Default',
                'files': ['History', 'Downloads', 'Cookies', 'Login Data'],
            },
            'firefox': {
                'name': 'Mozilla Firefox',
                'paths': [
                    r'%APPDATA%\Mozilla\Firefox\Profiles\*\places.sqlite',
                    r'%APPDATA%\Mozilla\Firefox\Profiles\*\cookies.sqlite',
                    r'%APPDATA%\Mozilla\Firefox\Profiles\*\logins.json',
                    r'%APPDATA%\Mozilla\Firefox\Profiles\*\formhistory.sqlite',
                ],
                'mft_path': 'AppData/Roaming/Mozilla/Firefox/Profiles',
                'files': ['places.sqlite', 'cookies.sqlite', 'logins.json', 'formhistory.sqlite'],
                'profile_based': True,
            },
        },
        'requires_admin': False,
        'collector': 'collect_all_browsers',
    },
    # Legacy aliases for backward compatibility
    'browser_chrome': {
        'name': 'Chrome Browser (Legacy)',
        'description': 'Alias for browser - Chrome only',
        'alias_of': 'browser',
        'filter_browser': 'chrome',
    },
    'browser_edge': {
        'name': 'Edge Browser (Legacy)',
        'description': 'Alias for browser - Edge only',
        'alias_of': 'browser',
        'filter_browser': 'edge',
    },
    'recent': {
        'name': 'Recent Documents',
        'description': 'Recently accessed files',
        'paths': [r'%APPDATA%\Microsoft\Windows\Recent\*.lnk'],
        'mft_config': {
            'user_path': 'AppData/Roaming/Microsoft/Windows/Recent',
            'pattern': '*.lnk',
        },
        'requires_admin': False,
        'collector': 'collect_user_glob',
    },
    'recycle_bin': {
        'name': 'Recycle Bin',
        'description': 'Deleted files metadata',
        'paths': [r'C:\$Recycle.Bin\*\$I*'],
        'mft_config': {
            'base_path': '$Recycle.Bin',
            'pattern': '$I*',
            'recursive': True,
        },
        'requires_admin': True,
        'collector': 'collect_glob',
    },
    # Legacy alias for backward compatibility
    'recyclebin': {
        'name': 'Recycle Bin (Legacy)',
        'description': 'Alias for recycle_bin',
        'alias_of': 'recycle_bin',
    },
    'usb': {
        'name': 'USB History',
        'description': 'USB device connection history',
        'paths': [
            r'C:\Windows\INF\setupapi.dev.log',
        ],
        'mft_config': {
            'base_path': 'Windows/INF',
            'files': ['setupapi.dev.log'],
        },
        'requires_admin': True,
        'collector': 'collect_files',
    },
    'srum': {
        'name': 'SRUM Database',
        'description': 'System Resource Usage Monitor',
        'paths': [r'C:\Windows\System32\sru\SRUDB.dat'],
        'mft_config': {
            'base_path': 'Windows/System32/sru',
            'files': ['SRUDB.dat'],
        },
        'requires_admin': True,
        'collector': 'collect_locked_files',
    },
    # MFT-specific artifacts (only available with MFT collection)
    'mft': {
        'name': 'Master File Table',
        'description': 'NTFS MFT containing all file metadata',
        'paths': [],  # Not collectable via legacy method
        'mft_config': {
            'special': 'collect_mft_raw',
        },
        'requires_admin': True,
        'requires_mft': True,
        'collector': None,
    },
    'usn_journal': {
        'name': 'USN Journal',
        'description': 'File change journal ($UsnJrnl:$J)',
        'paths': [],  # Not collectable via legacy method
        'mft_config': {
            'special': 'collect_usn_journal',
        },
        'requires_admin': True,
        'requires_mft': True,
        'collector': None,
    },
    'logfile': {
        'name': 'NTFS $LogFile',
        'description': 'NTFS Transaction Log - metadata change history',
        'paths': [],  # Not collectable via legacy method
        'mft_config': {
            'special': 'collect_logfile',
        },
        'requires_admin': True,
        'requires_mft': True,
        'collector': None,
        'forensic_value': 'defense_evasion detection, file creation/deletion timeline',
    },

    # =========================================================================
    # Memory Forensics Artifacts (Phase 2.1)
    # =========================================================================
    'memory_dump': {
        'name': 'Memory Dump',
        'description': 'Full physical memory acquisition using WinPmem',
        'paths': [],
        'category': 'memory',
        'requires_admin': True,
        'requires_memory': True,
        'collector': 'collect_memory_dump',
    },
    'memory_process': {
        'name': 'Process List',
        'description': 'Running processes from memory (Volatility3 pslist)',
        'paths': [],
        'category': 'memory',
        'requires_admin': True,
        'requires_memory': True,
        'requires_volatility': True,
        'collector': 'collect_memory_analysis',
        'analysis_type': 'process',
    },
    'memory_network': {
        'name': 'Network Connections',
        'description': 'Active network connections from memory (Volatility3 netstat)',
        'paths': [],
        'category': 'memory',
        'requires_admin': True,
        'requires_memory': True,
        'requires_volatility': True,
        'collector': 'collect_memory_analysis',
        'analysis_type': 'network',
    },
    'memory_module': {
        'name': 'Loaded Modules',
        'description': 'DLLs and modules loaded in memory (Volatility3 dlllist)',
        'paths': [],
        'category': 'memory',
        'requires_admin': True,
        'requires_memory': True,
        'requires_volatility': True,
        'collector': 'collect_memory_analysis',
        'analysis_type': 'module',
    },
    'memory_handle': {
        'name': 'Handles',
        'description': 'Open handles (files, registry, etc.)',
        'paths': [],
        'category': 'memory',
        'requires_admin': True,
        'requires_memory': True,
        'requires_volatility': True,
        'collector': 'collect_memory_analysis',
        'analysis_type': 'handle',
    },
    'memory_registry': {
        'name': 'Registry Hives (Memory)',
        'description': 'Registry hives loaded in memory',
        'paths': [],
        'category': 'memory',
        'requires_admin': True,
        'requires_memory': True,
        'requires_volatility': True,
        'collector': 'collect_memory_analysis',
        'analysis_type': 'registry',
    },
    'memory_credential': {
        'name': 'Credentials',
        'description': 'Password hashes and credentials from memory',
        'paths': [],
        'category': 'memory',
        'requires_admin': True,
        'requires_memory': True,
        'requires_volatility': True,
        'collector': 'collect_memory_analysis',
        'analysis_type': 'credential',
    },
    'memory_malware': {
        'name': 'Malware Detection',
        'description': 'Suspicious memory regions and injected code (malfind + YARA)',
        'paths': [],
        'category': 'memory',
        'requires_admin': True,
        'requires_memory': True,
        'requires_volatility': True,
        'collector': 'collect_memory_analysis',
        'analysis_type': 'malware',
    },

    # =========================================================================
    # Android Forensics Artifacts (Phase 2.1)
    # =========================================================================
    'mobile_android_sms': {
        'name': 'Android SMS/MMS',
        'description': 'Text messages and multimedia messages',
        'paths': [],
        'category': 'android',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'sms',
    },
    'mobile_android_call': {
        'name': 'Android Call History',
        'description': 'Incoming, outgoing, and missed calls',
        'paths': [],
        'category': 'android',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'call',
    },
    'mobile_android_contacts': {
        'name': 'Android Contacts',
        'description': 'Contact list and details',
        'paths': [],
        'category': 'android',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'contacts',
    },
    'mobile_android_app': {
        'name': 'Android App Data',
        'description': 'Installed applications and their data',
        'paths': [],
        'category': 'android',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'app',
    },
    'mobile_android_wifi': {
        'name': 'Android WiFi Settings',
        'description': 'Saved WiFi networks and credentials',
        'paths': [],
        'category': 'android',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'wifi',
    },
    'mobile_android_location': {
        'name': 'Android Location History',
        'description': 'GPS and location data',
        'paths': [],
        'category': 'android',
        'requires_adb': True,
        'requires_root': True,
        'collector': 'collect_android',
        'artifact_key': 'location',
    },
    'mobile_android_media': {
        'name': 'Android Media Files',
        'description': 'Photos, videos, and audio files from DCIM/Pictures/Download',
        'paths': [],
        'category': 'android',
        'requires_adb': True,
        'requires_root': False,
        'collector': 'collect_android',
        'artifact_key': 'media',
    },

    # =========================================================================
    # iOS Forensics Artifacts (Phase 2.1)
    # =========================================================================
    'mobile_ios_sms': {
        'name': 'iOS iMessage/SMS',
        'description': 'Text messages and iMessages from iTunes/Finder backup',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'sms',
    },
    'mobile_ios_call': {
        'name': 'iOS Call History',
        'description': 'Phone call records from backup',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'call',
    },
    'mobile_ios_contacts': {
        'name': 'iOS Contacts',
        'description': 'Address book contacts from backup',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'contacts',
    },
    'mobile_ios_app': {
        'name': 'iOS App Data',
        'description': 'Application data and preferences from backup',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'app',
    },
    'mobile_ios_safari': {
        'name': 'iOS Safari',
        'description': 'Browser history, bookmarks, and tabs from backup',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'safari',
    },
    'mobile_ios_location': {
        'name': 'iOS Location History',
        'description': 'GPS and location data from backup',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'location',
    },
    'mobile_ios_backup': {
        'name': 'iOS Backup Metadata',
        'description': 'Backup configuration and device info (Info.plist, Manifest.plist)',
        'paths': [],
        'category': 'ios',
        'requires_backup': True,
        'collector': 'collect_ios',
        'artifact_key': 'backup',
    },
}


class ArtifactCollector:
    """
    Forensic artifact collector with MFT support.

    MFT 기반 수집을 우선 사용하며, 불가능한 경우 레거시 방식으로 폴백합니다.

    MFT 수집의 장점:
    - 삭제된 파일 복구 가능
    - OS 잠금 파일 수집 가능
    - MFT Entry 메타데이터 보존
    - 포렌식 무결성 확보
    """

    def __init__(self, output_dir: str, use_mft: bool = True, volume: str = 'C'):
        """
        Initialize the collector.

        Args:
            output_dir: Directory to store collected artifacts
            use_mft: Whether to use MFT-based collection (default: True)
            volume: Volume to collect from (default: 'C')
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.volume = volume
        self.use_mft = use_mft and MFT_AVAILABLE
        self.mft_collector: Optional[MFTCollector] = None

        # Initialize MFT collector if available
        if self.use_mft:
            try:
                self.mft_collector = MFTCollector(volume, str(output_dir))
                self.collection_mode = 'mft'
            except Exception as e:
                print(f"[WARNING] MFT collection unavailable: {e}")
                print("[INFO] Falling back to legacy collection method")
                self.use_mft = False
                self.collection_mode = 'legacy'
        else:
            self.collection_mode = 'legacy'

    def close(self):
        """Clean up resources"""
        if self.mft_collector:
            self.mft_collector.close()
            self.mft_collector = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def get_available_artifacts(self) -> List[Dict[str, Any]]:
        """
        Get list of available artifact types.

        Returns:
            List of artifact info dictionaries
        """
        artifacts = []
        for type_id, info in ARTIFACT_TYPES.items():
            available = True
            unavailable_reason = None

            # Check if requires MFT
            if info.get('requires_mft', False) and not self.use_mft:
                available = False
                unavailable_reason = 'MFT collection required (pytsk3)'

            # Check if requires Memory (WinPmem)
            if info.get('requires_memory', False) and not MEMORY_AVAILABLE:
                available = False
                unavailable_reason = 'WinPmem not available'

            # Check if requires Volatility
            if info.get('requires_volatility', False) and not VOLATILITY_AVAILABLE:
                available = False
                unavailable_reason = 'Volatility3 not installed'

            # Check if requires ADB
            if info.get('requires_adb', False) and not ADB_AVAILABLE:
                available = False
                unavailable_reason = 'ADB not installed or not in PATH'

            # Check if requires iOS backup
            if info.get('requires_backup', False) and not IOS_AVAILABLE:
                available = False
                unavailable_reason = 'iOS backup support not available'

            artifacts.append({
                'type': type_id,
                'name': info['name'],
                'description': info['description'],
                'category': info.get('category', 'windows'),
                'requires_admin': info.get('requires_admin', False),
                'requires_mft': info.get('requires_mft', False),
                'requires_memory': info.get('requires_memory', False),
                'requires_volatility': info.get('requires_volatility', False),
                'requires_adb': info.get('requires_adb', False),
                'requires_root': info.get('requires_root', False),
                'requires_backup': info.get('requires_backup', False),
                'available': available,
                'unavailable_reason': unavailable_reason,
            })

        return artifacts

    def get_artifacts_by_category(self, category: str) -> List[Dict[str, Any]]:
        """
        Get available artifacts filtered by category.

        Args:
            category: 'windows', 'memory', 'android', or 'ios'

        Returns:
            List of artifact info dictionaries for the category
        """
        all_artifacts = self.get_available_artifacts()
        return [a for a in all_artifacts if a.get('category', 'windows') == category]

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None,
        include_deleted: bool = True,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts of a specific type.

        Args:
            artifact_type: Type of artifact to collect (e.g., 'prefetch')
            progress_callback: Optional callback for progress updates
            include_deleted: Include deleted files (MFT mode only)
            **kwargs: Additional arguments for specific collectors
                - device_serial: Android device serial (for android category)
                - backup_path: iOS backup path (for ios category)
                - memory_dump_path: Path to existing memory dump (for memory analysis)

        Yields:
            Tuple of (file_path, metadata) for each collected file
        """
        if artifact_type not in ARTIFACT_TYPES:
            raise ValueError(f"Unknown artifact type: {artifact_type}")

        artifact_info = ARTIFACT_TYPES[artifact_type]

        # Handle alias types (e.g., browser_chrome -> browser)
        if 'alias_of' in artifact_info:
            actual_type = artifact_info['alias_of']
            browser_filter = artifact_info.get('filter_browser')
            artifact_info = ARTIFACT_TYPES[actual_type]
            artifact_type = actual_type
        else:
            browser_filter = None

        # Get category for routing
        category = artifact_info.get('category', 'windows')

        # Check availability based on category
        if artifact_info.get('requires_mft', False) and not self.use_mft:
            print(f"[WARNING] {artifact_type} requires MFT collection (pytsk3)")
            return

        if artifact_info.get('requires_memory', False) and not MEMORY_AVAILABLE:
            print(f"[WARNING] {artifact_type} requires WinPmem (not available)")
            return

        if artifact_info.get('requires_volatility', False) and not VOLATILITY_AVAILABLE:
            print(f"[WARNING] {artifact_type} requires Volatility3 (not installed)")
            return

        if artifact_info.get('requires_adb', False) and not ADB_AVAILABLE:
            print(f"[WARNING] {artifact_type} requires ADB (not in PATH)")
            return

        if artifact_info.get('requires_backup', False) and not IOS_AVAILABLE:
            print(f"[WARNING] {artifact_type} requires iOS backup support")
            return

        # Create artifact-specific output directory
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        # Route to appropriate collector based on category
        if category == 'memory':
            yield from self._collect_memory(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, **kwargs
            )
        elif category == 'android':
            yield from self._collect_android(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, **kwargs
            )
        elif category == 'ios':
            yield from self._collect_ios(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, **kwargs
            )
        elif artifact_type == 'browser':
            # Special handling for browser type
            yield from self._collect_browsers(
                artifact_info, artifact_dir, progress_callback,
                browser_filter, include_deleted
            )
        elif self.use_mft and self.mft_collector:
            # Use MFT collection if available for Windows artifacts
            yield from self._collect_mft(
                artifact_type, artifact_info, artifact_dir,
                progress_callback, include_deleted
            )
        else:
            yield from self._collect_legacy(
                artifact_type, artifact_info, artifact_dir,
                progress_callback
            )

    def _collect_browsers(
        self,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        browser_filter: Optional[str],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect browser data from Chrome, Edge, and Firefox.

        Args:
            artifact_info: Browser artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            browser_filter: Optional filter for specific browser (e.g., 'chrome')
            include_deleted: Include deleted files (MFT mode only)
        """
        browsers = artifact_info.get('browsers', {})

        for browser_id, browser_config in browsers.items():
            # Skip if filter is set and doesn't match
            if browser_filter and browser_id != browser_filter:
                continue

            browser_name = browser_config.get('name', browser_id)
            browser_dir = artifact_dir / browser_id
            browser_dir.mkdir(exist_ok=True)

            # Use MFT collection if available
            if self.use_mft and self.mft_collector:
                yield from self._collect_browser_mft(
                    browser_id, browser_config, browser_dir,
                    progress_callback, include_deleted
                )
            else:
                yield from self._collect_browser_legacy(
                    browser_id, browser_config, browser_dir,
                    progress_callback
                )

    def _collect_browser_mft(
        self,
        browser_id: str,
        browser_config: Dict[str, Any],
        browser_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect browser data using MFT"""
        browser_name = browser_config.get('name', browser_id)
        mft_path = browser_config.get('mft_path', '')
        files = browser_config.get('files', [])
        profile_based = browser_config.get('profile_based', False)

        users_dir = Path(r'C:\Users')

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue
            if user_dir.name.lower() in ['public', 'default', 'default user', 'all users']:
                continue

            if profile_based:
                # Firefox: search for profiles
                profiles_path = f"Users/{user_dir.name}/{mft_path}"
                try:
                    for result in self.mft_collector.collect_by_pattern(
                        profiles_path, "*.sqlite", "browser", include_deleted
                    ):
                        result[1]['browser'] = browser_name
                        result[1]['browser_id'] = browser_id
                        result[1]['username'] = user_dir.name
                        yield result
                        if progress_callback:
                            progress_callback(result[0])
                except Exception as e:
                    print(f"[MFT BROWSER] Firefox profiles error for {user_dir.name}: {e}")
            else:
                # Chrome/Edge: specific files
                full_base_path = f"Users/{user_dir.name}/{mft_path}"
                for filename in files:
                    file_path = f"{full_base_path}/{filename}"
                    try:
                        for result in self.mft_collector.collect_by_path(
                            file_path, "browser", include_deleted
                        ):
                            result[1]['browser'] = browser_name
                            result[1]['browser_id'] = browser_id
                            result[1]['username'] = user_dir.name
                            yield result
                            if progress_callback:
                                progress_callback(result[0])
                    except Exception as e:
                        print(f"[MFT BROWSER] Error collecting {filename} for {user_dir.name}: {e}")

    def _collect_browser_legacy(
        self,
        browser_id: str,
        browser_config: Dict[str, Any],
        browser_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect browser data using legacy method"""
        browser_name = browser_config.get('name', browser_id)
        profile_based = browser_config.get('profile_based', False)

        if profile_based:
            # Firefox
            yield from self._collect_firefox_profiles(
                browser_config, browser_dir, 'browser', browser_name
            )
        else:
            # Chrome/Edge
            for path_pattern in browser_config.get('paths', []):
                expanded_path = os.path.expandvars(path_pattern)
                src_path = Path(expanded_path)

                if src_path.exists():
                    try:
                        dst_path = browser_dir / src_path.name
                        shutil.copy2(src_path, dst_path)
                        metadata = self._get_metadata(
                            str(src_path), dst_path, 'browser'
                        )
                        metadata['browser'] = browser_name
                        metadata['browser_id'] = browser_id
                        yield str(dst_path), metadata
                        if progress_callback:
                            progress_callback(str(dst_path))
                    except (PermissionError, OSError) as e:
                        print(f"[BROWSER] Cannot access {expanded_path}: {e}")

    def _collect_mft(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts using MFT-based method.
        """
        mft_config = artifact_info.get('mft_config', {})

        # Handle special collection methods
        if 'special' in mft_config:
            method_name = mft_config['special']
            method = getattr(self.mft_collector, method_name)
            result = method()
            if result:
                yield result
                if progress_callback:
                    progress_callback(result[0])
            return

        # Handle user-specific paths
        if 'user_path' in mft_config:
            yield from self._collect_mft_user_paths(
                artifact_type, mft_config, artifact_dir,
                progress_callback, include_deleted
            )
            return

        # Handle pattern-based collection
        base_path = mft_config.get('base_path', '')
        pattern = mft_config.get('pattern', None)
        files = mft_config.get('files', None)

        if pattern:
            # Pattern-based collection
            for result in self.mft_collector.collect_by_pattern(
                base_path, pattern, artifact_type, include_deleted
            ):
                yield result
                if progress_callback:
                    progress_callback(result[0])

        elif files:
            # Specific files collection
            for filename in files:
                file_path = f"{base_path}/{filename}" if base_path else filename
                for result in self.mft_collector.collect_by_path(
                    file_path, artifact_type, include_deleted
                ):
                    yield result
                    if progress_callback:
                        progress_callback(result[0])

    def _collect_mft_user_paths(
        self,
        artifact_type: str,
        mft_config: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        include_deleted: bool
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts from user profile directories using MFT.
        """
        users_dir = Path(r'C:\Users')

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            # Skip system directories
            if user_dir.name.lower() in ['public', 'default', 'default user', 'all users']:
                continue

            user_path = mft_config.get('user_path', '')
            pattern = mft_config.get('pattern', None)
            files = mft_config.get('files', None)

            full_base_path = f"Users/{user_dir.name}/{user_path}"

            try:
                if pattern:
                    for result in self.mft_collector.collect_by_pattern(
                        full_base_path, pattern, artifact_type, include_deleted
                    ):
                        result[1]['username'] = user_dir.name
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

                elif files:
                    for filename in files:
                        file_path = f"{full_base_path}/{filename}"
                        for result in self.mft_collector.collect_by_path(
                            file_path, artifact_type, include_deleted
                        ):
                            result[1]['username'] = user_dir.name
                            yield result
                            if progress_callback:
                                progress_callback(result[0])

                elif user_path:
                    # Single file (like NTUSER.DAT)
                    for result in self.mft_collector.collect_by_path(
                        f"Users/{user_dir.name}/{user_path}",
                        artifact_type, include_deleted
                    ):
                        result[1]['username'] = user_dir.name
                        yield result
                        if progress_callback:
                            progress_callback(result[0])

            except Exception as e:
                print(f"[MFT] Error collecting from {user_dir.name}: {e}")

    def _collect_legacy(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts using legacy file API (fallback).

        Note: This method cannot:
        - Recover deleted files
        - Access locked files
        - Preserve MFT metadata
        """
        collector_method_name = artifact_info.get('collector')
        if not collector_method_name:
            return

        collector_method = getattr(self, collector_method_name)

        for path_pattern in artifact_info['paths']:
            for result in collector_method(path_pattern, artifact_dir, artifact_type):
                # Mark as legacy collection
                result[1]['collection_method'] = 'legacy_file_api'
                result[1]['warning'] = 'Collected via legacy method - limited forensic value'
                yield result
                if progress_callback:
                    progress_callback(result[0])

    def collect_deleted_files(
        self,
        extensions: Optional[List[str]] = None,
        min_size: int = 0,
        max_size: int = 100 * 1024 * 1024
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Scan and collect deleted files (MFT mode only).

        Args:
            extensions: List of file extensions to look for
            min_size: Minimum file size
            max_size: Maximum file size

        Yields:
            Tuple of (file_path, metadata) for each recovered file
        """
        if not self.use_mft or not self.mft_collector:
            print("[WARNING] Deleted file recovery requires MFT collection")
            return

        deleted_dir = self.output_dir / 'deleted_files'
        deleted_dir.mkdir(exist_ok=True)

        for entry_info in self.mft_collector.scan_deleted_files(extensions, min_size, max_size):
            # Try to extract the file
            try:
                file_obj = self.mft_collector.fs.open_meta(inode=entry_info.entry_number)
                for result in self.mft_collector._extract_file(
                    file_obj, "", "deleted_recovery"
                ):
                    yield result
            except Exception as e:
                print(f"[MFT] Cannot recover deleted file {entry_info.filename}: {e}")

    # =========================================================================
    # Legacy Collection Methods (Fallback)
    # =========================================================================

    def collect_glob(
        self,
        pattern: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching a glob pattern (legacy)"""
        for src_path in glob.glob(pattern):
            try:
                dst_path = output_dir / Path(src_path).name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(src_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                print(f"[LEGACY] Cannot access {src_path}: {e}")
                continue

    def collect_files(
        self,
        file_path: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect a specific file (legacy)"""
        src_path = Path(file_path)
        if src_path.exists():
            try:
                dst_path = output_dir / src_path.name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(str(src_path), dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                print(f"[LEGACY] Cannot access {file_path}: {e}")

    def collect_locked_files(
        self,
        file_path: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect files that may be locked by the OS (legacy).

        Uses Volume Shadow Copy or raw file read.
        """
        src_path = Path(file_path)
        if not src_path.exists():
            return

        dst_path = output_dir / src_path.name

        # Try direct copy first
        try:
            shutil.copy2(src_path, dst_path)
            yield str(dst_path), self._get_metadata(str(src_path), dst_path, artifact_type)
            return
        except (PermissionError, OSError):
            pass

        # Try using Volume Shadow Copy
        try:
            vss_path = self._get_vss_path(str(src_path))
            if vss_path and Path(vss_path).exists():
                shutil.copy2(vss_path, dst_path)
                metadata = self._get_metadata(str(src_path), dst_path, artifact_type)
                metadata['collection_method'] = 'vss'
                yield str(dst_path), metadata
                return
        except Exception:
            pass

        print(f"[LEGACY] Cannot collect locked file {file_path}")
        print("[INFO] Consider using MFT collection for locked files")

    def collect_user_files(
        self,
        path_pattern: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files from user profile with environment variable expansion (legacy)"""
        expanded_path = os.path.expandvars(path_pattern)
        src_path = Path(expanded_path)

        if src_path.exists():
            try:
                dst_path = output_dir / src_path.name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(expanded_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                print(f"[LEGACY] Cannot access {expanded_path}: {e}")

    def collect_user_glob(
        self,
        pattern: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching a glob pattern with environment variable expansion (legacy)"""
        expanded_pattern = os.path.expandvars(pattern)
        for src_path in glob.glob(expanded_pattern):
            try:
                dst_path = output_dir / Path(src_path).name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(src_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                print(f"[LEGACY] Cannot access {src_path}: {e}")
                continue

    def collect_ntuser(
        self,
        _: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect NTUSER.DAT files for all users (legacy)"""
        users_dir = Path(r'C:\Users')

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            ntuser_path = user_dir / 'NTUSER.DAT'
            if ntuser_path.exists():
                dst_path = output_dir / f"NTUSER.DAT_{user_dir.name}"

                # NTUSER.DAT is usually locked
                for result in self.collect_locked_files(
                    str(ntuser_path), output_dir, artifact_type
                ):
                    # Rename to include username
                    if Path(result[0]).exists():
                        final_path = output_dir / f"NTUSER.DAT_{user_dir.name}"
                        Path(result[0]).rename(final_path)
                        result[1]['username'] = user_dir.name
                        yield str(final_path), result[1]

    def collect_all_browsers(
        self,
        _: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect browser data from Chrome, Edge, and Firefox (legacy).

        Collects: History, Downloads, Cookies, Login Data
        """
        browser_info = ARTIFACT_TYPES.get('browser', {})
        browsers = browser_info.get('browsers', {})

        for browser_id, browser_config in browsers.items():
            browser_name = browser_config.get('name', browser_id)
            browser_dir = output_dir / browser_id
            browser_dir.mkdir(exist_ok=True)

            # Handle Firefox profile-based structure
            if browser_config.get('profile_based', False):
                yield from self._collect_firefox_profiles(
                    browser_config, browser_dir, artifact_type, browser_name
                )
            else:
                # Chrome/Edge - standard paths
                for path_pattern in browser_config.get('paths', []):
                    expanded_path = os.path.expandvars(path_pattern)
                    src_path = Path(expanded_path)

                    if src_path.exists():
                        try:
                            dst_path = browser_dir / src_path.name
                            shutil.copy2(src_path, dst_path)
                            metadata = self._get_metadata(
                                str(src_path), dst_path, artifact_type
                            )
                            metadata['browser'] = browser_name
                            metadata['browser_id'] = browser_id
                            yield str(dst_path), metadata
                        except (PermissionError, OSError) as e:
                            print(f"[BROWSER] Cannot access {expanded_path}: {e}")

    def _collect_firefox_profiles(
        self,
        browser_config: Dict[str, Any],
        output_dir: Path,
        artifact_type: str,
        browser_name: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect Firefox data from all profiles"""
        firefox_profiles_dir = Path(os.path.expandvars(
            r'%APPDATA%\Mozilla\Firefox\Profiles'
        ))

        if not firefox_profiles_dir.exists():
            return

        for profile_dir in firefox_profiles_dir.iterdir():
            if not profile_dir.is_dir():
                continue

            profile_name = profile_dir.name
            profile_output = output_dir / profile_name
            profile_output.mkdir(exist_ok=True)

            for filename in browser_config.get('files', []):
                src_path = profile_dir / filename
                if src_path.exists():
                    try:
                        dst_path = profile_output / filename
                        shutil.copy2(src_path, dst_path)
                        metadata = self._get_metadata(
                            str(src_path), dst_path, artifact_type
                        )
                        metadata['browser'] = browser_name
                        metadata['browser_id'] = 'firefox'
                        metadata['profile'] = profile_name
                        yield str(dst_path), metadata
                    except (PermissionError, OSError) as e:
                        print(f"[FIREFOX] Cannot access {src_path}: {e}")

    def _get_metadata(
        self,
        src_path: str,
        dst_path: Path,
        artifact_type: str
    ) -> Dict[str, Any]:
        """Generate metadata for a collected file (legacy)"""
        src = Path(src_path)

        # Calculate hash
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(dst_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)
                md5.update(chunk)

        try:
            stat = src.stat()
            timestamps = {
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            }
        except (OSError, ValueError):
            timestamps = {}

        return {
            'artifact_type': artifact_type,
            'original_path': str(src_path),
            'filename': src.name,
            'size': dst_path.stat().st_size,
            'sha256': sha256.hexdigest(),
            'md5': md5.hexdigest(),
            'timestamps': timestamps,
            'collected_at': datetime.utcnow().isoformat(),
            'collection_method': 'legacy_file_api',
        }

    # =========================================================================
    # Memory Forensics Collection Methods
    # =========================================================================

    def _collect_memory(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect memory forensics artifacts.

        Args:
            artifact_type: Type of memory artifact (memory_dump, memory_process, etc.)
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: memory_dump_path for analysis artifacts
        """
        from collectors.memory_collector import MemoryCollector

        memory_dump_path = kwargs.get('memory_dump_path')

        if artifact_type == 'memory_dump':
            # Full memory acquisition
            collector = MemoryCollector(str(artifact_dir))
            try:
                dump_path = artifact_dir / 'memory.raw'
                result = collector.acquire_memory(
                    str(dump_path),
                    progress_callback=lambda cur, tot: progress_callback(f"Memory dump: {cur // (1024*1024)} MB / {tot // (1024*1024)} MB") if progress_callback else None
                )
                metadata = {
                    'artifact_type': artifact_type,
                    'filename': 'memory.raw',
                    'size': result.get('size', 0),
                    'sha256': result.get('hash', {}).get('sha256', ''),
                    'md5': result.get('hash', {}).get('md5', ''),
                    'collected_at': datetime.utcnow().isoformat(),
                    'collection_method': 'winpmem',
                    'system_memory_gb': result.get('system_memory_size', 0) // (1024**3),
                    'acquisition_time_seconds': result.get('acquisition_time', 0),
                }
                yield str(dump_path), metadata
            except Exception as e:
                print(f"[MEMORY] Acquisition failed: {e}")
        else:
            # Memory analysis (requires dump)
            if not memory_dump_path:
                print(f"[MEMORY] {artifact_type} requires memory_dump_path kwarg")
                return

            analysis_type = artifact_info.get('analysis_type', 'process')
            collector = MemoryCollector(str(artifact_dir))

            try:
                results = collector.analyze_memory(
                    memory_dump_path,
                    analysis_types=[analysis_type],
                    progress_callback=progress_callback
                )

                if analysis_type in results:
                    output_file = artifact_dir / f"{analysis_type}_analysis.json"
                    import json
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(results[analysis_type], f, indent=2, ensure_ascii=False)

                    metadata = {
                        'artifact_type': artifact_type,
                        'filename': output_file.name,
                        'analysis_type': analysis_type,
                        'record_count': len(results[analysis_type]) if isinstance(results[analysis_type], list) else 1,
                        'collected_at': datetime.utcnow().isoformat(),
                        'collection_method': 'volatility3',
                        'source_dump': memory_dump_path,
                    }
                    yield str(output_file), metadata
            except Exception as e:
                print(f"[MEMORY] Analysis failed for {analysis_type}: {e}")

    # =========================================================================
    # Android Forensics Collection Methods
    # =========================================================================

    def _collect_android(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect Android forensics artifacts via ADB.

        Args:
            artifact_type: Type of Android artifact
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: device_serial for specific device
        """
        from collectors.android_collector import AndroidCollector

        device_serial = kwargs.get('device_serial')
        artifact_key = artifact_info.get('artifact_key', '')

        try:
            collector = AndroidCollector(device_serial, str(artifact_dir))

            # Map artifact_key to collector method
            method_map = {
                'sms': collector.collect_sms,
                'call': collector.collect_call_history,
                'contacts': collector.collect_contacts,
                'app': collector.collect_app_data,
                'wifi': collector.collect_wifi_settings,
                'location': collector.collect_location_data,
                'media': collector.collect_media_files,
            }

            if artifact_key not in method_map:
                print(f"[ANDROID] Unknown artifact key: {artifact_key}")
                return

            method = method_map[artifact_key]

            for result in method(progress_callback=progress_callback):
                file_path, file_metadata = result
                # Add standard fields
                file_metadata['artifact_type'] = artifact_type
                file_metadata['collection_method'] = 'adb'
                file_metadata['device_serial'] = device_serial or 'auto-detected'
                file_metadata['collected_at'] = datetime.utcnow().isoformat()
                yield file_path, file_metadata

        except Exception as e:
            print(f"[ANDROID] Collection failed for {artifact_type}: {e}")

    # =========================================================================
    # iOS Forensics Collection Methods
    # =========================================================================

    def _collect_ios(
        self,
        artifact_type: str,
        artifact_info: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable],
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect iOS forensics artifacts from iTunes/Finder backup.

        Args:
            artifact_type: Type of iOS artifact
            artifact_info: Artifact configuration
            artifact_dir: Output directory
            progress_callback: Progress callback
            **kwargs: backup_path for specific backup
        """
        from collectors.ios_collector import iOSCollector, find_ios_backups

        backup_path = kwargs.get('backup_path')
        artifact_key = artifact_info.get('artifact_key', '')

        # If no backup path specified, try to find one
        if not backup_path:
            backups = find_ios_backups()
            if not backups:
                print("[iOS] No iOS backups found on this system")
                return
            # Use the most recent backup
            backup_path = str(backups[0].path)
            print(f"[iOS] Using backup: {backups[0].device_name} ({backups[0].ios_version})")

        try:
            collector = iOSCollector(backup_path, str(artifact_dir))

            # Check if backup is encrypted
            if collector.is_encrypted:
                print(f"[iOS] Backup is encrypted - cannot extract artifacts")
                print("[iOS] Please create an unencrypted backup or provide decryption key")
                return

            # Map artifact_key to collector method
            method_map = {
                'sms': collector.collect_sms,
                'call': collector.collect_call_history,
                'contacts': collector.collect_contacts,
                'app': collector.collect_app_data,
                'safari': collector.collect_safari_data,
                'location': collector.collect_location_data,
                'backup': collector.collect_backup_metadata,
            }

            if artifact_key not in method_map:
                print(f"[iOS] Unknown artifact key: {artifact_key}")
                return

            method = method_map[artifact_key]

            for result in method(progress_callback=progress_callback):
                file_path, file_metadata = result
                # Add standard fields
                file_metadata['artifact_type'] = artifact_type
                file_metadata['collection_method'] = 'ios_backup'
                file_metadata['backup_path'] = backup_path
                file_metadata['collected_at'] = datetime.utcnow().isoformat()
                yield file_path, file_metadata

        except Exception as e:
            print(f"[iOS] Collection failed for {artifact_type}: {e}")

    def _get_vss_path(self, file_path: str) -> Optional[str]:
        """Get path to file in latest Volume Shadow Copy"""
        try:
            import subprocess
            result = subprocess.run(
                ['vssadmin', 'list', 'shadows'],
                capture_output=True,
                text=True
            )

            # Parse VSS output to find latest shadow copy
            for line in result.stdout.split('\n'):
                if 'Shadow Copy Volume' in line:
                    vss_volume = line.split(':')[-1].strip()
                    drive = file_path[0]
                    relative_path = file_path[2:]  # Remove 'C:'
                    return f"{vss_volume}{relative_path}"

        except Exception:
            pass

        return None


def get_collection_mode() -> str:
    """
    Get current collection mode.

    Returns:
        'mft' if MFT collection available, 'legacy' otherwise
    """
    if MFT_AVAILABLE:
        try:
            if check_admin_privileges():
                return 'mft'
            else:
                return 'legacy (no admin)'
        except Exception:
            return 'legacy'
    return 'legacy (no pytsk3)'


if __name__ == "__main__":
    import sys

    print(f"Collection mode: {get_collection_mode()}")
    print(f"MFT available: {MFT_AVAILABLE}")

    if len(sys.argv) > 1 and sys.argv[1] == '--test':
        import tempfile

        with tempfile.TemporaryDirectory() as temp_dir:
            collector = ArtifactCollector(temp_dir)
            print(f"\nUsing {collector.collection_mode} collection method")

            print("\nAvailable artifacts:")
            for artifact in collector.get_available_artifacts():
                status = "OK" if artifact['available'] else "N/A"
                admin = " [ADMIN]" if artifact['requires_admin'] else ""
                print(f"  [{status}] {artifact['type']}: {artifact['name']}{admin}")

            collector.close()
