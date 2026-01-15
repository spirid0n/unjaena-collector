# -*- coding: utf-8 -*-
"""
Base MFT Collector Module

E01 이미지와 로컬 디스크 모두에서 사용할 수 있는 MFT 기반 아티팩트 수집기.

디지털 포렌식 원칙:
- MFT 파싱 기반 수집 (디렉토리 탐색 최소화)
- 파일 수 제한 없음
- 삭제 파일 포함
- 시스템 폴더 포함

지원 운영체제:
- Windows (NTFS/FAT/exFAT)
- Linux (ext2/3/4)
- macOS (APFS/HFS+)

Usage:
    # E01 이미지
    collector = E01ArtifactCollector(e01_path, output_dir)

    # 로컬 디스크
    collector = LocalArtifactCollector(output_dir, volume='C')

    # 공통 인터페이스
    for path, metadata in collector.collect('document'):
        print(f"Collected: {path}")
"""

import re
import hashlib
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Generator, Tuple, Set

# OS별 아티팩트 정의 임포트
try:
    from .linux_artifacts import LINUX_ARTIFACT_FILTERS
except ImportError:
    LINUX_ARTIFACT_FILTERS = {}

try:
    from .macos_artifacts import MACOS_ARTIFACT_FILTERS
except ImportError:
    MACOS_ARTIFACT_FILTERS = {}

logger = logging.getLogger(__name__)

# =============================================================================
# Debug Logging (disabled in production)
# =============================================================================

def _debug_log(message: str):
    """디버그 로그 (프로덕션에서는 비활성화)"""
    # 프로덕션에서는 출력하지 않음
    # 디버그 필요시 아래 주석 해제
    # logger.debug(message)
    pass

# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class CollectedArtifact:
    """수집된 아티팩트 정보"""
    local_path: str           # 추출된 로컬 파일 경로
    original_path: str        # 원본 경로
    filename: str             # 파일명
    size: int                 # 파일 크기
    md5: str                  # MD5 해시
    sha256: str               # SHA256 해시
    artifact_type: str        # 아티팩트 유형
    inode: Optional[int] = None
    is_deleted: bool = False
    created_time: Optional[str] = None
    modified_time: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# OS Detection and Artifact Routing
# =============================================================================

def detect_os_type(filesystem: str, root_entries: List[str] = None) -> str:
    """
    파일시스템과 루트 디렉토리 구조를 기반으로 OS 타입 감지

    Args:
        filesystem: 파일시스템 타입 (NTFS, ext4, APFS 등)
        root_entries: 루트 디렉토리의 파일/폴더 목록

    Returns:
        'windows', 'linux', 'macos', 'unknown'
    """
    filesystem_lower = filesystem.lower()

    # 파일시스템 기반 1차 감지
    if filesystem_lower in ('ntfs', 'fat32', 'fat16', 'fat12', 'exfat'):
        return 'windows'
    elif filesystem_lower in ('apfs', 'hfs+', 'hfsx', 'hfs'):
        return 'macos'
    elif filesystem_lower in ('ext2', 'ext3', 'ext4'):
        return 'linux'

    # 루트 디렉토리 구조 기반 2차 감지
    if root_entries:
        entries_lower = {e.lower() for e in root_entries}

        # Windows 특징
        if 'windows' in entries_lower or 'program files' in entries_lower:
            return 'windows'

        # macOS 특징
        if 'applications' in entries_lower or 'library' in entries_lower:
            if 'system' in entries_lower:
                return 'macos'

        # Linux 특징
        if 'etc' in entries_lower and 'var' in entries_lower:
            if 'home' in entries_lower or 'root' in entries_lower:
                return 'linux'

    return 'unknown'


def get_artifact_filters_for_os(os_type: str) -> Dict[str, Any]:
    """
    OS 타입에 맞는 아티팩트 필터 반환

    Args:
        os_type: 'windows', 'linux', 'macos'

    Returns:
        해당 OS의 아티팩트 필터 딕셔너리
    """
    if os_type == 'linux':
        return LINUX_ARTIFACT_FILTERS
    elif os_type == 'macos':
        return MACOS_ARTIFACT_FILTERS
    else:
        return ARTIFACT_MFT_FILTERS  # Windows default


def get_all_artifact_filters() -> Dict[str, Dict[str, Any]]:
    """모든 OS의 아티팩트 필터 통합 반환"""
    all_filters = {}

    # Windows 아티팩트 (기본)
    for key, value in ARTIFACT_MFT_FILTERS.items():
        all_filters[f'windows_{key}'] = {**value, 'os_type': 'windows'}

    # Linux 아티팩트
    for key, value in LINUX_ARTIFACT_FILTERS.items():
        all_filters[key] = {**value, 'os_type': 'linux'}

    # macOS 아티팩트
    for key, value in MACOS_ARTIFACT_FILTERS.items():
        all_filters[key] = {**value, 'os_type': 'macos'}

    return all_filters


# =============================================================================
# MFT Filter Definitions (E01 + Local 통합) - Windows
# =============================================================================

ARTIFACT_MFT_FILTERS = {
    # =========================================================================
    # Windows System Artifacts
    # =========================================================================
    'prefetch': {
        'path_pattern': r'windows/prefetch/',
        'extensions': {'.pf'},
        'include_deleted': True,
        'description': 'Program execution history',
    },
    'eventlog': {
        'path_pattern': r'windows/system32/winevt/logs/',
        'extensions': {'.evtx'},
        'include_deleted': True,
        'description': 'Windows event logs',
    },
    'registry': {
        'files': {'system', 'software', 'sam', 'security', 'default', 'ntuser.dat',
                  'usrclass.dat', 'amcache.hve'},
        'path_patterns': [r'windows/system32/config/', r'users/'],
        'include_deleted': True,
        'description': 'Windows registry hives',
    },
    'amcache': {
        'files': {'amcache.hve'},
        'path_pattern': r'windows/appcompat/programs/',
        'path_optional': True,  # 고유 파일명 - 경로 없어도 수집
        'include_deleted': True,
        'description': 'Application compatibility cache',
    },
    'userassist': {
        'files': {'ntuser.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': 'User activity tracking',
    },

    # =========================================================================
    # NTFS System Files
    # =========================================================================
    'mft': {
        'special': 'collect_mft_raw',
        'inode': 0,
        'include_deleted': False,
        'description': 'Master File Table',
    },
    'logfile': {
        'special': 'collect_logfile',
        'inode': 2,
        'include_deleted': False,
        'description': 'NTFS Transaction Log',
    },
    'usn_journal': {
        'special': 'collect_usn_journal',
        'path_pattern': r'\$extend/',
        'files': {'$usnjrnl'},
        'include_deleted': False,
        'description': 'USN Journal ($UsnJrnl:$J)',
    },

    # =========================================================================
    # Browser Artifacts
    # =========================================================================
    'browser': {
        'files': {'history', 'cookies', 'login data', 'web data', 'places.sqlite',
                  'cookies.sqlite', 'formhistory.sqlite', 'downloads'},
        'path_patterns': [
            r'appdata/local/google/chrome/',
            r'appdata/local/microsoft/edge/',
            r'appdata/roaming/mozilla/firefox/',
        ],
        'path_optional': True,  # MFT 스캔 시 경로 없어도 파일명만으로 수집
        'include_deleted': True,
        'description': 'Browser history, cookies, credentials',
    },

    # =========================================================================
    # USB & External Devices
    # =========================================================================
    'usb': {
        'files': {'setupapi.dev.log'},
        'path_pattern': r'windows/inf/',
        'path_optional': True,  # 고유 파일명 - 경로 없어도 수집
        'include_deleted': True,
        'description': 'USB device connection history',
    },

    # =========================================================================
    # Recent Activity
    # =========================================================================
    'recent': {
        'path_patterns': [
            r'appdata/roaming/microsoft/windows/recent/',
            r'appdata/roaming/microsoft/office/recent/',
        ],
        'extensions': {'.lnk'},
        'include_deleted': True,
        'description': 'Recently accessed files',
    },
    'jumplist': {
        'path_patterns': [
            r'appdata/roaming/microsoft/windows/recent/automaticdestinations/',
            r'appdata/roaming/microsoft/windows/recent/customdestinations/',
        ],
        'extensions': {'.automaticdestinations-ms', '.customdestinations-ms'},
        'include_deleted': True,
        'description': 'Jump lists (taskbar history)',
    },
    'shortcut': {
        'extensions': {'.lnk'},
        'include_deleted': True,
        'description': 'Shortcut files',
    },

    # =========================================================================
    # Recycle Bin
    # =========================================================================
    'recycle_bin': {
        # 휴지통 경로 패턴 (다양한 형태 지원)
        'path_patterns': [
            r'\$recycle\.bin[/\\]',     # 표준: $Recycle.Bin/ 또는 $Recycle.Bin\
            r'recycle\.bin[/\\]',       # $ 없는 형태
            r'\$recycle\.bin$',         # 경로 끝이 $Recycle.Bin인 경우
        ],
        'include_deleted': True,
        'description': 'Deleted files in Recycle Bin ($I metadata + $R files)',
    },

    # =========================================================================
    # System Resources
    # =========================================================================
    'srum': {
        'files': {'srudb.dat'},
        'path_patterns': [r'windows/system32/sru/'],
        'path_optional': True,  # 고유 파일명 - 경로 없어도 수집
        'include_deleted': True,
        'description': 'System Resource Usage Monitor',
    },
    'scheduled_task': {
        'path_pattern': r'windows/system32/tasks/',
        'include_deleted': True,
        'description': 'Scheduled tasks',
    },

    # =========================================================================
    # User Profile
    # =========================================================================
    'shellbags': {
        'files': {'ntuser.dat', 'usrclass.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': 'Explorer folder browsing history',
    },
    'thumbcache': {
        'path_pattern': r'appdata/local/microsoft/windows/explorer/',
        'name_pattern': r'thumbcache_.*\.db',
        'include_deleted': True,
        'description': 'Thumbnail cache',
    },

    # =========================================================================
    # User Files - 서버 분석 가능한 확장자만 (server_parsing_service.py 기준)
    # =========================================================================
    'document': {
        'extensions': {
            '.doc', '.docx',      # Word (python-docx, olefile)
            '.xls', '.xlsx',      # Excel (openpyxl, olefile)
            '.ppt', '.pptx',      # PowerPoint (olefile)
            '.pdf',               # PDF (pypdf)
            '.hwp', '.hwpx',      # 한글 (olefile)
        },
        'include_deleted': True,
        'include_system_folders': True,
        'full_disk_scan': True,
        'description': 'Office documents, PDFs (server-parseable only)',
    },
    'email': {
        'extensions': {'.eml', '.msg', '.pst', '.ost'},  # email, extract_msg, pypff
        'include_deleted': True,
        'include_system_folders': True,
        'full_disk_scan': True,
        'description': 'Email files (.eml, .msg, .pst, .ost)',
    },

    # =========================================================================
    # Command History & Execution Artifacts (Phase 2)
    # =========================================================================
    'powershell_history': {
        'files': {'consolehost_history.txt'},
        'path_pattern': r'appdata/roaming/microsoft/windows/powershell/psreadline/',
        'path_optional': True,  # 고유 파일명 - 경로 없어도 수집
        'include_deleted': True,
        'description': 'PowerShell command history (PSReadLine)',
    },
    'wer': {
        'path_patterns': [
            r'programdata/microsoft/windows/wer/',
            r'appdata/local/microsoft/windows/wer/',
        ],
        'extensions': {'.wer', '.txt', '.hdmp', '.mdmp'},
        'include_deleted': True,
        'description': 'Windows Error Reporting (crash dumps, reports)',
    },
    'rdp_cache': {
        'path_pattern': r'appdata/local/microsoft/terminal server client/cache/',
        'name_pattern': r'(bcache|cache).*\.(bmc|bin)',
        'include_deleted': True,
        'description': 'RDP Bitmap Cache (remote desktop thumbnails)',
    },

    # =========================================================================
    # Phase 3: 보완 아티팩트
    # =========================================================================
    'wlan_event': {
        'files': {'microsoft-windows-wlan-autoconfig%4operational.evtx'},
        'path_pattern': r'windows/system32/winevt/logs/',
        'path_optional': True,  # 고유 파일명 - 경로 없어도 수집
        'include_deleted': True,
        'description': 'WLAN Auto-Config event log (WiFi connection history)',
    },
    'profile_list': {
        # ProfileList는 SOFTWARE 레지스트리에 포함됨
        # registry 수집에서 자동으로 처리됨
        'files': {'software'},
        'path_pattern': r'windows/system32/config/',
        'include_deleted': True,
        'description': 'User profile list (SOFTWARE registry)',
    },
    # image, video 제외됨 - 포렌식 관점에서 중요도 낮음 + 해시 계산으로 인한 속도 저하

    # =========================================================================
    # [2026-01] P0 신규 아티팩트 - 높은 포렌식 가치
    # =========================================================================
    'activities_cache': {
        'path_pattern': r'appdata/local/connecteddevicesplatform/',
        'files': {'activitiescache.db', 'activitiescache.db-wal', 'activitiescache.db-shm'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'Windows Timeline (ActivitiesCache.db) - 앱 실행 지속시간 포함',
    },
    'pca_launch': {
        'path_pattern': r'windows/appcompat/pca/',
        'name_pattern': r'pca.*\.txt',
        'include_deleted': True,
        'description': 'Program Compatibility Assistant (Win11+) - 실행 기록',
    },
    'etl_log': {
        'path_patterns': [
            r'windows/system32/wdi/logfiles/',
            r'windows/system32/logfiles/wmi/',
            r'windows/panther/',
        ],
        'extensions': {'.etl'},
        'include_deleted': True,
        'description': 'ETW AutoLogger - 이벤트 로그 삭제 후에도 유지',
    },
    'wmi_subscription': {
        'path_pattern': r'windows/system32/wbem/repository/',
        'files': {'objects.data', 'index.btr'},
        'name_pattern': r'mapping.*\.map',
        'include_deleted': True,
        'description': 'WMI 이벤트 구독 - 지속성 메커니즘 탐지 (MITRE T1546.003)',
    },
    'defender_detection': {
        'path_patterns': [
            r'programdata/microsoft/windows defender/scans/history/service/detectionhistory/',
            r'programdata/microsoft/windows defender/support/',
        ],
        'name_pattern': r'(mpdetection.*\.bin|mplog.*\.log)',
        'include_deleted': True,
        'description': 'Windows Defender 탐지 기록',
    },
    'zone_identifier': {
        # Zone.Identifier는 Alternate Data Stream (ADS)
        # MFT 직접 수집 불가 - artifact_collector의 collect_zone_identifier 사용
        'special': 'collect_zone_identifier',
        'include_deleted': False,
        'description': 'Zone.Identifier (ADS) - 다운로드 파일 출처 정보',
    },
    'bits_jobs': {
        'path_pattern': r'programdata/microsoft/network/downloader/',
        'files': {'qmgr0.dat', 'qmgr1.dat'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'BITS Transfer Jobs - 악성코드 다운로드 탐지 (MITRE T1197)',
    },

    # =========================================================================
    # [2026-01] 네트워크/RDP/공유 아티팩트
    # =========================================================================
    'rdp_history': {
        # RDP 연결 기록 (Terminal Server Client)
        # 레지스트리: NTUSER.DAT\Software\Microsoft\Terminal Server Client
        'files': {'ntuser.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': 'RDP 연결 기록 (Terminal Server Client MRU)',
    },
    'wireless_profile': {
        # WiFi 프로필 (NetworkList)
        # 레지스트리: SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList
        'files': {'software'},
        'path_pattern': r'windows/system32/config/',
        'include_deleted': True,
        'description': 'WiFi 프로필 (NetworkList - SSID, MAC, 연결 시간)',
    },
    'shared_folder': {
        # 공유 폴더 설정 (LanmanServer\Shares)
        # 레지스트리: SYSTEM\CurrentControlSet\Services\LanmanServer\Shares
        'files': {'system'},
        'path_pattern': r'windows/system32/config/',
        'include_deleted': True,
        'description': '공유 폴더 설정 (LanmanServer\\Shares)',
    },
    'mapped_drive': {
        # 네트워크 드라이브 매핑 (HKCU\Network)
        # 레지스트리: NTUSER.DAT\Network, Map Network Drive MRU
        'files': {'ntuser.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': '네트워크 드라이브 매핑 (HKCU\\Network)',
    },

    # =========================================================================
    # [2026-01] 클라우드 스토리지 아티팩트
    # =========================================================================
    'cloud_onedrive': {
        'path_patterns': [
            r'appdata/local/microsoft/onedrive/',
            r'appdata/local/microsoft/windows/onedrive/',
        ],
        'files': {'settings.dat', 'syncengine.db', 'syncdiagnostics.txt'},
        'extensions': {'.odl', '.etl'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'Microsoft OneDrive 동기화 로그 및 설정',
    },
    'cloud_google_drive': {
        'path_patterns': [
            r'appdata/local/google/drive/',
            r'appdata/local/google/drivefilesync/',
        ],
        'files': {'sync_log.log', 'sync_config.db', 'cloud_graph.db', 'metadata_sqlite_db'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'Google Drive 동기화 로그 (파일 해시, 이메일 포함)',
    },
    'cloud_dropbox': {
        'path_patterns': [
            r'appdata/local/dropbox/',
            r'appdata/roaming/dropbox/',
        ],
        'files': {'filecache.db', 'host.db', 'config.dbx', 'sync_history.db', 'aggregation.dbx'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'Dropbox 동기화 DB 및 캐시',
    },
    'cloud_naver_mybox': {
        'path_patterns': [
            r'appdata/local/naver/navercloud/',
            r'appdata/local/naver/naverbox/',
            r'appdata/local/naverbox/',
        ],
        'files': {'sync.db', 'naverbox.db', 'sync_log.db'},
        'extensions': {'.db', '.log'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'Naver MyBox (네이버 클라우드) 동기화 DB',
    },
    'cloud_icloud': {
        'path_patterns': [
            r'appdata/local/apple inc/clouddocs/',
            r'appdata/local/apple computer/clouddocs/',
            r'appdata/roaming/apple computer/mobilesync/',
        ],
        'files': {'cloudkit.db', 'sqlite3'},
        'path_optional': True,
        'include_deleted': True,
        'description': 'iCloud Drive 동기화 데이터',
    },

    # =========================================================================
    # [2026-01] Office MRU 및 어플리케이션 MRU
    # =========================================================================
    'office_mru': {
        # Office MRU는 NTUSER.DAT에서 파싱
        # 경로: NTUSER.DAT\Software\Microsoft\Office\{버전}\{앱}\File MRU
        'files': {'ntuser.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': 'Office 문서 MRU (Word, Excel, PowerPoint 최근 파일)',
    },
    'comdlg_mru': {
        # ComDlg32 MRU (공통 대화상자)
        # 경로: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32
        'files': {'ntuser.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': '공통 대화상자 MRU (OpenSavePidlMRU, LastVisitedPidlMRU)',
    },
    'application_mru': {
        # 어플리케이션별 MRU (Paint, ALZip, Acrobat 등)
        # 경로: NTUSER.DAT\Software\{앱경로}\Recent File List
        'files': {'ntuser.dat'},
        'path_pattern': r'users/',
        'include_deleted': True,
        'description': '앱별 MRU (Paint, ALZip, Acrobat 등 최근 파일)',
    },
}


# =============================================================================
# Base MFT Collector (Abstract)
# =============================================================================

class BaseMFTCollector(ABC):
    """
    MFT 기반 아티팩트 수집기 베이스 클래스

    E01 이미지와 로컬 디스크 모두에서 사용 가능한 공통 인터페이스 제공.

    디지털 포렌식 원칙:
    - MFT 파싱 기반 수집 (디렉토리 탐색 최소화)
    - 파일 수 제한 없음
    - 삭제 파일 포함 (기본값)
    - 시스템 폴더 포함
    """

    def __init__(self, output_dir: str):
        """
        Args:
            output_dir: 추출된 아티팩트 저장 디렉토리
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # MFT 인덱스 캐시
        self._mft_indexed: bool = False
        self._mft_cache: Dict[str, List[Any]] = {
            'active_files': [],
            'deleted_files': [],
            'directories': [],
        }
        # 확장자 → 파일 엔트리 맵 (빠른 조회용)
        self._extension_index: Dict[str, List[Any]] = {}

        # 서브클래스에서 설정
        self._accessor = None

    @abstractmethod
    def _initialize_accessor(self) -> bool:
        """
        ForensicDiskAccessor 초기화 (서브클래스에서 구현)

        Returns:
            초기화 성공 여부
        """
        pass

    @abstractmethod
    def _get_source_description(self) -> str:
        """
        소스 설명 반환 (예: "E01: image.E01" 또는 "Local: C:")
        """
        pass

    def close(self):
        """리소스 정리"""
        if self._accessor:
            try:
                self._accessor.close()
            except Exception:
                pass
            self._accessor = None

        self._mft_indexed = False
        self._mft_cache = {'active_files': [], 'deleted_files': [], 'directories': []}
        self._extension_index = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # =========================================================================
    # MFT Index Building
    # =========================================================================

    def _build_mft_index(self) -> None:
        """
        MFT 전체 인덱스 구축 (최초 1회)

        디지털 포렌식 원칙:
        - 파일 수 제한 없음
        - 삭제 파일 포함
        - 시스템 폴더 포함
        """
        if self._mft_indexed or not self._accessor:
            return

        source = self._get_source_description()
        logger.info(f"[{source}] Building MFT index (Digital Forensics: Complete collection)...")

        try:
            # MFT 전체 스캔 - 제한 없음, 삭제 파일 포함
            scan_result = self._accessor.scan_all_files(
                include_deleted=True,
                max_entries=None,
            )

            self._mft_cache['active_files'] = scan_result.get('active_files', [])
            self._mft_cache['deleted_files'] = scan_result.get('deleted_files', [])
            self._mft_cache['directories'] = scan_result.get('directories', [])

            total_files = len(self._mft_cache['active_files']) + len(self._mft_cache['deleted_files'])
            logger.info(f"[{source}] MFT index built: {total_files:,} files "
                       f"({len(self._mft_cache['active_files']):,} active, "
                       f"{len(self._mft_cache['deleted_files']):,} deleted)")

            # 확장자 인덱스 구축
            self._build_extension_index()

            self._mft_indexed = True

        except Exception as e:
            logger.error(f"[{source}] Failed to build MFT index: {e}", exc_info=True)
            self._mft_indexed = False

    def _build_extension_index(self) -> None:
        """확장자별 인덱스 구축 (빠른 조회용)"""
        self._extension_index = {}

        all_files = self._mft_cache['active_files'] + self._mft_cache['deleted_files']

        for entry in all_files:
            filename = entry.filename if hasattr(entry, 'filename') else str(entry)
            if '.' in filename:
                ext = '.' + filename.rsplit('.', 1)[-1].lower()
                if ext not in self._extension_index:
                    self._extension_index[ext] = []
                self._extension_index[ext].append(entry)

        logger.debug(f"Extension index built: {len(self._extension_index)} unique extensions")

    # =========================================================================
    # MFT-Based Collection
    # =========================================================================

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None,
        **kwargs
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        아티팩트 수집 (MFT 기반)

        디지털 포렌식 원칙:
        - MFT 파싱만 사용 (디렉토리 탐색 금지)
        - 파일 수 제한 없음
        - 삭제 파일 포함
        - 시스템 폴더 포함

        Args:
            artifact_type: 수집할 아티팩트 유형
            progress_callback: 진행률 콜백

        Yields:
            (로컬 경로, 메타데이터) 튜플
        """
        if not self._accessor:
            logger.error("Accessor not initialized")
            return

        if artifact_type not in ARTIFACT_MFT_FILTERS:
            logger.warning(f"Unknown artifact type: {artifact_type}")
            return

        mft_filter = ARTIFACT_MFT_FILTERS[artifact_type]
        source = self._get_source_description()

        # MFT 인덱스 구축 (최초 1회)
        if not self._mft_indexed:
            self._build_mft_index()

        # 아티팩트별 출력 디렉토리
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        # 특수 아티팩트 처리 ($MFT, $LogFile, $UsnJrnl)
        if 'special' in mft_filter:
            yield from self._collect_special_artifact(
                artifact_type, mft_filter, artifact_dir, progress_callback
            )
            return

        # 일반 아티팩트 수집 (MFT 필터 기반)
        logger.info(f"[{source}] Collecting {artifact_type} using MFT filter...")

        extracted_count = 0
        for result in self._collect_by_mft_filter(artifact_type, mft_filter, artifact_dir):
            extracted_count += 1
            yield result
            if progress_callback:
                progress_callback(result[0])

        logger.info(f"[{source}] Collected {extracted_count:,} {artifact_type} artifacts")

    def _collect_by_mft_filter(
        self,
        artifact_type: str,
        mft_filter: Dict[str, Any],
        artifact_dir: Path
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        MFT 필터를 사용한 아티팩트 수집

        Args:
            artifact_type: 아티팩트 유형
            mft_filter: MFT 필터 설정
            artifact_dir: 출력 디렉토리

        Yields:
            (로컬 경로, 메타데이터) 튜플
        """
        include_deleted = mft_filter.get('include_deleted', True)
        full_disk_scan = mft_filter.get('full_disk_scan', False)

        # 수집 대상 파일 리스트
        files_to_check = list(self._mft_cache['active_files'])
        if include_deleted:
            files_to_check.extend(self._mft_cache['deleted_files'])

        # 필터 조건
        extensions = mft_filter.get('extensions', set())
        target_files = mft_filter.get('files', set())
        path_pattern = mft_filter.get('path_pattern')
        path_patterns = mft_filter.get('path_patterns', [])
        name_pattern = mft_filter.get('name_pattern')
        path_optional = mft_filter.get('path_optional', False)  # 경로 없어도 파일명만으로 수집

        # 경로 패턴 컴파일
        compiled_patterns = []
        if path_pattern:
            compiled_patterns.append(re.compile(path_pattern, re.IGNORECASE))
        for pp in path_patterns:
            compiled_patterns.append(re.compile(pp, re.IGNORECASE))

        # 이름 패턴 컴파일
        compiled_name_pattern = None
        if name_pattern:
            compiled_name_pattern = re.compile(name_pattern, re.IGNORECASE)

        # 확장자 기반 빠른 필터링 (전체 디스크 스캔 시)
        if extensions and full_disk_scan:
            file_counter = 0
            for ext in extensions:
                ext_lower = ext.lower()
                ext_count = len(self._extension_index.get(ext_lower, []))
                _debug_log(f"[SCAN] Extension {ext_lower}: {ext_count} files to process")

                for entry in self._extension_index.get(ext_lower, []):
                    if not include_deleted and getattr(entry, 'is_deleted', False):
                        continue

                    file_counter += 1
                    filename = entry.filename if hasattr(entry, 'filename') else str(entry)
                    if file_counter % 500 == 0:
                        _debug_log(f"[PROGRESS] {artifact_type}: Processing file #{file_counter} - {filename}")

                    yield from self._extract_entry(artifact_type, entry, artifact_dir)
            return

        # 전체 스캔 (경로/파일명 기반)
        for entry in files_to_check:
            filename = entry.filename if hasattr(entry, 'filename') else str(entry)
            filename_lower = filename.lower()
            full_path = entry.full_path if hasattr(entry, 'full_path') else ""
            full_path_lower = full_path.lower() if full_path else ""

            if not include_deleted and getattr(entry, 'is_deleted', False):
                continue

            matched = False

            # 1. 파일명 일치 검사
            if target_files and filename_lower in target_files:
                if compiled_patterns and full_path_lower:
                    # 경로가 있으면 경로 패턴도 확인
                    for pattern in compiled_patterns:
                        if pattern.search(full_path_lower):
                            matched = True
                            break
                elif path_optional:
                    # path_optional=True면 파일명만으로 수집 (MFT 경로 복원 안됐을 때)
                    matched = True
                elif not compiled_patterns:
                    # 경로 패턴 없으면 파일명만으로 수집
                    matched = True

            # 2. 확장자 일치 검사
            if not matched and extensions:
                if '.' in filename_lower:
                    ext = '.' + filename_lower.rsplit('.', 1)[-1]
                    if ext in extensions:
                        if compiled_patterns and full_path_lower:
                            for pattern in compiled_patterns:
                                if pattern.search(full_path_lower):
                                    matched = True
                                    break
                        elif path_optional or not compiled_patterns:
                            matched = True

            # 3. 경로 패턴만 검사
            if not matched and compiled_patterns and not extensions and not target_files:
                for pattern in compiled_patterns:
                    if pattern.search(full_path_lower):
                        matched = True
                        break

            # 4. 이름 패턴 검사
            if compiled_name_pattern and not matched:
                if compiled_name_pattern.match(filename_lower):
                    matched = True

            if matched:
                yield from self._extract_entry(artifact_type, entry, artifact_dir)

    def _extract_entry(
        self,
        artifact_type: str,
        entry: Any,
        artifact_dir: Path
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        MFT 엔트리에서 파일 추출 (청크 스트리밍)

        Args:
            artifact_type: 아티팩트 유형
            entry: FileCatalogEntry
            artifact_dir: 출력 디렉토리

        Yields:
            (로컬 경로, 메타데이터) 튜플
        """
        import time

        inode = entry.inode if hasattr(entry, 'inode') else None
        filename = entry.filename if hasattr(entry, 'filename') else str(entry)
        full_path = entry.full_path if hasattr(entry, 'full_path') else f"MFT_{inode}"
        is_deleted = getattr(entry, 'is_deleted', False)
        file_size = getattr(entry, 'size', 0)

        if inode is None:
            return

        # 디버깅: 대용량 파일 경고
        if file_size > 100 * 1024 * 1024:  # 100MB 이상
            _debug_log(f"[DEBUG] Large file detected: {filename} ({file_size / 1024 / 1024:.1f}MB)")

        try:
            # 출력 파일명 생성
            safe_filename = self._sanitize_filename(filename)
            if is_deleted:
                safe_filename = f"[DELETED]_{safe_filename}"

            output_file = artifact_dir / safe_filename

            # 중복 방지
            if output_file.exists():
                base = output_file.stem
                suffix = output_file.suffix
                counter = 1
                while output_file.exists():
                    output_file = artifact_dir / f"{base}_{counter}{suffix}"
                    counter += 1

            # 청크 스트리밍으로 파일 쓰기 + 해시 계산
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            total_size = 0
            has_data = False

            # 타임아웃 설정 (파일당 최대 5분, 청크당 30초)
            FILE_TIMEOUT = 300  # 5분
            CHUNK_TIMEOUT = 30  # 30초
            start_time = time.time()
            last_chunk_time = start_time

            # 스트리밍 메서드 확인
            if hasattr(self._accessor, 'stream_file_by_inode'):
                # 청크 스트리밍 (대용량 파일 지원)
                try:
                    _debug_log(f"[EXTRACT START] {filename} (inode={inode}, size={file_size})")
                    with open(output_file, 'wb') as f:
                        chunk_count = 0
                        stream_generator = self._accessor.stream_file_by_inode(inode)
                        _debug_log(f"[STREAM READY] {filename}")
                        for chunk in stream_generator:
                            current_time = time.time()

                            # 파일 전체 타임아웃 체크
                            if current_time - start_time > FILE_TIMEOUT:
                                _debug_log(f"[TIMEOUT] File extraction timeout ({FILE_TIMEOUT}s): {filename}")
                                break

                            if chunk:
                                f.write(chunk)
                                md5_hash.update(chunk)
                                sha256_hash.update(chunk)
                                total_size += len(chunk)
                                has_data = True
                                chunk_count += 1
                                last_chunk_time = current_time

                                # 진행 로그 (100MB마다)
                                if total_size % (100 * 1024 * 1024) < len(chunk):
                                    _debug_log(f"[PROGRESS] {filename}: {total_size / 1024 / 1024:.1f}MB written")

                except Exception as stream_error:
                    _debug_log(f"[STREAM ERROR] {filename}: {stream_error}")
                    # 부분적으로 쓰인 파일 삭제
                    if output_file.exists() and total_size == 0:
                        output_file.unlink()
                    return

            else:
                # 폴백: 전체 읽기 (작은 파일용)
                data = self._accessor.read_file_by_inode(inode)
                if data:
                    output_file.write_bytes(data)
                    md5_hash.update(data)
                    sha256_hash.update(data)
                    total_size = len(data)
                    has_data = True

            if has_data:
                # 메타데이터 생성
                metadata = {
                    'artifact_type': artifact_type,
                    'name': filename,
                    'original_path': full_path,
                    'size': total_size,
                    'hash_md5': md5_hash.hexdigest(),
                    'hash_sha256': sha256_hash.hexdigest(),
                    'collection_method': 'mft_based',
                    'source': self._get_source_description(),
                    'mft_inode': inode,
                    'is_deleted': is_deleted,
                    'created_time': getattr(entry, 'created_time', None),
                    'modified_time': getattr(entry, 'modified_time', None),
                    'collected_at': datetime.now().isoformat(),
                }

                yield str(output_file), metadata
            else:
                # 빈 파일 삭제
                if output_file.exists():
                    output_file.unlink()

        except Exception as e:
            logger.debug(f"Cannot extract {full_path}: {e}")

    def _collect_special_artifact(
        self,
        artifact_type: str,
        mft_filter: Dict[str, Any],
        artifact_dir: Path,
        progress_callback: Optional[callable]
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        특수 시스템 아티팩트 수집 ($MFT, $LogFile, $UsnJrnl)
        """
        special_method = mft_filter.get('special')
        source = self._get_source_description()

        try:
            if special_method == 'collect_mft_raw':
                # $MFT (inode 0)
                logger.info(f"[{source}] Collecting $MFT (inode 0)...")
                data = self._accessor.read_file_by_inode(0)

                if data:
                    output_file = artifact_dir / '$MFT'
                    output_file.write_bytes(data)

                    metadata = {
                        'artifact_type': artifact_type,
                        'name': '$MFT',
                        'original_path': '$MFT',
                        'size': len(data),
                        'hash_md5': hashlib.md5(data).hexdigest(),
                        'hash_sha256': hashlib.sha256(data).hexdigest(),
                        'collection_method': 'mft_based',
                        'source': source,
                        'mft_inode': 0,
                        'collected_at': datetime.now().isoformat(),
                    }

                    yield str(output_file), metadata
                    if progress_callback:
                        progress_callback(str(output_file))

            elif special_method == 'collect_logfile':
                # $LogFile (inode 2)
                logger.info(f"[{source}] Collecting $LogFile (inode 2)...")
                data = self._accessor.read_file_by_inode(2)

                if data:
                    output_file = artifact_dir / '$LogFile'
                    output_file.write_bytes(data)

                    metadata = {
                        'artifact_type': artifact_type,
                        'name': '$LogFile',
                        'original_path': '$LogFile',
                        'size': len(data),
                        'hash_md5': hashlib.md5(data).hexdigest(),
                        'hash_sha256': hashlib.sha256(data).hexdigest(),
                        'collection_method': 'mft_based',
                        'source': source,
                        'mft_inode': 2,
                        'collected_at': datetime.now().isoformat(),
                    }

                    yield str(output_file), metadata
                    if progress_callback:
                        progress_callback(str(output_file))

            elif special_method == 'collect_usn_journal':
                # $UsnJrnl:$J
                logger.info(f"[{source}] Collecting $UsnJrnl:$J...")
                data = None

                try:
                    data = self._accessor.read_usnjrnl_raw()
                except Exception:
                    # 대체 방법: $Extend 디렉토리에서 찾기
                    try:
                        usnjrnl_inode = self._accessor._find_in_directory(11, '$UsnJrnl')
                        if usnjrnl_inode:
                            data = self._accessor.read_file_by_inode(
                                usnjrnl_inode, stream_name='$J'
                            )
                    except Exception:
                        pass

                if data and len(data) > 0:
                    output_file = artifact_dir / '$UsnJrnl_J'
                    output_file.write_bytes(data)

                    metadata = {
                        'artifact_type': artifact_type,
                        'name': '$UsnJrnl:$J',
                        'original_path': '$Extend/$UsnJrnl:$J',
                        'size': len(data),
                        'hash_md5': hashlib.md5(data).hexdigest(),
                        'hash_sha256': hashlib.sha256(data).hexdigest(),
                        'collection_method': 'mft_based',
                        'source': source,
                        'ads_stream': '$J',
                        'collected_at': datetime.now().isoformat(),
                    }

                    yield str(output_file), metadata
                    if progress_callback:
                        progress_callback(str(output_file))

            elif special_method == 'collect_zone_identifier':
                # Zone.Identifier ADS - 다운로드 파일 출처 정보
                logger.info(f"[{source}] Collecting Zone.Identifier ADS streams...")

                # MFT 인덱스 구축 (최초 1회)
                if not self._mft_indexed:
                    self._build_mft_index()

                # 대상 사용자 디렉토리 (대소문자 무시)
                user_paths = ['downloads', 'desktop', 'documents']
                ads_stream_name = 'Zone.Identifier'
                collected_count = 0
                checked_count = 0

                all_files = self._mft_cache.get('active_files', [])
                logger.info(f"[{source}] Scanning {len(all_files)} active files for Zone.Identifier...")

                for entry in all_files:
                    try:
                        full_path = getattr(entry, 'full_path', '') or ''
                        filename = getattr(entry, 'filename', '') or ''
                        inode = getattr(entry, 'inode', None)
                        # ads_streams가 이미 FileCatalogEntry에 포함됨
                        entry_ads = getattr(entry, 'ads_streams', []) or []

                        if not inode or not full_path:
                            continue

                        full_path_lower = full_path.lower()

                        # 사용자 디렉토리 필터링 (Users 폴더 하위)
                        is_user_path = False
                        for user_path in user_paths:
                            # '/users/' 또는 'users/' (루트 시작 유무 모두 처리)
                            if ('users/' in full_path_lower or '/users/' in full_path_lower) and \
                               f'/{user_path}/' in full_path_lower:
                                is_user_path = True
                                break

                        if not is_user_path:
                            continue

                        checked_count += 1

                        # Zone.Identifier ADS 존재 여부 확인 (캐시된 ads_streams 사용)
                        if ads_stream_name not in entry_ads:
                            continue

                        # Zone.Identifier ADS 읽기
                        ads_data = self._accessor.read_file_by_inode(
                            inode, stream_name=ads_stream_name
                        )

                        if ads_data:
                            # 출력 파일명: 원본파일명_Zone.Identifier.txt
                            safe_filename = self._sanitize_filename(filename)
                            output_filename = f"{safe_filename}_Zone.Identifier.txt"
                            output_file = artifact_dir / output_filename

                            # 중복 방지
                            if output_file.exists():
                                counter = 1
                                while output_file.exists():
                                    output_file = artifact_dir / f"{safe_filename}_{counter}_Zone.Identifier.txt"
                                    counter += 1

                            output_file.write_bytes(ads_data)
                            collected_count += 1

                            metadata = {
                                'artifact_type': artifact_type,
                                'name': f"{filename}:Zone.Identifier",
                                'original_path': f"{full_path}:Zone.Identifier",
                                'parent_file': filename,
                                'parent_path': full_path,
                                'size': len(ads_data),
                                'hash_md5': hashlib.md5(ads_data).hexdigest(),
                                'hash_sha256': hashlib.sha256(ads_data).hexdigest(),
                                'collection_method': 'mft_based',
                                'source': source,
                                'ads_stream': ads_stream_name,
                                'mft_inode': inode,
                                'collected_at': datetime.now().isoformat(),
                            }

                            # Zone.Identifier 내용 파싱
                            try:
                                ads_text = ads_data.decode('utf-8', errors='ignore')
                                for line in ads_text.split('\n'):
                                    line = line.strip()
                                    if '=' in line:
                                        key, value = line.split('=', 1)
                                        key = key.strip()
                                        value = value.strip()
                                        if key == 'ZoneId':
                                            metadata['zone_id'] = int(value)
                                            zone_names = {
                                                0: 'Local Machine',
                                                1: 'Local Intranet',
                                                2: 'Trusted Sites',
                                                3: 'Internet',
                                                4: 'Restricted Sites'
                                            }
                                            metadata['zone_name'] = zone_names.get(int(value), 'Unknown')
                                        elif key == 'ReferrerUrl':
                                            metadata['referrer_url'] = value
                                        elif key == 'HostUrl':
                                            metadata['host_url'] = value
                            except Exception:
                                pass

                            yield str(output_file), metadata
                            if progress_callback:
                                progress_callback(str(output_file))

                    except Exception as entry_err:
                        logger.debug(f"Zone.Identifier entry error: {entry_err}")
                        continue

                logger.info(f"[{source}] Zone.Identifier: checked {checked_count} user files, collected {collected_count} ADS streams")

        except Exception as e:
            logger.error(f"[{source}] Special artifact collection failed ({special_method}): {e}")

    # =========================================================================
    # Utilities
    # =========================================================================

    def _sanitize_filename(self, filename: str) -> str:
        """파일명에서 유효하지 않은 문자 제거"""
        sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
        sanitized = re.sub(r'_+', '_', sanitized)
        sanitized = sanitized.strip(' _.')
        if not sanitized:
            sanitized = 'unnamed_file'
        return sanitized

    def get_available_artifacts(self) -> List[Dict[str, Any]]:
        """사용 가능한 아티팩트 목록 반환"""
        artifacts = []
        for type_id, mft_filter in ARTIFACT_MFT_FILTERS.items():
            artifacts.append({
                'type': type_id,
                'description': mft_filter.get('description', ''),
                'include_deleted': mft_filter.get('include_deleted', True),
                'full_disk_scan': mft_filter.get('full_disk_scan', False),
            })
        return artifacts
