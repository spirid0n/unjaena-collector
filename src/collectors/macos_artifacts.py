# -*- coding: utf-8 -*-
"""
macOS Artifact Definitions - macOS 시스템 아티팩트 수집 정의

디지털 포렌식을 위한 macOS 시스템 아티팩트 수집 필터를 정의합니다.
APFS/HFS+ 파일시스템에서 수집 가능한 모든 주요 아티팩트를 포함합니다.

Categories:
1. System Logs - 시스템 로그
2. User Activity - 사용자 활동
3. Launch Items - 시작 항목
4. Network - 네트워크
5. Applications - 애플리케이션
6. Security - 보안
7. Browser - 브라우저
8. Persistence - 지속성

Usage:
    from collectors.macos_artifacts import MACOS_ARTIFACT_FILTERS

    for artifact_id, config in MACOS_ARTIFACT_FILTERS.items():
        paths = config['paths']
        description = config['description']
        forensic_value = config['forensic_value']
"""

from typing import Dict, List, Any

# ==============================================================================
# macOS Artifact Filter Definitions
# ==============================================================================

MACOS_ARTIFACT_FILTERS: Dict[str, Dict[str, Any]] = {

    # ==========================================================================
    # System Logs (시스템 로그)
    # ==========================================================================

    'macos_unified_log': {
        'paths': [
            '/var/db/diagnostics/*.tracev3',
            '/var/db/diagnostics/Persist/*.tracev3',
            '/var/db/uuidtext/*',
        ],
        'description': 'Unified Logging System (macOS 10.12+)',
        'forensic_value': 'critical',
        'category': 'system_logs',
        'os_type': 'macos',
        'note': 'log show 명령으로 파싱 필요',
    },

    'macos_system_log': {
        'paths': [
            '/var/log/system.log',
            '/var/log/system.log.*.gz',
        ],
        'description': '시스템 로그 (레거시)',
        'forensic_value': 'high',
        'category': 'system_logs',
        'os_type': 'macos',
    },

    'macos_install_log': {
        'paths': [
            '/var/log/install.log',
        ],
        'description': '설치 로그',
        'forensic_value': 'high',
        'category': 'system_logs',
        'os_type': 'macos',
    },

    'macos_asl_logs': {
        'paths': [
            '/var/log/asl/*.asl',
        ],
        'description': 'Apple System Log (레거시)',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'macos',
    },

    'macos_crash_reports': {
        'paths': [
            '/Library/Logs/DiagnosticReports/*.crash',
            '/Library/Logs/DiagnosticReports/*.diag',
            '/Users/*/Library/Logs/DiagnosticReports/*.crash',
        ],
        'description': '애플리케이션 크래시 리포트',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'macos',
    },

    'macos_audit_logs': {
        'paths': [
            '/var/audit/*',
        ],
        'description': 'BSM Audit 로그',
        'forensic_value': 'critical',
        'category': 'security',
        'os_type': 'macos',
    },

    # ==========================================================================
    # User Activity (사용자 활동)
    # ==========================================================================

    'macos_bash_history': {
        'paths': [
            '/Users/*/.bash_history',
            '/var/root/.bash_history',
        ],
        'description': 'Bash 명령어 히스토리',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_zsh_history': {
        'paths': [
            '/Users/*/.zsh_history',
            '/var/root/.zsh_history',
        ],
        'description': 'Zsh 명령어 히스토리 (Catalina+)',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_recent_items': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.recentitems.plist',
        ],
        'description': '최근 사용 항목',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_finder_plist': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.finder.plist',
        ],
        'description': 'Finder 설정 및 최근 폴더',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_spotlight_shortcuts': {
        'paths': [
            '/Users/*/Library/Application Support/com.apple.spotlight.Shortcuts',
        ],
        'description': 'Spotlight 검색 기록',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_trash': {
        'paths': [
            '/Users/*/.Trash/*',
            '/Users/*/.Trash/.DS_Store',
        ],
        'description': '휴지통 내용',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_knowledgec': {
        'paths': [
            '/Users/*/Library/Application Support/Knowledge/knowledgeC.db',
            '/private/var/db/CoreDuet/Knowledge/knowledgeC.db',
        ],
        'description': 'KnowledgeC 사용자 활동 DB',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_quicklook': {
        'paths': [
            '/Users/*/Library/Caches/com.apple.QuickLook.thumbnailcache/*',
            '/private/var/folders/*/*/C/com.apple.QuickLook.thumbnailcache/*',
        ],
        'description': 'QuickLook 썸네일 캐시',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'macos',
    },

    'macos_downloads': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2',
        ],
        'description': '다운로드 격리 기록',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'macos',
        'path_optional': True,
    },

    # ==========================================================================
    # FSEvents (파일 시스템 이벤트)
    # ==========================================================================

    'macos_fseventsd': {
        'paths': [
            '/.fseventsd/*',
        ],
        'description': 'FSEvents 파일 시스템 변경 로그',
        'forensic_value': 'critical',
        'category': 'filesystem',
        'os_type': 'macos',
    },

    'macos_spotlight': {
        'paths': [
            '/.Spotlight-V100/*',
        ],
        'description': 'Spotlight 인덱스 데이터',
        'forensic_value': 'high',
        'category': 'filesystem',
        'os_type': 'macos',
    },

    # ==========================================================================
    # Launch Items (시작 항목 - 지속성)
    # ==========================================================================

    'macos_launch_agents_system': {
        'paths': [
            '/Library/LaunchAgents/*.plist',
            '/System/Library/LaunchAgents/*.plist',
        ],
        'description': '시스템 Launch Agents',
        'forensic_value': 'critical',
        'category': 'persistence',
        'os_type': 'macos',
    },

    'macos_launch_agents_user': {
        'paths': [
            '/Users/*/Library/LaunchAgents/*.plist',
        ],
        'description': '사용자 Launch Agents',
        'forensic_value': 'critical',
        'category': 'persistence',
        'os_type': 'macos',
    },

    'macos_launch_daemons': {
        'paths': [
            '/Library/LaunchDaemons/*.plist',
            '/System/Library/LaunchDaemons/*.plist',
        ],
        'description': 'Launch Daemons',
        'forensic_value': 'critical',
        'category': 'persistence',
        'os_type': 'macos',
    },

    'macos_login_items': {
        'paths': [
            '/Users/*/Library/Preferences/com.apple.loginitems.plist',
            '/Users/*/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm',
        ],
        'description': '로그인 항목',
        'forensic_value': 'critical',
        'category': 'persistence',
        'os_type': 'macos',
    },

    'macos_startup_items': {
        'paths': [
            '/Library/StartupItems/*',
        ],
        'description': 'Startup Items (레거시)',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'macos',
    },

    'macos_cron': {
        'paths': [
            '/var/at/tabs/*',
            '/usr/lib/cron/tabs/*',
        ],
        'description': 'Cron 작업',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'macos',
    },

    'macos_periodic': {
        'paths': [
            '/etc/periodic/daily/*',
            '/etc/periodic/weekly/*',
            '/etc/periodic/monthly/*',
        ],
        'description': 'Periodic 스크립트',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'macos',
    },

    # ==========================================================================
    # Security & Privacy
    # ==========================================================================

    'macos_tcc': {
        'paths': [
            '/Library/Application Support/com.apple.TCC/TCC.db',
            '/Users/*/Library/Application Support/com.apple.TCC/TCC.db',
        ],
        'description': 'TCC 권한 데이터베이스',
        'forensic_value': 'critical',
        'category': 'security',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_keychain': {
        'paths': [
            '/Users/*/Library/Keychains/login.keychain-db',
            '/Library/Keychains/System.keychain',
        ],
        'description': 'Keychain 데이터베이스',
        'forensic_value': 'critical',
        'category': 'security',
        'os_type': 'macos',
    },

    'macos_gatekeeper': {
        'paths': [
            '/var/db/SystemPolicy',
            '/var/db/SystemPolicyConfiguration/*',
        ],
        'description': 'Gatekeeper 정책 데이터',
        'forensic_value': 'high',
        'category': 'security',
        'os_type': 'macos',
    },

    'macos_xprotect': {
        'paths': [
            '/Library/Apple/System/Library/CoreServices/XProtect.bundle/*',
            '/var/db/xprotect/*',
        ],
        'description': 'XProtect 맬웨어 정의',
        'forensic_value': 'medium',
        'category': 'security',
        'os_type': 'macos',
    },

    # ==========================================================================
    # Network
    # ==========================================================================

    'macos_wifi': {
        'paths': [
            '/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist',
            '/Library/Preferences/com.apple.wifi.known-networks.plist',
        ],
        'description': 'Wi-Fi 연결 기록',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'macos',
    },

    'macos_network_preferences': {
        'paths': [
            '/Library/Preferences/SystemConfiguration/preferences.plist',
            '/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist',
        ],
        'description': '네트워크 설정',
        'forensic_value': 'medium',
        'category': 'network',
        'os_type': 'macos',
    },

    'macos_hosts': {
        'paths': [
            '/etc/hosts',
            '/private/etc/hosts',
        ],
        'description': 'Hosts 파일',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'macos',
    },

    'macos_ssh': {
        'paths': [
            '/Users/*/.ssh/known_hosts',
            '/Users/*/.ssh/authorized_keys',
            '/Users/*/.ssh/config',
            '/var/root/.ssh/*',
        ],
        'description': 'SSH 설정 및 기록',
        'forensic_value': 'critical',
        'category': 'network',
        'os_type': 'macos',
        'path_optional': True,
    },

    # ==========================================================================
    # Browser Artifacts
    # ==========================================================================

    'macos_safari_history': {
        'paths': [
            '/Users/*/Library/Safari/History.db',
            '/Users/*/Library/Safari/History.db-wal',
        ],
        'description': 'Safari 방문 기록',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_safari_downloads': {
        'paths': [
            '/Users/*/Library/Safari/Downloads.plist',
        ],
        'description': 'Safari 다운로드 기록',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'macos',
    },

    'macos_safari_cookies': {
        'paths': [
            '/Users/*/Library/Cookies/Cookies.binarycookies',
        ],
        'description': 'Safari 쿠키',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'macos',
    },

    'macos_safari_cache': {
        'paths': [
            '/Users/*/Library/Caches/com.apple.Safari/Cache.db',
        ],
        'description': 'Safari 캐시',
        'forensic_value': 'medium',
        'category': 'browser',
        'os_type': 'macos',
    },

    'macos_chrome': {
        'paths': [
            '/Users/*/Library/Application Support/Google/Chrome/Default/History',
            '/Users/*/Library/Application Support/Google/Chrome/Default/Cookies',
            '/Users/*/Library/Application Support/Google/Chrome/Default/Login Data',
            '/Users/*/Library/Application Support/Google/Chrome/Default/Bookmarks',
        ],
        'description': 'Chrome 브라우저 데이터',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_firefox': {
        'paths': [
            '/Users/*/Library/Application Support/Firefox/Profiles/*.default*/places.sqlite',
            '/Users/*/Library/Application Support/Firefox/Profiles/*.default*/cookies.sqlite',
            '/Users/*/Library/Application Support/Firefox/Profiles/*.default*/logins.json',
        ],
        'description': 'Firefox 브라우저 데이터',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'macos',
        'path_optional': True,
    },

    # ==========================================================================
    # Applications
    # ==========================================================================

    'macos_imessage': {
        'paths': [
            '/Users/*/Library/Messages/chat.db',
            '/Users/*/Library/Messages/chat.db-wal',
        ],
        'description': 'iMessage 메시지',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_mail': {
        'paths': [
            '/Users/*/Library/Mail/V*/MailData/Envelope Index',
            '/Users/*/Library/Mail/V*/MailData/Envelope Index-wal',
        ],
        'description': 'Mail 앱 인덱스',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'macos',
    },

    'macos_notes': {
        'paths': [
            '/Users/*/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite',
        ],
        'description': 'Notes 앱 데이터',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'macos',
        'path_optional': True,
    },

    'macos_calendar': {
        'paths': [
            '/Users/*/Library/Calendars/*.caldav/*.calendar/Events/*.ics',
            '/Users/*/Library/Calendars/Calendar Cache',
        ],
        'description': 'Calendar 앱 데이터',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'macos',
    },

    'macos_reminders': {
        'paths': [
            '/Users/*/Library/Reminders/Container_v1/Stores/*.sqlite',
        ],
        'description': 'Reminders 앱 데이터',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'macos',
    },

    'macos_photos': {
        'paths': [
            '/Users/*/Pictures/Photos Library.photoslibrary/database/Photos.sqlite',
        ],
        'description': 'Photos 앱 데이터베이스',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'macos',
    },

    'macos_terminal': {
        'paths': [
            '/Users/*/Library/Saved Application State/com.apple.Terminal.savedState/*',
        ],
        'description': 'Terminal 저장 상태',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'macos',
    },

    # ==========================================================================
    # System Information
    # ==========================================================================

    'macos_system_version': {
        'paths': [
            '/System/Library/CoreServices/SystemVersion.plist',
        ],
        'description': 'macOS 버전 정보',
        'forensic_value': 'low',
        'category': 'system_info',
        'os_type': 'macos',
    },

    'macos_bluetooth': {
        'paths': [
            '/Library/Preferences/com.apple.Bluetooth.plist',
        ],
        'description': 'Bluetooth 연결 기록',
        'forensic_value': 'medium',
        'category': 'system_info',
        'os_type': 'macos',
    },

    'macos_usb': {
        'paths': [
            '/var/db/lockdown/*',
        ],
        'description': 'USB 기기 연결 기록 (iOS 페어링)',
        'forensic_value': 'high',
        'category': 'system_info',
        'os_type': 'macos',
    },

    'macos_time_machine': {
        'paths': [
            '/Library/Preferences/com.apple.TimeMachine.plist',
        ],
        'description': 'Time Machine 설정',
        'forensic_value': 'medium',
        'category': 'system_info',
        'os_type': 'macos',
    },
}


# ==============================================================================
# Helper Functions
# ==============================================================================

def get_macos_artifacts_by_category(category: str) -> Dict[str, Dict[str, Any]]:
    """카테고리별 macOS 아티팩트 반환"""
    return {
        k: v for k, v in MACOS_ARTIFACT_FILTERS.items()
        if v.get('category') == category
    }


def get_macos_artifacts_by_forensic_value(value: str) -> Dict[str, Dict[str, Any]]:
    """포렌식 가치별 macOS 아티팩트 반환"""
    return {
        k: v for k, v in MACOS_ARTIFACT_FILTERS.items()
        if v.get('forensic_value') == value
    }


def get_all_macos_artifact_paths() -> List[str]:
    """모든 macOS 아티팩트 경로 반환 (와일드카드 포함)"""
    paths = []
    for config in MACOS_ARTIFACT_FILTERS.values():
        paths.extend(config.get('paths', []))
    return paths


def get_macos_categories() -> List[str]:
    """macOS 아티팩트 카테고리 목록 반환"""
    categories = set()
    for config in MACOS_ARTIFACT_FILTERS.values():
        if 'category' in config:
            categories.add(config['category'])
    return sorted(list(categories))


# 아티팩트 통계
MACOS_ARTIFACT_STATS = {
    'total_artifacts': len(MACOS_ARTIFACT_FILTERS),
    'categories': get_macos_categories(),
    'critical_artifacts': len(get_macos_artifacts_by_forensic_value('critical')),
    'high_artifacts': len(get_macos_artifacts_by_forensic_value('high')),
}
