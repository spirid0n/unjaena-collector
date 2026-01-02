# -*- coding: utf-8 -*-
"""
Linux Artifact Definitions - Linux 시스템 아티팩트 수집 정의

디지털 포렌식을 위한 Linux 시스템 아티팩트 수집 필터를 정의합니다.
ext2/3/4 파일시스템에서 수집 가능한 모든 주요 아티팩트를 포함합니다.

Supported Distributions:
- Debian/Ubuntu
- RHEL/CentOS/Fedora
- Arch Linux
- SUSE
- Other systemd-based distributions

Categories:
1. System Logs - 시스템 로그
2. Authentication - 인증 관련
3. User Activity - 사용자 활동
4. Network - 네트워크 설정
5. Services - 서비스 및 데몬
6. Persistence - 지속성 메커니즘
7. Browser - 브라우저 아티팩트
8. Applications - 애플리케이션 데이터

Usage:
    from collectors.linux_artifacts import LINUX_ARTIFACT_FILTERS

    for artifact_id, config in LINUX_ARTIFACT_FILTERS.items():
        paths = config['paths']
        description = config['description']
        forensic_value = config['forensic_value']
"""

from typing import Dict, List, Any

# ==============================================================================
# Linux Artifact Filter Definitions
# ==============================================================================

LINUX_ARTIFACT_FILTERS: Dict[str, Dict[str, Any]] = {

    # ==========================================================================
    # System Logs (시스템 로그)
    # ==========================================================================

    'linux_syslog': {
        'paths': [
            '/var/log/syslog',           # Debian/Ubuntu
            '/var/log/messages',         # RHEL/CentOS
        ],
        'description': '시스템 로그 (커널, 서비스 메시지)',
        'forensic_value': 'high',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_auth_log': {
        'paths': [
            '/var/log/auth.log',         # Debian/Ubuntu
            '/var/log/secure',           # RHEL/CentOS
        ],
        'description': '인증 로그 (로그인, sudo, SSH)',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_kern_log': {
        'paths': [
            '/var/log/kern.log',         # Debian/Ubuntu
            '/var/log/dmesg',            # 커널 메시지
        ],
        'description': '커널 로그 (하드웨어, 드라이버)',
        'forensic_value': 'high',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_boot_log': {
        'paths': [
            '/var/log/boot.log',
            '/var/log/boot.msg',         # SUSE
        ],
        'description': '부팅 로그',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_daemon_log': {
        'paths': [
            '/var/log/daemon.log',
        ],
        'description': '데몬 서비스 로그',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_cron_log': {
        'paths': [
            '/var/log/cron',
            '/var/log/cron.log',
        ],
        'description': 'Cron 작업 로그',
        'forensic_value': 'high',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    'linux_mail_log': {
        'paths': [
            '/var/log/mail.log',
            '/var/log/maillog',
        ],
        'description': '메일 서버 로그',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_apt_log': {
        'paths': [
            '/var/log/apt/history.log',
            '/var/log/apt/term.log',
        ],
        'description': 'APT 패키지 설치 로그 (Debian/Ubuntu)',
        'forensic_value': 'high',
        'category': 'package_manager',
        'os_type': 'linux',
    },

    'linux_yum_log': {
        'paths': [
            '/var/log/yum.log',
            '/var/log/dnf.log',
        ],
        'description': 'YUM/DNF 패키지 설치 로그 (RHEL/CentOS/Fedora)',
        'forensic_value': 'high',
        'category': 'package_manager',
        'os_type': 'linux',
    },

    'linux_dpkg_log': {
        'paths': [
            '/var/log/dpkg.log',
        ],
        'description': 'DPKG 패키지 로그',
        'forensic_value': 'high',
        'category': 'package_manager',
        'os_type': 'linux',
    },

    'linux_audit_log': {
        'paths': [
            '/var/log/audit/audit.log',
        ],
        'description': 'Audit 로그 (SELinux, 보안 이벤트)',
        'forensic_value': 'critical',
        'category': 'security',
        'os_type': 'linux',
    },

    'linux_faillog': {
        'paths': [
            '/var/log/faillog',
            '/var/log/btmp',             # 실패한 로그인 시도
        ],
        'description': '로그인 실패 기록',
        'forensic_value': 'high',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_lastlog': {
        'paths': [
            '/var/log/lastlog',
            '/var/log/wtmp',             # 로그인 세션 기록
            '/var/run/utmp',             # 현재 로그인 사용자
        ],
        'description': '로그인 세션 기록',
        'forensic_value': 'high',
        'category': 'authentication',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Authentication & Users (인증 및 사용자)
    # ==========================================================================

    'linux_passwd': {
        'paths': [
            '/etc/passwd',
        ],
        'description': '사용자 계정 정보',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_shadow': {
        'paths': [
            '/etc/shadow',
        ],
        'description': '암호화된 비밀번호 해시',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_group': {
        'paths': [
            '/etc/group',
            '/etc/gshadow',
        ],
        'description': '그룹 정보',
        'forensic_value': 'high',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_sudoers': {
        'paths': [
            '/etc/sudoers',
            '/etc/sudoers.d/*',
        ],
        'description': 'sudo 권한 설정',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    # ==========================================================================
    # User Activity (사용자 활동)
    # ==========================================================================

    'linux_bash_history': {
        'paths': [
            '/home/*/.bash_history',
            '/root/.bash_history',
        ],
        'description': 'Bash 명령어 히스토리',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,  # 파일명으로 검색 허용
    },

    'linux_zsh_history': {
        'paths': [
            '/home/*/.zsh_history',
            '/home/*/.zhistory',
            '/root/.zsh_history',
        ],
        'description': 'Zsh 명령어 히스토리',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_fish_history': {
        'paths': [
            '/home/*/.local/share/fish/fish_history',
        ],
        'description': 'Fish 명령어 히스토리',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_bashrc': {
        'paths': [
            '/home/*/.bashrc',
            '/home/*/.bash_profile',
            '/home/*/.profile',
            '/root/.bashrc',
            '/etc/bash.bashrc',
        ],
        'description': 'Bash 설정 파일 (별칭, 환경변수)',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
    },

    'linux_viminfo': {
        'paths': [
            '/home/*/.viminfo',
            '/root/.viminfo',
        ],
        'description': 'Vim 편집기 히스토리',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_recent_files': {
        'paths': [
            '/home/*/.local/share/recently-used.xbel',
        ],
        'description': '최근 사용 파일 (GNOME)',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
    },

    'linux_trash': {
        'paths': [
            '/home/*/.local/share/Trash/files/*',
            '/home/*/.local/share/Trash/info/*',
        ],
        'description': '휴지통 내용',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
    },

    # ==========================================================================
    # SSH & Remote Access (SSH 및 원격 접속)
    # ==========================================================================

    'linux_ssh_config': {
        'paths': [
            '/etc/ssh/sshd_config',
            '/etc/ssh/ssh_config',
            '/home/*/.ssh/config',
        ],
        'description': 'SSH 설정',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_ssh_known_hosts': {
        'paths': [
            '/home/*/.ssh/known_hosts',
            '/root/.ssh/known_hosts',
            '/etc/ssh/ssh_known_hosts',
        ],
        'description': 'SSH 접속 호스트 기록',
        'forensic_value': 'critical',
        'category': 'network',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_ssh_authorized_keys': {
        'paths': [
            '/home/*/.ssh/authorized_keys',
            '/root/.ssh/authorized_keys',
        ],
        'description': 'SSH 인증된 공개키',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_ssh_private_keys': {
        'paths': [
            '/home/*/.ssh/id_rsa',
            '/home/*/.ssh/id_ed25519',
            '/home/*/.ssh/id_ecdsa',
            '/root/.ssh/id_rsa',
        ],
        'description': 'SSH 개인키 (민감)',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # Network Configuration (네트워크 설정)
    # ==========================================================================

    'linux_hosts': {
        'paths': [
            '/etc/hosts',
            '/etc/hosts.allow',
            '/etc/hosts.deny',
        ],
        'description': 'Hosts 파일',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_resolv': {
        'paths': [
            '/etc/resolv.conf',
        ],
        'description': 'DNS 설정',
        'forensic_value': 'medium',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_network_interfaces': {
        'paths': [
            '/etc/network/interfaces',
            '/etc/sysconfig/network-scripts/ifcfg-*',
            '/etc/netplan/*.yaml',
        ],
        'description': '네트워크 인터페이스 설정',
        'forensic_value': 'medium',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_iptables': {
        'paths': [
            '/etc/iptables/rules.v4',
            '/etc/iptables/rules.v6',
            '/etc/sysconfig/iptables',
        ],
        'description': '방화벽 규칙',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Scheduled Tasks (예약 작업)
    # ==========================================================================

    'linux_crontab': {
        'paths': [
            '/etc/crontab',
            '/etc/cron.d/*',
            '/etc/cron.daily/*',
            '/etc/cron.hourly/*',
            '/etc/cron.weekly/*',
            '/etc/cron.monthly/*',
            '/var/spool/cron/crontabs/*',
        ],
        'description': 'Cron 예약 작업',
        'forensic_value': 'critical',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    'linux_anacron': {
        'paths': [
            '/etc/anacrontab',
        ],
        'description': 'Anacron 예약 작업',
        'forensic_value': 'high',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    'linux_at_jobs': {
        'paths': [
            '/var/spool/at/*',
            '/var/spool/atjobs/*',
        ],
        'description': 'at 예약 작업',
        'forensic_value': 'high',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    'linux_systemd_timers': {
        'paths': [
            '/etc/systemd/system/*.timer',
            '/usr/lib/systemd/system/*.timer',
            '/home/*/.config/systemd/user/*.timer',
        ],
        'description': 'Systemd 타이머',
        'forensic_value': 'high',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Services & Daemons (서비스 및 데몬)
    # ==========================================================================

    'linux_systemd_services': {
        'paths': [
            '/etc/systemd/system/*.service',
            '/usr/lib/systemd/system/*.service',
            '/home/*/.config/systemd/user/*.service',
        ],
        'description': 'Systemd 서비스 정의',
        'forensic_value': 'critical',
        'category': 'services',
        'os_type': 'linux',
    },

    'linux_init_scripts': {
        'paths': [
            '/etc/init.d/*',
            '/etc/rc.local',
        ],
        'description': 'SysV init 스크립트',
        'forensic_value': 'high',
        'category': 'services',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Persistence Mechanisms (지속성 메커니즘)
    # ==========================================================================

    'linux_autostart': {
        'paths': [
            '/etc/xdg/autostart/*.desktop',
            '/home/*/.config/autostart/*.desktop',
        ],
        'description': '자동 시작 항목 (GUI)',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
    },

    'linux_profile_scripts': {
        'paths': [
            '/etc/profile',
            '/etc/profile.d/*',
            '/etc/environment',
        ],
        'description': '로그인 시 실행 스크립트',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
    },

    'linux_ld_preload': {
        'paths': [
            '/etc/ld.so.preload',
            '/etc/ld.so.conf',
            '/etc/ld.so.conf.d/*',
        ],
        'description': '동적 라이브러리 프리로드 설정',
        'forensic_value': 'critical',
        'category': 'persistence',
        'os_type': 'linux',
    },

    'linux_modules': {
        'paths': [
            '/etc/modules',
            '/etc/modprobe.d/*',
            '/etc/modules-load.d/*',
        ],
        'description': '커널 모듈 설정',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Browser Artifacts (브라우저 아티팩트)
    # ==========================================================================

    'linux_firefox': {
        'paths': [
            '/home/*/.mozilla/firefox/*.default*/places.sqlite',
            '/home/*/.mozilla/firefox/*.default*/cookies.sqlite',
            '/home/*/.mozilla/firefox/*.default*/formhistory.sqlite',
            '/home/*/.mozilla/firefox/*.default*/logins.json',
            '/home/*/.mozilla/firefox/*.default*/key4.db',
        ],
        'description': 'Firefox 브라우저 데이터',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_chrome': {
        'paths': [
            '/home/*/.config/google-chrome/Default/History',
            '/home/*/.config/google-chrome/Default/Cookies',
            '/home/*/.config/google-chrome/Default/Login Data',
            '/home/*/.config/google-chrome/Default/Bookmarks',
            '/home/*/.config/google-chrome/Default/Web Data',
        ],
        'description': 'Chrome 브라우저 데이터',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_chromium': {
        'paths': [
            '/home/*/.config/chromium/Default/History',
            '/home/*/.config/chromium/Default/Cookies',
            '/home/*/.config/chromium/Default/Login Data',
        ],
        'description': 'Chromium 브라우저 데이터',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # Application Data (애플리케이션 데이터)
    # ==========================================================================

    'linux_docker': {
        'paths': [
            '/var/lib/docker/containers/*/*.json',
            '/etc/docker/daemon.json',
        ],
        'description': 'Docker 컨테이너 정보',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_mysql': {
        'paths': [
            '/var/log/mysql/error.log',
            '/var/lib/mysql/*.err',
            '/home/*/.mysql_history',
        ],
        'description': 'MySQL 로그 및 히스토리',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_postgresql': {
        'paths': [
            '/var/log/postgresql/*.log',
            '/home/*/.psql_history',
        ],
        'description': 'PostgreSQL 로그 및 히스토리',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_apache': {
        'paths': [
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/httpd/access_log',
            '/var/log/httpd/error_log',
        ],
        'description': 'Apache 웹 서버 로그',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_nginx': {
        'paths': [
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
        ],
        'description': 'Nginx 웹 서버 로그',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_git': {
        'paths': [
            '/home/*/.gitconfig',
            '/home/*/.git-credentials',
        ],
        'description': 'Git 설정 및 자격 증명',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # System Configuration (시스템 설정)
    # ==========================================================================

    'linux_os_release': {
        'paths': [
            '/etc/os-release',
            '/etc/lsb-release',
            '/etc/redhat-release',
            '/etc/debian_version',
        ],
        'description': 'OS 버전 정보',
        'forensic_value': 'medium',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_hostname': {
        'paths': [
            '/etc/hostname',
            '/etc/machine-id',
        ],
        'description': '호스트명 및 머신 ID',
        'forensic_value': 'medium',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_fstab': {
        'paths': [
            '/etc/fstab',
        ],
        'description': '파일 시스템 마운트 설정',
        'forensic_value': 'medium',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_timezone': {
        'paths': [
            '/etc/timezone',
            '/etc/localtime',
        ],
        'description': '시간대 설정',
        'forensic_value': 'low',
        'category': 'system_config',
        'os_type': 'linux',
    },
}


# ==============================================================================
# Helper Functions
# ==============================================================================

def get_linux_artifacts_by_category(category: str) -> Dict[str, Dict[str, Any]]:
    """카테고리별 Linux 아티팩트 반환"""
    return {
        k: v for k, v in LINUX_ARTIFACT_FILTERS.items()
        if v.get('category') == category
    }


def get_linux_artifacts_by_forensic_value(value: str) -> Dict[str, Dict[str, Any]]:
    """포렌식 가치별 Linux 아티팩트 반환"""
    return {
        k: v for k, v in LINUX_ARTIFACT_FILTERS.items()
        if v.get('forensic_value') == value
    }


def get_all_linux_artifact_paths() -> List[str]:
    """모든 Linux 아티팩트 경로 반환 (와일드카드 포함)"""
    paths = []
    for config in LINUX_ARTIFACT_FILTERS.values():
        paths.extend(config.get('paths', []))
    return paths


def get_linux_categories() -> List[str]:
    """Linux 아티팩트 카테고리 목록 반환"""
    categories = set()
    for config in LINUX_ARTIFACT_FILTERS.values():
        if 'category' in config:
            categories.add(config['category'])
    return sorted(list(categories))


# 아티팩트 통계
LINUX_ARTIFACT_STATS = {
    'total_artifacts': len(LINUX_ARTIFACT_FILTERS),
    'categories': get_linux_categories(),
    'critical_artifacts': len(get_linux_artifacts_by_forensic_value('critical')),
    'high_artifacts': len(get_linux_artifacts_by_forensic_value('high')),
}
