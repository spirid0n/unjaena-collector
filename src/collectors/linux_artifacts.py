# -*- coding: utf-8 -*-
"""
Linux Artifact Definitions - Linux System Artifact Collection Definitions

Defines Linux system artifact collection filters for digital forensics.
Includes all major artifacts collectable from ext2/3/4 file systems.

Supported Distributions:
- Debian/Ubuntu
- RHEL/CentOS/Fedora
- Arch Linux
- SUSE
- Other systemd-based distributions

Categories:
1. System Logs
2. Authentication
3. User Activity
4. Network Settings
5. Services and Daemons
6. Persistence Mechanisms
7. Browser Artifacts
8. Application Data

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
    # System Logs
    # ==========================================================================

    'linux_syslog': {
        'paths': [
            '/var/log/syslog',           # Debian/Ubuntu
            '/var/log/messages',         # RHEL/CentOS
        ],
        'description': 'System log (kernel, service messages)',
        'forensic_value': 'high',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_auth_log': {
        'paths': [
            '/var/log/auth.log',         # Debian/Ubuntu
            '/var/log/secure',           # RHEL/CentOS
        ],
        'description': 'Authentication log (login, sudo, SSH)',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_kern_log': {
        'paths': [
            '/var/log/kern.log',         # Debian/Ubuntu
            '/var/log/dmesg',            # Kernel messages
        ],
        'description': 'Kernel log (hardware, drivers)',
        'forensic_value': 'high',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_boot_log': {
        'paths': [
            '/var/log/boot.log',
            '/var/log/boot.msg',         # SUSE
        ],
        'description': 'Boot log',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_daemon_log': {
        'paths': [
            '/var/log/daemon.log',
        ],
        'description': 'Daemon service log',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_cron_log': {
        'paths': [
            '/var/log/cron',
            '/var/log/cron.log',
        ],
        'description': 'Cron job log',
        'forensic_value': 'high',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    'linux_mail_log': {
        'paths': [
            '/var/log/mail.log',
            '/var/log/maillog',
        ],
        'description': 'Mail server log',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_apt_log': {
        'paths': [
            '/var/log/apt/history.log',
            '/var/log/apt/term.log',
        ],
        'description': 'APT package installation log (Debian/Ubuntu)',
        'forensic_value': 'high',
        'category': 'package_manager',
        'os_type': 'linux',
    },

    'linux_yum_log': {
        'paths': [
            '/var/log/yum.log',
            '/var/log/dnf.log',
        ],
        'description': 'YUM/DNF package installation log (RHEL/CentOS/Fedora)',
        'forensic_value': 'high',
        'category': 'package_manager',
        'os_type': 'linux',
    },

    'linux_dpkg_log': {
        'paths': [
            '/var/log/dpkg.log',
        ],
        'description': 'DPKG package log',
        'forensic_value': 'high',
        'category': 'package_manager',
        'os_type': 'linux',
    },

    'linux_audit_log': {
        'paths': [
            '/var/log/audit/audit.log',
        ],
        'description': 'Audit log (SELinux, security events)',
        'forensic_value': 'critical',
        'category': 'security',
        'os_type': 'linux',
    },

    'linux_faillog': {
        'paths': [
            '/var/log/faillog',
            '/var/log/btmp',             # Failed login attempts
        ],
        'description': 'Login failure records',
        'forensic_value': 'high',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_lastlog': {
        'paths': ['/var/log/lastlog'],
        'description': 'Last login time per user (binary)',
        'forensic_value': 'high',
        'category': 'authentication',
        'os_type': 'linux',
    },
    'linux_wtmp': {
        'paths': ['/var/log/wtmp', '/var/log/wtmp.*'],
        'description': 'Login/logout session history (binary)',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },
    'linux_btmp': {
        'paths': ['/var/log/btmp', '/var/log/btmp.*'],
        'description': 'Failed login attempts (binary)',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },
    'linux_utmp': {
        'paths': ['/var/run/utmp', '/run/utmp'],
        'description': 'Currently logged-in users (binary)',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },
    'linux_rc_local': {
        'paths': ['/etc/rc.local', '/etc/rc.d/rc.local'],
        'description': 'Legacy startup script (persistence)',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Authentication & Users
    # ==========================================================================

    'linux_passwd': {
        'paths': [
            '/etc/passwd',
        ],
        'description': 'User account information',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_shadow': {
        'paths': [
            '/etc/shadow',
        ],
        'description': 'Encrypted password hashes',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_group': {
        'paths': [
            '/etc/group',
            '/etc/gshadow',
        ],
        'description': 'Group information',
        'forensic_value': 'high',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_sudoers': {
        'paths': [
            '/etc/sudoers',
            '/etc/sudoers.d/*',
        ],
        'description': 'sudo privilege configuration',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    # ==========================================================================
    # User Activity
    # ==========================================================================

    'linux_bash_history': {
        'paths': [
            '/home/*/.bash_history',
            '/root/.bash_history',
        ],
        'description': 'Bash command history',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,  # Allow search by filename
    },

    'linux_zsh_history': {
        'paths': [
            '/home/*/.zsh_history',
            '/home/*/.zhistory',
            '/root/.zsh_history',
        ],
        'description': 'Zsh command history',
        'forensic_value': 'critical',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_fish_history': {
        'paths': [
            '/home/*/.local/share/fish/fish_history',
        ],
        'description': 'Fish command history',
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
        'description': 'Bash configuration files (aliases, environment variables)',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
    },

    'linux_viminfo': {
        'paths': [
            '/home/*/.viminfo',
            '/root/.viminfo',
        ],
        'description': 'Vim editor history',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_recent_files': {
        'paths': [
            '/home/*/.local/share/recently-used.xbel',
        ],
        'description': 'Recently used files (GNOME)',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
    },

    'linux_trash': {
        'paths': [
            '/home/*/.local/share/Trash/files/*',
            '/home/*/.local/share/Trash/info/*',
        ],
        'description': 'Trash contents',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
    },

    # ==========================================================================
    # SSH & Remote Access
    # ==========================================================================

    'linux_ssh_config': {
        'paths': [
            '/etc/ssh/sshd_config',
            '/etc/ssh/ssh_config',
            '/home/*/.ssh/config',
        ],
        'description': 'SSH configuration',
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
        'description': 'SSH connection host records',
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
        'description': 'SSH authorized public keys',
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
        'description': 'SSH private keys (sensitive)',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # Network Configuration
    # ==========================================================================

    'linux_hosts': {
        'paths': [
            '/etc/hosts',
            '/etc/hosts.allow',
            '/etc/hosts.deny',
        ],
        'description': 'Hosts file',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_resolv': {
        'paths': [
            '/etc/resolv.conf',
        ],
        'description': 'DNS settings',
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
        'description': 'Network interface settings',
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
        'description': 'Firewall rules',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Scheduled Tasks
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
        'description': 'Cron scheduled tasks',
        'forensic_value': 'critical',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    'linux_anacron': {
        'paths': [
            '/etc/anacrontab',
        ],
        'description': 'Anacron scheduled tasks',
        'forensic_value': 'high',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    'linux_at_jobs': {
        'paths': [
            '/var/spool/at/*',
            '/var/spool/atjobs/*',
        ],
        'description': 'at scheduled tasks',
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
        'description': 'Systemd timers',
        'forensic_value': 'high',
        'category': 'scheduled_tasks',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Services & Daemons
    # ==========================================================================

    'linux_systemd_service': {
        'paths': [
            '/etc/systemd/system/*.service',
            '/usr/lib/systemd/system/*.service',
            '/home/*/.config/systemd/user/*.service',
        ],
        'description': 'Systemd service definitions',
        'forensic_value': 'critical',
        'category': 'services',
        'os_type': 'linux',
    },

    'linux_init_scripts': {
        'paths': [
            '/etc/init.d/*',
            '/etc/rc.local',
        ],
        'description': 'SysV init scripts',
        'forensic_value': 'high',
        'category': 'services',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Persistence Mechanisms
    # ==========================================================================

    'linux_autostart': {
        'paths': [
            '/etc/xdg/autostart/*.desktop',
            '/home/*/.config/autostart/*.desktop',
        ],
        'description': 'Auto-start items (GUI)',
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
        'description': 'Login execution scripts',
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
        'description': 'Dynamic library preload settings',
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
        'description': 'Kernel module settings',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Browser Artifacts
    # ==========================================================================

    'linux_firefox': {
        'paths': [
            '/home/*/.mozilla/firefox/*.default*/places.sqlite',
            '/home/*/.mozilla/firefox/*.default*/cookies.sqlite',
            '/home/*/.mozilla/firefox/*.default*/formhistory.sqlite',
            '/home/*/.mozilla/firefox/*.default*/logins.json',
            '/home/*/.mozilla/firefox/*.default*/key4.db',
        ],
        'description': 'Firefox browser data',
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
        'description': 'Chrome browser data',
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
        'description': 'Chromium browser data',
        'forensic_value': 'high',
        'category': 'browser',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # Application Data
    # ==========================================================================

    'linux_docker': {
        'paths': [
            '/var/lib/docker/containers/*/*.json',
            '/etc/docker/daemon.json',
        ],
        'description': 'Docker container information',
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
        'description': 'MySQL logs and history',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_postgresql': {
        'paths': [
            '/var/log/postgresql/*.log',
            '/home/*/.psql_history',
        ],
        'description': 'PostgreSQL logs and history',
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
        'description': 'Apache web server logs',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_nginx': {
        'paths': [
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
        ],
        'description': 'Nginx web server logs',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_git': {
        'paths': [
            '/home/*/.gitconfig',
            '/home/*/.git-credentials',
        ],
        'description': 'Git settings and credentials',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # System Configuration
    # ==========================================================================

    'linux_os_release': {
        'paths': [
            '/etc/os-release',
            '/etc/lsb-release',
            '/etc/redhat-release',
            '/etc/debian_version',
        ],
        'description': 'OS version information',
        'forensic_value': 'medium',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_hostname': {
        'paths': [
            '/etc/hostname',
            '/etc/machine-id',
        ],
        'description': 'Hostname and machine ID',
        'forensic_value': 'medium',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_fstab': {
        'paths': [
            '/etc/fstab',
        ],
        'description': 'File system mount settings',
        'forensic_value': 'medium',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_timezone': {
        'paths': [
            '/etc/timezone',
            '/etc/localtime',
        ],
        'description': 'Timezone settings',
        'forensic_value': 'low',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_sysctl': {
        'paths': [
            '/etc/sysctl.conf',
            '/etc/sysctl.d/*.conf',
        ],
        'description': 'Kernel parameter configuration (network forwarding, ASLR)',
        'forensic_value': 'high',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_login_defs': {
        'paths': [
            '/etc/login.defs',
        ],
        'description': 'Login policy (password aging, UID ranges)',
        'forensic_value': 'medium',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_selinux': {
        'paths': [
            '/etc/selinux/config',
        ],
        'description': 'SELinux security configuration',
        'forensic_value': 'high',
        'category': 'security',
        'os_type': 'linux',
    },

    'linux_apparmor': {
        'paths': [
            '/etc/apparmor.d/*',
            '/etc/apparmor/parser.conf',
        ],
        'description': 'AppArmor mandatory access control profiles',
        'forensic_value': 'high',
        'category': 'security',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional User Activity
    # ==========================================================================

    'linux_python_history': {
        'paths': [
            '/home/*/.python_history',
            '/root/.python_history',
        ],
        'description': 'Python interactive shell history',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_mysql_history': {
        'paths': [
            '/home/*/.mysql_history',
            '/root/.mysql_history',
        ],
        'description': 'MySQL CLI command history',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_psql_history': {
        'paths': [
            '/home/*/.psql_history',
            '/root/.psql_history',
        ],
        'description': 'PostgreSQL CLI command history',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_lesshst': {
        'paths': [
            '/home/*/.lesshst',
            '/root/.lesshst',
        ],
        'description': 'Less pager search and command history',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_nano_history': {
        'paths': [
            '/home/*/.nano/search_history',
            '/root/.nano/search_history',
        ],
        'description': 'Nano editor search history',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_wget_hsts': {
        'paths': [
            '/home/*/.wget-hsts',
            '/root/.wget-hsts',
        ],
        'description': 'Wget HSTS cache (evidence of file downloads)',
        'forensic_value': 'high',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_xsession_errors': {
        'paths': [
            '/home/*/.xsession-errors',
            '/home/*/.xsession-errors.old',
        ],
        'description': 'X11 session errors (GUI application crashes, execution evidence)',
        'forensic_value': 'medium',
        'category': 'user_activity',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # Additional Authentication & Security
    # ==========================================================================

    'linux_pam_config': {
        'paths': [
            '/etc/pam.d/common-auth',
            '/etc/pam.d/common-password',
            '/etc/pam.d/sshd',
            '/etc/pam.d/sudo',
            '/etc/pam.d/login',
            '/etc/pam.d/su',
        ],
        'description': 'PAM authentication module configuration',
        'forensic_value': 'critical',
        'category': 'authentication',
        'os_type': 'linux',
    },

    'linux_security_limits': {
        'paths': [
            '/etc/security/limits.conf',
            '/etc/security/limits.d/*',
            '/etc/security/access.conf',
        ],
        'description': 'Security limits and access control configuration',
        'forensic_value': 'medium',
        'category': 'security',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional System Logs
    # ==========================================================================

    'linux_journald': {
        'paths': [
            '/var/log/journal/*/*.journal',
            '/var/log/journal/*/*.journal~',
        ],
        'description': 'Systemd journal binary logs (persistent journald)',
        'forensic_value': 'critical',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_ufw_log': {
        'paths': [
            '/var/log/ufw.log',
            '/var/log/ufw.log.*',
        ],
        'description': 'UFW firewall log (Debian/Ubuntu)',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional Network
    # ==========================================================================

    'linux_networkmanager': {
        'paths': [
            '/etc/NetworkManager/NetworkManager.conf',
            '/etc/NetworkManager/system-connections/*',
        ],
        'description': 'NetworkManager configuration and saved connections (may contain WiFi PSK)',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_wifi_config': {
        'paths': [
            '/etc/wpa_supplicant/wpa_supplicant.conf',
            '/etc/wpa_supplicant/*.conf',
        ],
        'description': 'WPA supplicant WiFi configuration (SSID, PSK)',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    'linux_nftables': {
        'paths': [
            '/etc/nftables.conf',
            '/etc/nftables.d/*.nft',
        ],
        'description': 'nftables firewall rules',
        'forensic_value': 'high',
        'category': 'network',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional Persistence Mechanisms
    # ==========================================================================

    'linux_systemd_generators': {
        'paths': [
            '/etc/systemd/system-generators/*',
            '/usr/lib/systemd/system-generators/*',
        ],
        'description': 'Systemd generators (run at boot before services)',
        'forensic_value': 'critical',
        'category': 'persistence',
        'os_type': 'linux',
    },

    'linux_udev_rules': {
        'paths': [
            '/etc/udev/rules.d/*.rules',
            '/usr/lib/udev/rules.d/*.rules',
        ],
        'description': 'Udev device event rules (triggers on device insertion)',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
    },

    'linux_motd': {
        'paths': [
            '/etc/motd',
            '/etc/update-motd.d/*',
        ],
        'description': 'Message of the day scripts (executed at login)',
        'forensic_value': 'medium',
        'category': 'persistence',
        'os_type': 'linux',
    },

    'linux_xprofile': {
        'paths': [
            '/home/*/.xprofile',
            '/home/*/.xinitrc',
            '/home/*/.xsessionrc',
            '/etc/X11/Xsession.d/*',
        ],
        'description': 'X11 login scripts (persistence via GUI session)',
        'forensic_value': 'high',
        'category': 'persistence',
        'os_type': 'linux',
        'path_optional': True,
    },

    # ==========================================================================
    # Additional Web Server / Application Logs
    # ==========================================================================

    'linux_apache_config': {
        'paths': [
            '/etc/apache2/apache2.conf',
            '/etc/apache2/sites-enabled/*',
            '/etc/httpd/conf/httpd.conf',
            '/etc/httpd/conf.d/*',
        ],
        'description': 'Apache web server configuration',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_nginx_config': {
        'paths': [
            '/etc/nginx/nginx.conf',
            '/etc/nginx/sites-enabled/*',
            '/etc/nginx/conf.d/*',
        ],
        'description': 'Nginx web server configuration',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_php_log': {
        'paths': [
            '/var/log/php*.log',
            '/var/log/php-fpm/*.log',
        ],
        'description': 'PHP error and FPM logs',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional Container / Virtualization
    # ==========================================================================

    'linux_docker_containers': {
        'paths': [
            '/var/lib/docker/containers/*/*-json.log',
        ],
        'description': 'Docker container stdout/stderr logs',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_podman': {
        'paths': [
            '/home/*/.config/containers/containers.conf',
            '/etc/containers/containers.conf',
            '/etc/containers/registries.conf',
        ],
        'description': 'Podman container engine configuration',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_libvirt': {
        'paths': [
            '/etc/libvirt/qemu/*.xml',
            '/var/log/libvirt/qemu/*.log',
        ],
        'description': 'KVM/QEMU virtual machine definitions and logs',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional Database Artifacts
    # ==========================================================================

    'linux_redis': {
        'paths': [
            '/etc/redis/redis.conf',
            '/etc/redis.conf',
            '/var/log/redis/redis-server.log',
        ],
        'description': 'Redis configuration and server log',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    'linux_mongodb': {
        'paths': [
            '/etc/mongod.conf',
            '/var/log/mongodb/mongod.log',
        ],
        'description': 'MongoDB configuration and server log',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
    },

    # ==========================================================================
    # Additional Application Artifacts
    # ==========================================================================

    'linux_thunderbird': {
        'paths': [
            '/home/*/.thunderbird/*.default*/prefs.js',
            '/home/*/.thunderbird/*.default*/global-messages-db.sqlite',
            '/home/*/.thunderbird/*.default*/places.sqlite',
        ],
        'description': 'Thunderbird email client data',
        'forensic_value': 'high',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_aws_credentials': {
        'paths': [
            '/home/*/.aws/credentials',
            '/home/*/.aws/config',
            '/root/.aws/credentials',
        ],
        'description': 'AWS CLI credentials and configuration',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_gcloud_config': {
        'paths': [
            '/home/*/.config/gcloud/properties',
            '/home/*/.config/gcloud/credentials.db',
            '/home/*/.config/gcloud/access_tokens.db',
        ],
        'description': 'Google Cloud SDK configuration and credentials',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_azure_config': {
        'paths': [
            '/home/*/.azure/azureProfile.json',
            '/home/*/.azure/accessTokens.json',
            '/home/*/.azure/msal_token_cache.json',
        ],
        'description': 'Azure CLI configuration and token cache',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_kubectl_config': {
        'paths': [
            '/home/*/.kube/config',
            '/root/.kube/config',
        ],
        'description': 'Kubernetes kubectl configuration (cluster credentials)',
        'forensic_value': 'critical',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_screen_tmux': {
        'paths': [
            '/home/*/.screenrc',
            '/home/*/.tmux.conf',
            '/tmp/tmux-*/default',
        ],
        'description': 'Screen/tmux configuration and socket files',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_npm_config': {
        'paths': [
            '/home/*/.npmrc',
            '/root/.npmrc',
        ],
        'description': 'NPM configuration (may contain auth tokens)',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_pip_config': {
        'paths': [
            '/home/*/.pip/pip.conf',
            '/home/*/.config/pip/pip.conf',
            '/etc/pip.conf',
        ],
        'description': 'Python pip configuration (may contain index URLs, credentials)',
        'forensic_value': 'medium',
        'category': 'applications',
        'os_type': 'linux',
        'path_optional': True,
    },

    'linux_env_files': {
        'paths': [
            '/etc/environment',
            '/etc/default/locale',
        ],
        'description': 'System-wide environment variables',
        'forensic_value': 'medium',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_crypttab': {
        'paths': [
            '/etc/crypttab',
        ],
        'description': 'Encrypted device mapping (LUKS volumes)',
        'forensic_value': 'high',
        'category': 'system_config',
        'os_type': 'linux',
    },

    'linux_cups_log': {
        'paths': [
            '/var/log/cups/access_log',
            '/var/log/cups/error_log',
        ],
        'description': 'CUPS printing system log (document exfiltration evidence)',
        'forensic_value': 'medium',
        'category': 'system_logs',
        'os_type': 'linux',
    },

    'linux_snap_log': {
        'paths': [
            '/var/log/syslog',          # snap logs via syslog
            '/var/snap/*/common/*.log',
        ],
        'description': 'Snap package application logs',
        'forensic_value': 'low',
        'category': 'package_manager',
        'os_type': 'linux',
    },

    'linux_dmesg': {
        'paths': [
            '/var/log/dmesg',
            '/var/log/dmesg.0',
            '/var/log/dmesg.1.gz',
        ],
        'description': 'Kernel ring buffer dump (USB insertions, hardware changes)',
        'forensic_value': 'high',
        'category': 'system_logs',
        'os_type': 'linux',
    },
}


# ==============================================================================
# Helper Functions
# ==============================================================================

def get_linux_artifacts_by_category(category: str) -> Dict[str, Dict[str, Any]]:
    """Return Linux artifacts by category"""
    return {
        k: v for k, v in LINUX_ARTIFACT_FILTERS.items()
        if v.get('category') == category
    }


def get_linux_artifacts_by_forensic_value(value: str) -> Dict[str, Dict[str, Any]]:
    """Return Linux artifacts by forensic value"""
    return {
        k: v for k, v in LINUX_ARTIFACT_FILTERS.items()
        if v.get('forensic_value') == value
    }


def get_all_linux_artifact_paths() -> List[str]:
    """Return all Linux artifact paths (including wildcards)"""
    paths = []
    for config in LINUX_ARTIFACT_FILTERS.values():
        paths.extend(config.get('paths', []))
    return paths


def get_linux_categories() -> List[str]:
    """Return list of Linux artifact categories"""
    categories = set()
    for config in LINUX_ARTIFACT_FILTERS.values():
        if 'category' in config:
            categories.add(config['category'])
    return sorted(list(categories))


# Artifact statistics
LINUX_ARTIFACT_STATS = {
    'total_artifacts': len(LINUX_ARTIFACT_FILTERS),
    'categories': get_linux_categories(),
    'critical_artifacts': len(get_linux_artifacts_by_forensic_value('critical')),
    'high_artifacts': len(get_linux_artifacts_by_forensic_value('high')),
}
