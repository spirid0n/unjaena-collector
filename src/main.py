#!/usr/bin/env python3
"""
Digital Forensics Collector - Main Entry Point

This tool collects forensic artifacts from Windows systems
and uploads them to the forensics server for analysis.
"""
import sys
import os
import json

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication, QMessageBox
from PyQt6.QtCore import Qt

from gui.app import CollectorWindow
from utils.privilege import is_admin, run_as_admin


# =============================================================================
# P1 보안 강화: HTTPS/WSS 필수화
# =============================================================================

def _get_config_paths() -> list:
    """
    설정 파일 검색 경로 반환 (우선순위순)

    1. 실행 파일과 같은 디렉토리 (PyInstaller 빌드 시)
    2. collector 루트 디렉토리 (개발 환경)
    3. src 디렉토리
    """
    paths = []

    # PyInstaller 빌드된 경우 실행 파일 위치
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        paths.append(os.path.join(exe_dir, 'config.json'))

    # 개발 환경: collector 루트 및 src 디렉토리
    src_dir = os.path.dirname(os.path.abspath(__file__))
    collector_dir = os.path.dirname(src_dir)

    paths.append(os.path.join(collector_dir, 'config.json'))
    paths.append(os.path.join(src_dir, 'config.json'))

    return paths


def _load_config_file() -> dict | None:
    """
    설정 파일에서 구성 로드

    Returns:
        설정 딕셔너리 또는 None (파일 없음)
    """
    for config_path in _get_config_paths():
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    print(f"[설정] 설정 파일 로드: {config_path}")
                    return config
            except (json.JSONDecodeError, IOError) as e:
                print(f"[경고] 설정 파일 로드 실패: {config_path} - {e}")
                continue
    return None


def get_secure_config() -> dict:
    """
    보안 설정이 적용된 구성 반환

    우선순위:
        1. 환경변수 (가장 높은 우선순위)
        2. config.json 파일 (빌드 시 포함)
        3. 기본값 (개발용 fallback)

    환경변수:
        COLLECTOR_SERVER_URL: 서버 URL
        COLLECTOR_WS_URL: WebSocket URL
        COLLECTOR_DEV_MODE: 개발 모드 (true/false)
        COLLECTOR_ALLOW_INSECURE: 비보안 연결 허용 (true/false)

    배포 빌드 시:
        config.json 파일에 운영 서버 URL 포함하여 빌드
        → 사용자가 별도 설정 없이 실행만 하면 자동 연결

    개발 환경에서는:
        환경변수로 COLLECTOR_DEV_MODE=true 설정
    """
    # Step 1: 설정 파일에서 기본값 로드
    file_config = _load_config_file() or {}

    # Step 2: 환경변수로 오버라이드 (환경변수가 우선순위 높음)
    # 환경변수가 설정되지 않은 경우 파일 설정 → 기본값 순으로 fallback
    dev_mode_default = str(file_config.get('dev_mode', 'false')).lower()
    allow_insecure_default = str(file_config.get('allow_insecure', 'false')).lower()

    dev_mode = os.environ.get('COLLECTOR_DEV_MODE', dev_mode_default).lower() == 'true'
    allow_insecure = os.environ.get('COLLECTOR_ALLOW_INSECURE', allow_insecure_default).lower() == 'true'

    # URL 설정: 환경변수 → 파일 → 기본값
    # NOTE: Windows에서 'localhost'가 IPv6(::1)로 해석되어 Docker 연결 실패할 수 있음
    server_url = os.environ.get(
        'COLLECTOR_SERVER_URL',
        file_config.get('server_url', 'https://127.0.0.1:8000')
    )
    ws_url = os.environ.get(
        'COLLECTOR_WS_URL',
        file_config.get('ws_url', 'wss://127.0.0.1:8000')
    )

    # [보안] HTTPS/WSS 강제 및 경고
    if allow_insecure:
        print("=" * 60)
        print("[보안 경고] allow_insecure=true 설정됨!")
        print("[보안 경고] 데이터가 암호화되지 않은 채 전송됩니다.")
        print("[보안 경고] 운영 환경에서는 절대 사용하지 마세요!")
        print("=" * 60)
    elif not dev_mode:
        # 프로덕션 모드에서 HTTPS/WSS 강제
        if server_url.startswith('http://'):
            print("[보안 경고] HTTP 연결이 감지되었습니다. HTTPS로 변환합니다.")
            server_url = server_url.replace('http://', 'https://', 1)

        if ws_url.startswith('ws://'):
            print("[보안 경고] WS 연결이 감지되었습니다. WSS로 변환합니다.")
            ws_url = ws_url.replace('ws://', 'wss://', 1)

    config = {
        'server_url': server_url,
        'ws_url': ws_url,
        'version': file_config.get('version', '2.0.0'),
        'app_name': file_config.get('app_name', 'Digital Forensics Collector'),
        'dev_mode': dev_mode,
        'allow_insecure': allow_insecure,
    }

    # 설정 요약 출력
    mode_str = "개발" if dev_mode else "운영"
    print(f"[설정] 모드: {mode_str}, 서버: {server_url}")

    return config


# Configuration (P1: 보안 설정 적용)
CONFIG = get_secure_config()


def check_admin_privilege():
    """Check if running as administrator"""
    if not is_admin():
        # Show warning message in Korean
        msg_box = QMessageBox()
        msg_box.setIcon(QMessageBox.Icon.Warning)
        msg_box.setWindowTitle("관리자 권한 필요")
        msg_box.setText("이 수집 도구는 관리자 권한이 필요합니다.")
        msg_box.setInformativeText(
            "포렌식 아티팩트를 정확하게 수집하기 위해서는 관리자 권한으로 "
            "실행해야 합니다.\n\n"
            "관리자 권한으로 다시 실행하시겠습니까?"
        )
        msg_box.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        msg_box.setDefaultButton(QMessageBox.StandardButton.Yes)
        msg_box.button(QMessageBox.StandardButton.Yes).setText("예, 다시 실행")
        msg_box.button(QMessageBox.StandardButton.No).setText("아니오, 종료")

        reply = msg_box.exec()

        if reply == QMessageBox.StandardButton.Yes:
            if run_as_admin():
                # Elevation requested successfully, exit current process
                sys.exit(0)
            else:
                # Failed to request elevation
                QMessageBox.critical(
                    None,
                    "오류",
                    "관리자 권한으로 실행할 수 없습니다.\n"
                    "프로그램을 마우스 오른쪽 버튼으로 클릭하고 "
                    "'관리자 권한으로 실행'을 선택하세요."
                )
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
