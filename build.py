#!/usr/bin/env python3
"""
Collector Build Script

Usage:
    python build.py --production    # 운영 빌드 (운영 서버 URL 포함)
    python build.py --development   # 개발 빌드 (로컬 서버 URL 포함)
    python build.py                 # 기본: 운영 빌드
"""
import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='Build Forensic Collector')
    parser.add_argument(
        '--production', '-p',
        action='store_true',
        help='Production build (uses config.production.json)'
    )
    parser.add_argument(
        '--development', '-d',
        action='store_true',
        help='Development build (uses config.development.json)'
    )
    parser.add_argument(
        '--server-url',
        type=str,
        help='Override server URL in config'
    )
    args = parser.parse_args()

    # 기본값: 운영 빌드
    if args.development:
        config_source = 'config.development.json'
        build_type = 'Development'
    else:
        config_source = 'config.production.json'
        build_type = 'Production'

    collector_dir = Path(__file__).parent
    config_source_path = collector_dir / config_source
    config_dest_path = collector_dir / 'config.json'

    # 설정 파일 복사
    if not config_source_path.exists():
        print(f"[오류] 설정 파일을 찾을 수 없습니다: {config_source_path}")
        print("config.production.json 또는 config.development.json을 생성하세요.")
        sys.exit(1)

    print(f"[빌드] 빌드 타입: {build_type}")
    print(f"[빌드] 설정 파일: {config_source} -> config.json")

    # 설정 파일 복사 (서버 URL 오버라이드 적용)
    if args.server_url:
        import json
        with open(config_source_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        config['server_url'] = args.server_url
        # ws_url도 자동 생성
        if args.server_url.startswith('https://'):
            config['ws_url'] = args.server_url.replace('https://', 'wss://')
        elif args.server_url.startswith('http://'):
            config['ws_url'] = args.server_url.replace('http://', 'ws://')
        with open(config_dest_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4)
        print(f"[빌드] 서버 URL 오버라이드: {args.server_url}")
    else:
        shutil.copy(config_source_path, config_dest_path)

    # PyInstaller 실행
    print("[빌드] PyInstaller 빌드 시작...")
    spec_file = collector_dir / 'ForensicCollector.spec'

    result = subprocess.run(
        [sys.executable, '-m', 'PyInstaller', str(spec_file), '--clean'],
        cwd=collector_dir
    )

    if result.returncode == 0:
        dist_dir = collector_dir / 'dist'
        print(f"\n[성공] 빌드 완료!")
        print(f"[성공] 출력 위치: {dist_dir}")
        print(f"[성공] 실행 파일: {dist_dir / 'ForensicCollector.exe'}")
    else:
        print(f"\n[오류] 빌드 실패 (종료 코드: {result.returncode})")
        sys.exit(result.returncode)


if __name__ == '__main__':
    main()
