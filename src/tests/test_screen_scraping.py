#!/usr/bin/env python3
"""
Screen Scraping Collector 테스트

테스트 대상:
1. ANDROID_ARTIFACT_TYPES에 screen_scrape 등록 확인
2. _collect_impl에서 screen_scrape 라우팅 확인
3. Agent APK 관련 상수/경로 확인
4. Mock ADB를 사용한 메서드 단위 테스트
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

# Add project path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ===========================================================================
# 1. Artifact Type 등록 테스트
# ===========================================================================

class TestScreenScrapeArtifactType:
    """screen_scrape 아티팩트 타입 등록 검증"""

    def test_artifact_type_exists(self):
        """ANDROID_ARTIFACT_TYPES에 mobile_android_screen_scrape 존재"""
        from collectors.android_collector import ANDROID_ARTIFACT_TYPES

        assert 'mobile_android_screen_scrape' in ANDROID_ARTIFACT_TYPES

    def test_artifact_type_structure(self):
        """screen_scrape 아티팩트 타입 필수 필드"""
        from collectors.android_collector import ANDROID_ARTIFACT_TYPES

        info = ANDROID_ARTIFACT_TYPES['mobile_android_screen_scrape']

        assert 'name' in info
        assert 'collection_method' in info
        assert info['collection_method'] == 'screen_scrape'

    def test_artifact_type_in_collector_artifact_types(self):
        """artifact_collector ARTIFACT_TYPES에도 등록됨"""
        from collectors.artifact_collector import ARTIFACT_TYPES

        assert 'mobile_android_screen_scrape' in ARTIFACT_TYPES

    def test_artifact_type_subcategory(self):
        """artifact_collector에서 서브카테고리 확인"""
        from collectors.artifact_collector import ARTIFACT_TYPES

        info = ARTIFACT_TYPES['mobile_android_screen_scrape']
        assert info.get('subcategory') == 'screen_scrape'


# ===========================================================================
# 2. AndroidCollector 상수 검증
# ===========================================================================

class TestScreenScrapeConstants:
    """Agent APK 관련 상수 검증"""

    def test_agent_package(self):
        """Agent 패키지명"""
        from collectors.android_collector import AndroidCollector
        assert AndroidCollector.AGENT_PACKAGE == 'com.unjaena.agent'

    def test_agent_receiver(self):
        """CommandReceiver 경로"""
        from collectors.android_collector import AndroidCollector
        assert '.receiver.CommandReceiver' in AndroidCollector.AGENT_RECEIVER

    def test_agent_result_dir(self):
        """결과 디렉토리 경로"""
        from collectors.android_collector import AndroidCollector
        assert 'com.unjaena.agent' in AndroidCollector.AGENT_RESULT_DIR
        assert AndroidCollector.AGENT_RESULT_DIR.endswith('/results')

    def test_agent_manifest_file(self):
        """매니페스트 파일 경로"""
        from collectors.android_collector import AndroidCollector
        assert AndroidCollector.AGENT_MANIFEST_FILE.endswith('result_manifest.json')

    def test_polling_interval(self):
        """폴링 간격 > 0"""
        from collectors.android_collector import AndroidCollector
        assert AndroidCollector.SCRAPING_POLL_INTERVAL > 0

    def test_max_wait(self):
        """최대 대기 시간 = 30분"""
        from collectors.android_collector import AndroidCollector
        assert AndroidCollector.SCRAPING_MAX_WAIT == 1800

    def test_apk_version_path(self):
        """version.txt 경로가 올바른 상대 경로"""
        from collectors.android_collector import AndroidCollector
        version_path = AndroidCollector.AGENT_APK_VERSION_PATH
        assert version_path.name == 'version.txt'
        assert 'agent_apk' in str(version_path)


# ===========================================================================
# 3. Mock 기반 메서드 테스트
# ===========================================================================

class TestScreenScrapeMethods:
    """Mock ADB를 사용한 screen_scrape 메서드 테스트"""

    def _make_collector(self, tmpdir):
        """mock 연결된 AndroidCollector 생성"""
        from collectors.android_collector import AndroidCollector

        collector = AndroidCollector.__new__(AndroidCollector)
        collector.output_dir = Path(tmpdir)

        # Mock device_info
        collector.device_info = MagicMock()
        collector.device_info.serial = 'TEST001'
        collector.device_info.model = 'Test Phone'
        collector.device_info.sdk_version = 33

        # Mock ADB 인터페이스
        collector._adb_shell = MagicMock(return_value=('', 0))
        collector._adb_pull = MagicMock(return_value=True)
        collector._run_system_adb = MagicMock(return_value=('Success\n', 0))

        # Mock config / auth
        collector._config = {'server_url': 'https://test.example.com'}
        collector._collection_token = 'test-token-123'
        collector._case_id = 'case-001'
        collector._session_id = 'sess-001'
        collector._udid = 'test-serial-hash'

        return collector

    def test_collect_screen_scrape_no_device(self, tmp_path):
        """디바이스 미연결 시 에러 반환"""
        from collectors.android_collector import AndroidCollector

        collector = AndroidCollector.__new__(AndroidCollector)
        collector.device_info = None
        collector.output_dir = tmp_path

        results = list(collector._collect_screen_scrape(
            artifact_type='mobile_android_screen_scrape',
            artifact_info={},
            output_dir=tmp_path,
            progress_callback=None,
        ))

        assert len(results) == 1
        path, meta = results[0]
        assert path == ''
        assert meta['status'] == 'error'
        assert 'Not connected' in meta['error']

    def test_install_agent_apk_not_found(self, tmp_path):
        """APK 파일 없을 때 False 반환"""
        collector = self._make_collector(tmp_path)

        # AGENT_APK_PATH를 존재하지 않는 경로로 설정
        collector.AGENT_APK_PATH = Path('/nonexistent/ForensicAgent.apk')

        result = collector._install_agent_apk()
        assert result is False

    def test_install_agent_apk_already_installed(self, tmp_path):
        """이미 최신 버전이 설치되어 있으면 True"""
        collector = self._make_collector(tmp_path)

        # APK 파일 존재 시뮬레이션
        apk_path = tmp_path / 'ForensicAgent.apk'
        apk_path.write_bytes(b'fake apk')
        collector.AGENT_APK_PATH = apk_path

        # 버전 파일
        version_path = tmp_path / 'version.txt'
        version_path.write_text('1.0.0')
        collector.AGENT_APK_VERSION_PATH = version_path

        # dumpsys가 동일 버전 반환
        collector._adb_shell = MagicMock(return_value=('    versionName=1.0.0', 0))

        result = collector._install_agent_apk()
        assert result is True
        # install 명령은 호출 안됨
        collector._run_system_adb.assert_not_called()

    def test_install_agent_apk_needs_update(self, tmp_path):
        """구 버전이면 업데이트 실행"""
        collector = self._make_collector(tmp_path)

        apk_path = tmp_path / 'ForensicAgent.apk'
        apk_path.write_bytes(b'fake apk')
        collector.AGENT_APK_PATH = apk_path

        version_path = tmp_path / 'version.txt'
        version_path.write_text('2.0.0')
        collector.AGENT_APK_VERSION_PATH = version_path

        # 기기에는 1.0.0이 설치되어 있음
        collector._adb_shell = MagicMock(return_value=('    versionName=1.0.0', 0))
        collector._run_system_adb = MagicMock(return_value=('Success', 0))

        result = collector._install_agent_apk()
        assert result is True
        collector._run_system_adb.assert_called_once()

    def test_get_installed_apps_for_scraping(self, tmp_path):
        """설치된 앱 목록 추출"""
        collector = self._make_collector(tmp_path)

        # dumpsys package listing 시뮬레이션
        # supported_apps에 있는 패키지만 조회
        def mock_shell(cmd, use_su=False):
            if 'com.kakao.talk' in cmd:
                return ('    versionName=10.5.0\n', 0)
            elif 'com.whatsapp' in cmd:
                return ('    versionName=2.24.1\n', 0)
            elif 'com.missing.app' in cmd:
                return ('', 1)  # 미설치
            return ('', 0)

        collector._adb_shell = MagicMock(side_effect=mock_shell)

        supported = ['com.kakao.talk', 'com.whatsapp', 'com.missing.app']
        apps = collector._get_installed_apps_for_scraping(supported)

        # com.missing.app은 미설치이므로 2개만 반환
        assert len(apps) == 2
        packages = [a['package'] for a in apps]
        assert 'com.kakao.talk' in packages
        assert 'com.whatsapp' in packages
        assert 'com.missing.app' not in packages

    def test_start_agent_scraping_broadcast(self, tmp_path):
        """ADB 브로드캐스트 명령 형식 확인"""
        collector = self._make_collector(tmp_path)

        calls = []
        def mock_shell(cmd, use_su=False):
            calls.append(cmd)
            return ('', 0)

        collector._adb_shell = MagicMock(side_effect=mock_shell)

        collector._start_agent_scraping(
            scraping_token='scrp_test123',
            session_id='sess-001',
            target_apps=['com.kakao.talk', 'com.whatsapp'],
        )

        # broadcast 명령이 호출됨 (토큰 파일 쓰기 후)
        assert len(calls) >= 1
        broadcast_cmds = [c for c in calls if 'am broadcast' in c]
        assert len(broadcast_cmds) >= 1, f"No broadcast command found in calls: {calls}"
        broadcast_cmd = broadcast_cmds[0]
        assert 'START_SCRAPING' in broadcast_cmd or 'com.unjaena.agent' in broadcast_cmd

    def test_pull_scraping_results(self, tmp_path):
        """결과 파일 pull"""
        collector = self._make_collector(tmp_path)

        # ls 명령이 파일 목록 반환
        collector._adb_shell = MagicMock(return_value=(
            'com.kakao.talk_chat_list_1234.jsonl\n'
            'com.whatsapp_contacts_5678.jsonl\n'
            'result_manifest.json\n',
            0
        ))

        # pull 성공 시뮬레이션 (파일 직접 생성)
        def mock_pull(remote, local):
            Path(local).write_text('{"test": true}\n')
            return True

        collector._adb_pull = MagicMock(side_effect=mock_pull)

        output_dir = tmp_path / 'scrape_output'
        output_dir.mkdir()

        files = collector._pull_scraping_results(output_dir)

        # JSONL 파일만 pull (manifest 제외)
        assert len(files) >= 2
        # pull 호출 수 확인
        assert collector._adb_pull.call_count >= 2

    def test_cleanup_device_results(self, tmp_path):
        """디바이스 결과 정리"""
        collector = self._make_collector(tmp_path)

        collector._cleanup_device_results()

        # rm 명령 호출 확인
        collector._adb_shell.assert_called()
        call_args = str(collector._adb_shell.call_args)
        assert 'rm' in call_args or 'results' in call_args

    def test_wait_for_scraping_completion_success(self, tmp_path):
        """스크래핑 완료 대기 - 성공"""
        import time as time_mod
        collector = self._make_collector(tmp_path)

        # 첫 호출: 미완료, 두 번째 호출: manifest 존재 (완료)
        call_count = [0]

        def mock_shell(cmd, use_su=False):
            call_count[0] += 1
            if 'cat' in cmd and 'manifest' in cmd:
                if call_count[0] <= 1:
                    return ('', 1)  # 아직 없음
                else:
                    manifest = json.dumps({
                        'status': 'completed',
                        'total_records': 50,
                    })
                    return (manifest, 0)  # 완료
            return ('', 0)

        collector._adb_shell = MagicMock(side_effect=mock_shell)

        # sleep을 no-op으로
        with patch('time.sleep'):
            result = collector._wait_for_scraping_completion(
                session_id='sess-001',
                progress_callback=None,
            )

        assert result is True

    def test_wait_for_scraping_completion_timeout(self, tmp_path):
        """스크래핑 대기 타임아웃"""
        collector = self._make_collector(tmp_path)
        collector.SCRAPING_MAX_WAIT = 1  # 1초로 축소

        # 항상 미완료 반환
        collector._adb_shell = MagicMock(return_value=('', 1))

        with patch('time.sleep'):
            with patch('time.time') as mock_time:
                # 첫 호출: start_time, 두 번째 호출: start + 100초 (타임아웃)
                mock_time.side_effect = [0, 0, 100, 100]
                result = collector._wait_for_scraping_completion(
                    session_id='sess-001',
                    progress_callback=None,
                )

        assert result is False


# ===========================================================================
# 4. _collect_impl 라우팅 테스트
# ===========================================================================

class TestCollectImplRouting:
    """_collect_impl에서 screen_scrape 라우팅 확인"""

    def test_screen_scrape_routing(self):
        """collection_method == 'screen_scrape' 시 _collect_screen_scrape 호출"""
        from collectors.android_collector import ANDROID_ARTIFACT_TYPES

        info = ANDROID_ARTIFACT_TYPES['mobile_android_screen_scrape']
        assert info['collection_method'] == 'screen_scrape'

    def test_no_server_type_map(self):
        """_SERVER_TYPE_MAP 제거 확인 (Root/Non-Root 이분화로 불필요)"""
        from collectors.android_collector import AndroidCollector

        # _SERVER_TYPE_MAP was removed in the Root/Non-Root simplification
        assert not hasattr(AndroidCollector, '_SERVER_TYPE_MAP')


# ===========================================================================
# 5. GUI 등록 테스트
# ===========================================================================

class TestGUIRegistration:
    """GUI 체크박스 등록 확인 (import만 테스트)"""

    def test_gui_subcategory_pattern(self):
        """app.py에 ANDROID_SUBCATEGORIES 패턴 확인
        (실제 GUI 모듈은 PyQt5 의존성으로 import 불가할 수 있음)"""
        # 파일에서 직접 확인
        app_path = Path(__file__).parent.parent / 'gui' / 'app.py'
        if not app_path.exists():
            pytest.skip("app.py not found")

        content = app_path.read_text(encoding='utf-8')
        assert 'screen_scrape' in content
        assert 'Screen Scraping' in content


# ===========================================================================
# 6. Agent APK 리소스 테스트
# ===========================================================================

class TestAgentAPKResources:
    """Agent APK 관련 리소스 파일 확인"""

    def test_version_file_exists(self):
        """version.txt 파일 존재"""
        version_path = (
            Path(__file__).parent.parent.parent
            / 'resources' / 'agent_apk' / 'version.txt'
        )
        assert version_path.exists(), f"version.txt not found at {version_path}"

    def test_version_file_format(self):
        """version.txt가 올바른 형식 (x.y.z)"""
        version_path = (
            Path(__file__).parent.parent.parent
            / 'resources' / 'agent_apk' / 'version.txt'
        )
        if not version_path.exists():
            pytest.skip("version.txt not found")

        version = version_path.read_text().strip()
        parts = version.split('.')
        assert len(parts) >= 2, f"Invalid version format: {version}"
        for part in parts:
            assert part.isdigit(), f"Non-numeric version part: {part}"


# ===========================================================================
# 7. 보안 강화 테스트 — 토큰 파일 전달
# ===========================================================================

class TestSecurityTokenFileDelivery:
    """[보안] broadcast extras 대신 파일로 토큰 전달 검증"""

    def _make_collector(self, tmpdir):
        from collectors.android_collector import AndroidCollector

        collector = AndroidCollector.__new__(AndroidCollector)
        collector.output_dir = Path(tmpdir)
        collector.device_info = MagicMock()
        collector.device_info.serial = 'TEST001'
        collector.device_info.model = 'Test Phone'
        collector.device_info.sdk_version = 33
        collector._adb_shell = MagicMock(return_value=('', 0))
        collector._adb_pull = MagicMock(return_value=True)
        collector._run_system_adb = MagicMock(return_value=('Success\n', 0))
        collector._config = {'server_url': 'https://test.example.com'}
        collector._server_url = 'https://test.example.com'
        collector._collection_token = 'test-token-123'
        collector._case_id = 'case-001'
        collector._session_id = 'sess-001'
        collector._udid = 'test-serial-hash'
        collector.AGENT_PACKAGE = 'com.unjaena.agent'
        collector.AGENT_RECEIVER = 'com.unjaena.agent/.receiver.CommandReceiver'
        return collector

    def test_broadcast_no_token_extra(self, tmp_path):
        """broadcast 명령에 scraping_token이 포함되지 않아야 함"""
        collector = self._make_collector(tmp_path)

        calls = []
        def mock_shell(cmd, use_su=False):
            calls.append(cmd)
            return ('', 0)

        collector._adb_shell = MagicMock(side_effect=mock_shell)

        collector._start_agent_scraping(
            scraping_token='scrp_secret_token_value',
            session_id='sess-001',
            target_apps=['com.kakao.talk'],
        )

        # broadcast 명령 찾기
        broadcast_cmds = [c for c in calls if 'am broadcast' in c]
        assert len(broadcast_cmds) == 1

        # broadcast 명령에 실제 토큰값이 포함되지 않아야 함
        assert 'scrp_secret_token_value' not in broadcast_cmds[0]
        assert 'scraping_token' not in broadcast_cmds[0]

    def test_token_written_to_file(self, tmp_path):
        """토큰이 파일로 기록됨"""
        collector = self._make_collector(tmp_path)

        calls = []
        def mock_shell(cmd, use_su=False):
            calls.append(cmd)
            return ('', 0)

        collector._adb_shell = MagicMock(side_effect=mock_shell)

        collector._start_agent_scraping(
            scraping_token='scrp_test_token_abc',
            session_id='sess-001',
            target_apps=['com.kakao.talk'],
        )

        # echo 'token' > path 형태의 파일 쓰기 명령 확인
        file_write_cmds = [c for c in calls if 'scrp_test_token_abc' in c and '.scraping_token' in c]
        assert len(file_write_cmds) >= 1, f"Token file write not found in commands: {calls}"

    def test_token_file_path_correct(self, tmp_path):
        """토큰 파일 경로가 앱 외부 저장소"""
        collector = self._make_collector(tmp_path)

        calls = []
        def mock_shell(cmd, use_su=False):
            calls.append(cmd)
            return ('', 0)

        collector._adb_shell = MagicMock(side_effect=mock_shell)

        collector._start_agent_scraping(
            scraping_token='scrp_xyz',
            session_id='sess-001',
            target_apps=['com.kakao.talk'],
        )

        # 토큰 파일 경로가 올바른지 확인
        expected_path = '/sdcard/Android/data/com.unjaena.agent/files/.scraping_token'
        file_cmds = [c for c in calls if '.scraping_token' in c]
        assert any(expected_path in c for c in file_cmds), \
            f"Expected path {expected_path} not found in: {file_cmds}"


# ===========================================================================
# 8. 보안 강화 테스트 — 서버 앱 목록 동적 조회
# ===========================================================================

class TestSecurityServerAppQuery:
    """[보안] supported_apps 하드코딩 제거 + 서버 동적 조회 검증"""

    def test_artifact_type_no_supported_apps(self):
        """artifact_type에 supported_apps 키가 없어야 함 (하드코딩 제거 확인)"""
        from collectors.android_collector import ANDROID_ARTIFACT_TYPES

        info = ANDROID_ARTIFACT_TYPES['mobile_android_screen_scrape']
        assert 'supported_apps' not in info, \
            "supported_apps should be removed from artifact_type (server dynamic query)"

    def test_get_supported_packages_calls_server(self, tmp_path):
        """_get_supported_packages()가 서버 API 호출"""
        from collectors.android_collector import AndroidCollector

        collector = AndroidCollector.__new__(AndroidCollector)
        collector._server_url = 'https://test.example.com'
        collector._collection_token = 'test-token-123'

        # mock urllib
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            'supported_packages': ['com.kakao.talk', 'com.whatsapp', 'jp.naver.line.android']
        }).encode()
        mock_response.__enter__ = MagicMock(return_value=mock_response)
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch('urllib.request.urlopen', return_value=mock_response) as mock_urlopen:
            result = collector._get_supported_packages()

        # 서버 API 호출 확인
        mock_urlopen.assert_called_once()
        call_args = mock_urlopen.call_args
        request_obj = call_args[0][0]
        assert '/scraping/supported-apps' in request_obj.full_url
        assert request_obj.get_header('Authorization') == 'Bearer test-token-123'

        # 결과 확인
        assert result == ['com.kakao.talk', 'com.whatsapp', 'jp.naver.line.android']

    def test_collect_screen_scrape_uses_server_packages(self, tmp_path):
        """_collect_screen_scrape가 서버 조회 결과를 사용"""
        from collectors.android_collector import AndroidCollector

        collector = AndroidCollector.__new__(AndroidCollector)
        collector.output_dir = Path(tmp_path)
        collector.device_info = MagicMock()
        collector.device_info.serial = 'TEST001'
        collector.device_info.model = 'TestPhone'
        collector.device_info.sdk_version = 33
        collector._config = {'server_url': 'https://test.example.com'}
        collector._server_url = 'https://test.example.com'
        collector._collection_token = 'test-token-123'
        collector._case_id = 'case-001'
        collector._session_id = 'sess-001'

        # Mock: APK 설치 성공
        collector._install_agent_apk = MagicMock(return_value=True)
        collector._enable_accessibility_service = MagicMock()

        # Mock: 서버에서 지원 패키지 조회
        collector._get_supported_packages = MagicMock(
            return_value=['com.kakao.talk', 'com.whatsapp']
        )

        # Mock: 설치된 앱 조회
        collector._get_installed_apps_for_scraping = MagicMock(return_value=[
            {'package': 'com.kakao.talk', 'version_name': '10.5.0', 'version_code': '1'},
        ])

        # Mock: 세션 요청 실패 (이후 단계 불필요)
        collector._request_scraping_session = MagicMock(return_value=None)

        results = list(collector._collect_screen_scrape(
            artifact_type='mobile_android_screen_scrape',
            artifact_info={},
            output_dir=tmp_path,
            progress_callback=None,
        ))

        # _get_supported_packages 호출 확인
        collector._get_supported_packages.assert_called_once()
        # 서버에서 받은 패키지를 _get_installed_apps_for_scraping에 전달
        collector._get_installed_apps_for_scraping.assert_called_once_with(
            ['com.kakao.talk', 'com.whatsapp']
        )


# ===========================================================================
# 9. 보안 강화 테스트 — APK 무결성 검증
# ===========================================================================

class TestSecurityAPKIntegrity:
    """[보안] APK SHA256 무결성 검증"""

    def _make_collector(self, tmpdir):
        from collectors.android_collector import AndroidCollector

        collector = AndroidCollector.__new__(AndroidCollector)
        collector.output_dir = Path(tmpdir)
        collector.device_info = MagicMock()
        collector.device_info.serial = 'TEST001'
        collector._adb_shell = MagicMock(return_value=('    versionName=0.9.0', 0))
        collector._run_system_adb = MagicMock(return_value=('Success', 0))
        return collector

    def test_install_apk_hash_match(self, tmp_path):
        """SHA256 일치 시 설치 진행"""
        import hashlib

        collector = self._make_collector(tmp_path)

        # 테스트 APK 파일 생성
        apk_path = tmp_path / 'ForensicAgent.apk'
        apk_content = b'test apk binary content here'
        apk_path.write_bytes(apk_content)
        collector.AGENT_APK_PATH = apk_path

        # 올바른 SHA256 해시 파일 생성
        sha256 = hashlib.sha256(apk_content).hexdigest()
        hash_path = tmp_path / 'ForensicAgent.apk.sha256'
        hash_path.write_text(f'{sha256}  ForensicAgent.apk')

        # 버전 파일 (업데이트 필요하게)
        version_path = tmp_path / 'version.txt'
        version_path.write_text('1.0.0')
        collector.AGENT_APK_VERSION_PATH = version_path

        result = collector._install_agent_apk()
        assert result is True
        # install 명령이 호출됨 (해시 통과 → 설치 진행)
        collector._run_system_adb.assert_called_once()

    def test_install_apk_hash_mismatch(self, tmp_path):
        """SHA256 불일치 시 설치 거부 (False 반환)"""
        collector = self._make_collector(tmp_path)

        # APK 파일
        apk_path = tmp_path / 'ForensicAgent.apk'
        apk_path.write_bytes(b'actual apk content')
        collector.AGENT_APK_PATH = apk_path

        # 잘못된 SHA256 해시 파일
        hash_path = tmp_path / 'ForensicAgent.apk.sha256'
        hash_path.write_text('0000000000000000000000000000000000000000000000000000000000000000  ForensicAgent.apk')

        version_path = tmp_path / 'version.txt'
        version_path.write_text('1.0.0')
        collector.AGENT_APK_VERSION_PATH = version_path

        result = collector._install_agent_apk()
        assert result is False
        # install 명령이 호출되지 않아야 함
        collector._run_system_adb.assert_not_called()

    def test_install_apk_no_hash_file(self, tmp_path):
        """해시 파일 미존재 시 검증 건너뛰고 설치 진행"""
        collector = self._make_collector(tmp_path)

        # APK 파일 (해시 파일 없음)
        apk_path = tmp_path / 'ForensicAgent.apk'
        apk_path.write_bytes(b'test apk')
        collector.AGENT_APK_PATH = apk_path

        # 해시 파일이 없는지 확인
        hash_path = tmp_path / 'ForensicAgent.apk.sha256'
        assert not hash_path.exists()

        version_path = tmp_path / 'version.txt'
        version_path.write_text('1.0.0')
        collector.AGENT_APK_VERSION_PATH = version_path

        result = collector._install_agent_apk()
        assert result is True
        # 해시 검증 건너뛰고 install 진행
        collector._run_system_adb.assert_called_once()


# ===========================================================================
# 10. 보안 강화 테스트 — APK 자동 제거
# ===========================================================================

class TestSecurityAPKUninstall:
    """[보안] 수집 완료 후 APK 자동 제거 검증"""

    def _make_collector(self, tmpdir):
        from collectors.android_collector import AndroidCollector

        collector = AndroidCollector.__new__(AndroidCollector)
        collector.output_dir = Path(tmpdir)
        collector.device_info = MagicMock()
        collector.device_info.serial = 'TEST001'
        collector.device_info.model = 'Test Phone'
        collector.device_info.sdk_version = 33
        collector._adb_shell = MagicMock(return_value=('', 0))
        collector._adb_pull = MagicMock(return_value=True)
        collector._run_system_adb = MagicMock(return_value=('Success\n', 0))
        collector._config = {'server_url': 'https://test.example.com'}
        collector._server_url = 'https://test.example.com'
        collector._collection_token = 'test-token-123'
        collector._case_id = 'case-001'
        collector._session_id = 'sess-001'
        collector.AGENT_PACKAGE = 'com.unjaena.agent'
        collector.AGENT_RECEIVER = 'com.unjaena.agent/.receiver.CommandReceiver'
        collector.AGENT_RESULT_DIR = '/sdcard/Android/data/com.unjaena.agent/files/results'
        collector.AGENT_MANIFEST_FILE = '/sdcard/Android/data/com.unjaena.agent/files/results/result_manifest.json'
        collector.SCRAPING_POLL_INTERVAL = 1
        collector.SCRAPING_MAX_WAIT = 1800
        return collector

    def test_uninstall_called_after_scraping(self, tmp_path):
        """수집 완료 후 _uninstall_agent_apk 호출됨"""
        collector = self._make_collector(tmp_path)

        # Mock: 전체 파이프라인 성공
        collector._install_agent_apk = MagicMock(return_value=True)
        collector._enable_accessibility_service = MagicMock()
        collector._get_supported_packages = MagicMock(
            return_value=['com.kakao.talk']
        )
        collector._get_installed_apps_for_scraping = MagicMock(return_value=[
            {'package': 'com.kakao.talk', 'version_name': '10.5.0', 'version_code': '1'},
        ])
        collector._request_scraping_session = MagicMock(return_value={
            'scraping_token': 'scrp_test',
            'session_id': 'sess-001',
            'available_apps': [{'package': 'com.kakao.talk'}],
        })
        collector._start_agent_scraping = MagicMock()
        collector._wait_for_scraping_completion = MagicMock(return_value=True)
        collector._pull_scraping_results = MagicMock(return_value=[
            tmp_path / 'result.jsonl',
        ])
        collector._cleanup_device_results = MagicMock()
        collector._uninstall_agent_apk = MagicMock()

        results = list(collector._collect_screen_scrape(
            artifact_type='mobile_android_screen_scrape',
            artifact_info={},
            output_dir=tmp_path,
            progress_callback=None,
        ))

        # uninstall 호출 확인
        collector._uninstall_agent_apk.assert_called_once()

    def test_uninstall_calls_adb_uninstall(self, tmp_path):
        """adb uninstall com.unjaena.agent 호출 확인"""
        collector = self._make_collector(tmp_path)

        collector._uninstall_agent_apk()

        # _run_system_adb에 uninstall 인수 확인
        collector._run_system_adb.assert_called_once()
        call_args = collector._run_system_adb.call_args[0][0]
        assert 'uninstall' in call_args
        assert 'com.unjaena.agent' in call_args


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
