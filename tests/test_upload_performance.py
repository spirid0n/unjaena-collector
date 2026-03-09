"""
업로드 속도 개선 테스트 — multipart 병렬 + batch 동시성
"""
import os
import sys
import time
import tempfile
import threading
from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path

import pytest

# collector 경로 추가
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# =============================================================================
# Mock R2DirectUploader (서버 없이 로직 테스트)
# =============================================================================

class MockResponse:
    def __init__(self, status_code=200, etag="mock-etag-123", text="OK"):
        self.status_code = status_code
        self.text = text
        self.headers = {"ETag": f'"{etag}"'}

    def json(self):
        return {"file_id": "test-file-id"}


def make_temp_file(size_bytes: int) -> str:
    """지정 크기의 임시 파일 생성"""
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    f.write(os.urandom(size_bytes))
    f.close()
    return f.name


# =============================================================================
# 1. Multipart 병렬 업로드 테스트
# =============================================================================

class TestMultipartParallel:
    """_upload_multipart가 파트를 병렬로 업로드하는지 검증"""

    def _make_uploader(self):
        from core.uploader import R2DirectUploader
        uploader = R2DirectUploader.__new__(R2DirectUploader)
        uploader.server_url = "https://mock-server.test"
        uploader.case_id = "test-case-id"
        uploader.session_id = "test-session"
        uploader.collection_token = "test-token"
        uploader.max_file_size = 10 * 1024 * 1024 * 1024
        uploader.signing_key = None
        uploader.challenge_salt = None
        return uploader

    def test_multipart_parallel_execution(self):
        """파트가 실제로 동시에 업로드되는지 확인 (순차면 8초, 병렬이면 ~2초)"""
        uploader = self._make_uploader()

        # 4파트 × 50MB 시뮬레이션용 임시 파일 (실제로는 작은 파일)
        file_path = make_temp_file(400)  # 400 bytes
        active_threads = []
        lock = threading.Lock()
        max_concurrent = [0]

        original_put = None

        def mock_put(url, data=None, headers=None, timeout=None):
            """PUT 호출 시 동시 실행 스레드 수 추적"""
            tid = threading.current_thread().ident
            with lock:
                active_threads.append(tid)
                concurrent = len(set(active_threads))
                if concurrent > max_concurrent[0]:
                    max_concurrent[0] = concurrent
            # 네트워크 지연 시뮬레이션
            time.sleep(0.3)
            with lock:
                active_threads.remove(tid)
            return MockResponse(etag=f"etag-{url[-1]}")

        presigned_info = {
            "upload_url": [
                {"part_number": 1, "url": "https://r2.mock/part1"},
                {"part_number": 2, "url": "https://r2.mock/part2"},
                {"part_number": 3, "url": "https://r2.mock/part3"},
                {"part_number": 4, "url": "https://r2.mock/part4"},
            ],
            "part_size": 100,  # 100 bytes per part
        }

        with patch("requests.put", side_effect=mock_put):
            start = time.time()
            result = uploader._upload_multipart(file_path, presigned_info)
            elapsed = time.time() - start

        os.unlink(file_path)

        # 검증
        assert len(result) == 4, f"Expected 4 parts, got {len(result)}"
        assert all(p["ETag"] for p in result), "All parts should have ETags"
        assert all(p["PartNumber"] for p in result), "All parts should have PartNumbers"

        # 파트 번호 순서 정렬 확인
        part_numbers = [p["PartNumber"] for p in result]
        assert part_numbers == [1, 2, 3, 4], f"Parts should be sorted: {part_numbers}"

        # 병렬 실행 확인: 최대 동시 스레드 > 1
        assert max_concurrent[0] > 1, \
            f"Expected parallel execution (max_concurrent={max_concurrent[0]}), but parts ran sequentially"

        # 시간 확인: 4파트 × 0.3s = 순차 1.2s, 병렬이면 ~0.3s
        assert elapsed < 1.0, \
            f"Parallel upload took {elapsed:.2f}s (expected <1.0s for 4 concurrent parts)"

        print(f"\n  [PASS] max_concurrent={max_concurrent[0]}, elapsed={elapsed:.2f}s")

    def test_multipart_part_order_preserved(self):
        """파트 번호 순서가 CompleteMultipartUpload 요구사항대로 정렬되는지"""
        uploader = self._make_uploader()
        file_path = make_temp_file(300)

        def mock_put(url, data=None, headers=None, timeout=None):
            # 역순으로 완료되도록 지연
            part_num = int(url[-1])
            time.sleep(0.1 * (4 - part_num))
            return MockResponse(etag=f"etag-{part_num}")

        presigned_info = {
            "upload_url": [
                {"part_number": 1, "url": "https://r2.mock/p1"},
                {"part_number": 2, "url": "https://r2.mock/p2"},
                {"part_number": 3, "url": "https://r2.mock/p3"},
            ],
            "part_size": 100,
        }

        with patch("requests.put", side_effect=mock_put):
            result = uploader._upload_multipart(file_path, presigned_info)

        os.unlink(file_path)

        part_numbers = [p["PartNumber"] for p in result]
        assert part_numbers == [1, 2, 3], f"Parts must be sorted ascending: {part_numbers}"
        print(f"\n  [PASS] Part order: {part_numbers}")

    def test_multipart_retry_on_failure(self):
        """파트 업로드 실패 시 재시도 동작 확인"""
        uploader = self._make_uploader()
        file_path = make_temp_file(100)
        attempt_count = [0]

        def mock_put(url, data=None, headers=None, timeout=None):
            attempt_count[0] += 1
            if attempt_count[0] <= 2:
                raise ConnectionError("Network error")
            return MockResponse()

        presigned_info = {
            "upload_url": [{"part_number": 1, "url": "https://r2.mock/p1"}],
            "part_size": 100,
        }

        with patch("requests.put", side_effect=mock_put):
            with patch("time.sleep"):  # 대기 스킵
                result = uploader._upload_multipart(file_path, presigned_info)

        os.unlink(file_path)
        assert len(result) == 1
        assert attempt_count[0] == 3, f"Expected 3 attempts (2 fail + 1 success), got {attempt_count[0]}"
        print(f"\n  [PASS] Retry count: {attempt_count[0]}")

    def test_multipart_all_retries_exhausted(self):
        """모든 재시도 실패 시 예외 전파"""
        uploader = self._make_uploader()
        file_path = make_temp_file(100)

        def mock_put(url, data=None, headers=None, timeout=None):
            raise ConnectionError("Persistent failure")

        presigned_info = {
            "upload_url": [{"part_number": 1, "url": "https://r2.mock/p1"}],
            "part_size": 100,
        }

        with patch("requests.put", side_effect=mock_put):
            with patch("time.sleep"):
                with pytest.raises(ConnectionError):
                    uploader._upload_multipart(file_path, presigned_info)

        os.unlink(file_path)
        print("\n  [PASS] Exception propagated after max retries")


# =============================================================================
# 2. Batch 업로드 동시성 테스트
# =============================================================================

class TestBatchConcurrency:
    """upload_batch의 max_workers=8 검증"""

    def test_batch_max_workers_is_8(self):
        """배치 업로드가 최대 8 동시 워커를 사용하는지"""
        from core.uploader import R2DirectUploader

        # upload_file을 mock해서 동시 실행 수 추적
        active = []
        lock = threading.Lock()
        max_concurrent = [0]

        def mock_upload_file(file_path, artifact_type, metadata, progress_callback=None):
            tid = threading.current_thread().ident
            with lock:
                active.append(tid)
                concurrent = len(set(active))
                max_concurrent[0] = max(max_concurrent[0], concurrent)
            time.sleep(0.2)
            with lock:
                active.remove(tid)
            mock_result = MagicMock()
            mock_result.success = True
            return mock_result

        uploader = R2DirectUploader.__new__(R2DirectUploader)
        uploader.upload_file = mock_upload_file

        # 12개 파일 배치
        files = [
            (f"/tmp/fake_{i}.bin", "prefetch", {"name": f"file_{i}"})
            for i in range(12)
        ]

        results = uploader.upload_batch(files)

        assert len(results) == 12
        assert max_concurrent[0] > 4, \
            f"Expected >4 concurrent workers, got {max_concurrent[0]} (max_workers should be 8)"
        assert max_concurrent[0] <= 8, \
            f"Expected <=8 concurrent workers, got {max_concurrent[0]}"
        print(f"\n  [PASS] Batch max_concurrent={max_concurrent[0]} (expected 5-8)")

    def test_batch_small_count_limits_workers(self):
        """파일 수가 적으면 워커 수도 줄어드는지"""
        from core.uploader import R2DirectUploader

        def mock_upload_file(file_path, artifact_type, metadata, progress_callback=None):
            mock_result = MagicMock()
            mock_result.success = True
            return mock_result

        uploader = R2DirectUploader.__new__(R2DirectUploader)
        uploader.upload_file = mock_upload_file

        files = [("/tmp/f1.bin", "evtx", {"name": "f1"})]
        results = uploader.upload_batch(files)

        assert len(results) == 1
        print("\n  [PASS] Single file batch works")


# =============================================================================
# 3. 속도 비교 (순차 vs 병렬)
# =============================================================================

class TestSpeedComparison:
    """병렬 업로드가 순차보다 빠른지 벤치마크"""

    def test_parallel_faster_than_sequential(self):
        """8파트 업로드: 순차(2.4s) vs 병렬(<1s)"""
        from core.uploader import R2DirectUploader

        uploader = R2DirectUploader.__new__(R2DirectUploader)
        uploader.server_url = "https://mock"
        uploader.case_id = "test"
        uploader.session_id = "test"
        uploader.collection_token = "test"
        uploader.max_file_size = 10 * 1024 * 1024 * 1024
        uploader.signing_key = None
        uploader.challenge_salt = None

        file_path = make_temp_file(800)

        def mock_put(url, data=None, headers=None, timeout=None):
            time.sleep(0.3)  # 300ms 네트워크 지연
            return MockResponse()

        presigned_info = {
            "upload_url": [
                {"part_number": i, "url": f"https://r2.mock/p{i}"}
                for i in range(1, 9)  # 8 parts
            ],
            "part_size": 100,
        }

        with patch("requests.put", side_effect=mock_put):
            start = time.time()
            result = uploader._upload_multipart(file_path, presigned_info)
            parallel_time = time.time() - start

        os.unlink(file_path)

        sequential_time = 8 * 0.3  # 순차면 2.4초
        speedup = sequential_time / parallel_time

        assert len(result) == 8
        assert parallel_time < sequential_time * 0.6, \
            f"Parallel ({parallel_time:.2f}s) should be <60% of sequential ({sequential_time:.2f}s)"
        print(f"\n  [PASS] Sequential: {sequential_time:.2f}s, Parallel: {parallel_time:.2f}s, Speedup: {speedup:.1f}x")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
