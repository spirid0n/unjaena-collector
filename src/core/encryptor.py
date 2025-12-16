"""
File Hash Calculator Module

수집된 파일의 무결성 검증을 위한 해시 계산.
암호화는 서버에서 수행 (보안 강화).

Note: 암호화 로직이 클라이언트에 있으면 리버싱으로 노출될 위험이 있으므로,
      수집 도구는 해시만 계산하고 원본 파일을 TLS로 전송합니다.
      서버에서 파일 수신 후 AES-256-GCM으로 암호화하여 저장합니다.
"""
import hashlib
from pathlib import Path
from dataclasses import dataclass
from typing import Tuple


@dataclass
class FileHashResult:
    """파일 해시 결과"""
    file_path: str
    file_size: int
    sha256_hash: str
    md5_hash: str


class FileHashCalculator:
    """
    파일 해시 계산기.

    수집된 아티팩트의 무결성 검증을 위해 해시를 계산합니다.
    암호화는 서버에서 수행됩니다.
    """

    CHUNK_SIZE = 64 * 1024  # 64KB chunks for large files

    def calculate_file_hash(self, file_path: str) -> FileHashResult:
        """
        파일의 SHA-256 및 MD5 해시를 계산합니다.

        Args:
            file_path: 해시를 계산할 파일 경로

        Returns:
            FileHashResult with hash values
        """
        file_path = Path(file_path)

        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        file_size = 0

        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(self.CHUNK_SIZE), b''):
                sha256.update(chunk)
                md5.update(chunk)
                file_size += len(chunk)

        return FileHashResult(
            file_path=str(file_path),
            file_size=file_size,
            sha256_hash=sha256.hexdigest(),
            md5_hash=md5.hexdigest(),
        )

    def calculate_bytes_hash(self, data: bytes) -> Tuple[str, str]:
        """
        바이트 데이터의 해시를 계산합니다.

        Args:
            data: 해시를 계산할 데이터

        Returns:
            Tuple of (sha256_hash, md5_hash)
        """
        sha256_hash = hashlib.sha256(data).hexdigest()
        md5_hash = hashlib.md5(data).hexdigest()
        return sha256_hash, md5_hash

    def verify_hash(self, file_path: str, expected_sha256: str) -> bool:
        """
        파일 해시를 검증합니다.

        Args:
            file_path: 검증할 파일 경로
            expected_sha256: 예상 SHA-256 해시

        Returns:
            True if hash matches, False otherwise
        """
        result = self.calculate_file_hash(file_path)
        return result.sha256_hash.lower() == expected_sha256.lower()


# Backward compatibility - 기존 코드 호환용
class FileEncryptor:
    """
    [DEPRECATED] 암호화는 서버에서 수행됩니다.

    이 클래스는 하위 호환성을 위해 유지되며,
    실제로는 해시 계산만 수행합니다.
    """

    def __init__(self, key: bytes = None):
        """암호화 키는 더 이상 사용되지 않습니다."""
        self._hash_calculator = FileHashCalculator()
        # 경고: 키는 무시됨 (서버에서 암호화)

    def encrypt_file(self, input_path: str, output_path: str = None):
        """
        [DEPRECATED] 파일 '암호화' (실제로는 복사 + 해시 계산)

        Note: 실제 암호화는 서버에서 수행됩니다.
        """
        from dataclasses import dataclass
        import shutil

        @dataclass
        class EncryptionResult:
            encrypted_path: str
            original_size: int
            encrypted_size: int
            original_hash: str
            nonce: str

        input_path = Path(input_path)

        if output_path is None:
            # .enc 확장자 대신 원본 유지 (서버에서 암호화)
            output_path = input_path
        else:
            output_path = Path(output_path)
            # 다른 경로면 복사
            if input_path != output_path:
                shutil.copy2(input_path, output_path)

        # 해시 계산
        hash_result = self._hash_calculator.calculate_file_hash(str(input_path))

        return EncryptionResult(
            encrypted_path=str(output_path),
            original_size=hash_result.file_size,
            encrypted_size=hash_result.file_size,  # 암호화 없음
            original_hash=hash_result.sha256_hash,
            nonce="server_side_encryption",  # 서버에서 생성
        )

    def calculate_hash(self, file_path: str) -> str:
        """SHA-256 해시 계산."""
        result = self._hash_calculator.calculate_file_hash(file_path)
        return result.sha256_hash
