"""
File Encryption Module

AES-256-GCM encryption for secure file transfer.
"""
import os
import hashlib
from pathlib import Path
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class EncryptionResult:
    """Encryption result metadata"""
    encrypted_path: str
    original_size: int
    encrypted_size: int
    original_hash: str
    nonce: str


class FileEncryptor:
    """
    AES-256-GCM file encryptor.

    Provides secure encryption for forensic artifact files
    before transfer to the server.
    """

    CHUNK_SIZE = 64 * 1024  # 64KB chunks for large files

    def __init__(self, key: bytes = None):
        """
        Initialize the encryptor.

        Args:
            key: 256-bit encryption key. Generated if not provided.
        """
        self.key = key or AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)

    def get_key_hex(self) -> str:
        """Get the encryption key as hex string."""
        return self.key.hex()

    def encrypt_file(self, input_path: str, output_path: str = None) -> EncryptionResult:
        """
        Encrypt a file using AES-256-GCM.

        Args:
            input_path: Path to the file to encrypt
            output_path: Path for the encrypted output (optional)

        Returns:
            EncryptionResult with metadata
        """
        input_path = Path(input_path)

        if output_path is None:
            output_path = input_path.with_suffix(input_path.suffix + '.enc')
        else:
            output_path = Path(output_path)

        # Read original file
        with open(input_path, 'rb') as f:
            plaintext = f.read()

        # Calculate original hash
        original_hash = hashlib.sha256(plaintext).hexdigest()

        # Generate random nonce
        nonce = os.urandom(12)

        # Encrypt
        ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)

        # Write encrypted file (nonce + ciphertext)
        with open(output_path, 'wb') as f:
            f.write(nonce + ciphertext)

        return EncryptionResult(
            encrypted_path=str(output_path),
            original_size=len(plaintext),
            encrypted_size=len(nonce) + len(ciphertext),
            original_hash=original_hash,
            nonce=nonce.hex(),
        )

    def encrypt_bytes(self, data: bytes) -> Tuple[bytes, str]:
        """
        Encrypt bytes in memory.

        Args:
            data: Data to encrypt

        Returns:
            Tuple of (encrypted_data, nonce_hex)
        """
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext, nonce.hex()

    def calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(self.CHUNK_SIZE), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
