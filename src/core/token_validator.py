"""
Token Validation Module

Validates session tokens with the forensics server.
"""
import requests
from typing import Optional
from dataclasses import dataclass

from utils.hardware_id import get_hardware_id, get_system_info


@dataclass
class ValidationResult:
    """Token validation result"""
    valid: bool
    session_id: Optional[str] = None
    case_id: Optional[str] = None
    allowed_artifacts: Optional[list] = None
    collection_token: Optional[str] = None
    server_url: Optional[str] = None
    ws_url: Optional[str] = None
    expires_at: Optional[str] = None
    error: Optional[str] = None


class TokenValidator:
    """
    Session token validator.

    Authenticates the collector with the forensics server
    using session tokens issued from the web platform.
    """

    def __init__(self, server_url: str):
        """
        Initialize the validator.

        Args:
            server_url: Base URL of the forensics server (e.g., http://localhost:8000)
        """
        self.server_url = server_url.rstrip('/')
        self.timeout = 30

    def validate(self, session_token: str) -> ValidationResult:
        """
        Validate a session token with the server.

        Args:
            session_token: Token issued from the web platform

        Returns:
            ValidationResult with authentication details
        """
        try:
            # Get hardware info for binding
            hardware_id = get_hardware_id()
            system_info = get_system_info()

            # Call authentication endpoint
            response = requests.post(
                f"{self.server_url}/api/v1/collector/authenticate",
                json={
                    "session_token": session_token,
                    "hardware_id": hardware_id,
                    "client_info": system_info,
                },
                timeout=self.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                return ValidationResult(
                    valid=True,
                    session_id=data.get('session_id'),
                    case_id=data.get('case_id'),
                    allowed_artifacts=data.get('allowed_artifacts', []),
                    collection_token=data.get('collection_token'),
                    server_url=data.get('server_url'),
                    ws_url=data.get('ws_url'),
                    expires_at=data.get('expires_at'),
                )
            else:
                error_detail = response.json().get('detail', response.text)
                return ValidationResult(
                    valid=False,
                    error=f"Server error ({response.status_code}): {error_detail}",
                )

        except requests.exceptions.ConnectionError:
            return ValidationResult(
                valid=False,
                error="Cannot connect to server. Please check your network connection.",
            )
        except requests.exceptions.Timeout:
            return ValidationResult(
                valid=False,
                error="Connection timeout. Please try again.",
            )
        except Exception as e:
            return ValidationResult(
                valid=False,
                error=f"Validation error: {str(e)}",
            )

    def check_server_health(self) -> bool:
        """Check if the server is reachable."""
        try:
            response = requests.get(
                f"{self.server_url}/health",
                timeout=10,
            )
            return response.status_code == 200
        except Exception:
            return False
