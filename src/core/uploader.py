"""
Real-time Upload Module

Handles file uploads with WebSocket progress reporting.
P2-2: 사용자 친화적 에러 메시지 지원
"""
import asyncio
import json
import aiohttp
import websockets
from pathlib import Path
from datetime import datetime
from typing import Callable, Optional
from dataclasses import dataclass

from utils.error_messages import translate_error, UserFriendlyError


@dataclass
class UploadResult:
    """Upload result (P2-2: 확장된 에러 정보)"""
    success: bool
    artifact_id: Optional[str] = None
    error: Optional[str] = None
    error_title: Optional[str] = None      # P2-2: 사용자 친화적 에러 제목
    error_solution: Optional[str] = None   # P2-2: 해결 방법
    is_recoverable: bool = True            # P2-2: 재시도 가능 여부

    @classmethod
    def from_error(cls, technical_error: str) -> 'UploadResult':
        """기술적 에러로부터 사용자 친화적 UploadResult 생성"""
        friendly = translate_error(technical_error)
        return cls(
            success=False,
            error=friendly.message,
            error_title=friendly.title,
            error_solution=friendly.solution,
            is_recoverable=friendly.is_recoverable,
        )


class RealTimeUploader:
    """
    Real-time file uploader with WebSocket progress.

    Uploads encrypted files to the forensics server while
    reporting progress via WebSocket connection.
    """

    def __init__(
        self,
        server_url: str,
        ws_url: str,
        session_id: str,
        collection_token: str,
        case_id: str = None,
        consent_record: dict = None,
    ):
        """
        Initialize the uploader.

        Args:
            server_url: HTTP server URL (e.g., http://localhost:8000)
            ws_url: WebSocket URL (e.g., ws://localhost:8000)
            session_id: Collection session ID
            collection_token: Authentication token for uploads
            case_id: Case ID for the collection
            consent_record: Legal consent record (P0 법적 필수)
        """
        self.server_url = server_url.rstrip('/')
        self.ws_url = ws_url.rstrip('/')
        self.session_id = session_id
        self.collection_token = collection_token
        self.case_id = case_id
        self.consent_record = consent_record
        self.ws = None

    async def connect_websocket(self):
        """Establish WebSocket connection for progress reporting."""
        try:
            ws_endpoint = f"{self.ws_url}/ws/collection/{self.session_id}"
            extra_headers = {
                'X-Collection-Token': self.collection_token,
            }
            self.ws = await websockets.connect(ws_endpoint, extra_headers=extra_headers)
        except Exception as e:
            print(f"WebSocket connection failed: {e}")
            self.ws = None

    async def disconnect_websocket(self):
        """Close WebSocket connection."""
        if self.ws:
            await self.ws.close()
            self.ws = None

    async def send_progress(
        self,
        progress: float,
        message: str,
        current_file: str = None,
    ):
        """
        Send progress update via WebSocket.

        Args:
            progress: Progress percentage (0.0 - 1.0)
            message: Status message
            current_file: Current file being processed
        """
        if self.ws:
            try:
                await self.ws.send(json.dumps({
                    'type': 'progress',
                    'progress': progress,
                    'message': message,
                    'current_file': current_file,
                    'timestamp': datetime.utcnow().isoformat(),
                }))
            except Exception as e:
                print(f"Failed to send progress: {e}")

    async def upload_file(
        self,
        file_path: str,
        artifact_type: str,
        metadata: dict,
        progress_callback: Callable[[float], None] = None,
    ) -> UploadResult:
        """
        Upload a single file to the server.

        Args:
            file_path: Path to the encrypted file
            artifact_type: Type of artifact (e.g., 'prefetch', 'eventlog')
            metadata: File metadata
            progress_callback: Optional callback for upload progress

        Returns:
            UploadResult with status
        """
        try:
            async with aiohttp.ClientSession() as session:
                with open(file_path, 'rb') as f:
                    data = aiohttp.FormData()
                    data.add_field(
                        'file',
                        f,
                        filename=Path(file_path).name,
                        content_type='application/octet-stream'
                    )
                    data.add_field('artifact_type', artifact_type)
                    data.add_field('metadata', json.dumps(metadata))
                    if self.case_id:
                        data.add_field('case_id', self.case_id)
                    # P0 법적 필수: 동의 기록 서버 전송
                    if self.consent_record:
                        data.add_field('consent_record', json.dumps(self.consent_record))

                    async with session.post(
                        f"{self.server_url}/api/v1/collector/raw-files/upload",
                        data=data,
                        headers={
                            'X-Session-ID': self.session_id,
                            'X-Collection-Token': self.collection_token,
                        },
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            return UploadResult(
                                success=True,
                                artifact_id=result.get('artifact_id'),
                            )
                        else:
                            error_text = await response.text()
                            # P2-2: 사용자 친화적 에러 메시지
                            return UploadResult.from_error(
                                f"Upload failed ({response.status}): {error_text}"
                            )

        except aiohttp.ClientError as e:
            # P2-2: 사용자 친화적 에러 메시지
            return UploadResult.from_error(f"Connection error: {str(e)}")
        except Exception as e:
            # P2-2: 사용자 친화적 에러 메시지
            return UploadResult.from_error(f"Upload error: {str(e)}")

    async def upload_batch(
        self,
        files: list,
        progress_callback: Callable[[float, str], None] = None,
    ) -> list:
        """
        Upload multiple files with progress tracking.

        Args:
            files: List of (file_path, artifact_type, metadata) tuples
            progress_callback: Callback(progress, filename)

        Returns:
            List of UploadResult for each file
        """
        results = []
        total = len(files)

        for i, (file_path, artifact_type, metadata) in enumerate(files):
            # Send progress
            progress = i / total
            filename = Path(file_path).name

            await self.send_progress(progress, f"Uploading {i+1}/{total}", filename)

            if progress_callback:
                progress_callback(progress, filename)

            # Upload file
            result = await self.upload_file(file_path, artifact_type, metadata)
            results.append(result)

        # Send completion
        await self.send_progress(1.0, "Upload complete", None)

        return results


class SyncUploader:
    """
    Synchronous wrapper for RealTimeUploader.

    Use this for integration with PyQt's event loop.
    """

    def __init__(self, *args, **kwargs):
        self.uploader = RealTimeUploader(*args, **kwargs)

    def upload_file(self, *args, **kwargs) -> UploadResult:
        """Synchronous file upload."""
        return asyncio.run(self.uploader.upload_file(*args, **kwargs))

    def upload_batch(self, *args, **kwargs) -> list:
        """Synchronous batch upload."""
        return asyncio.run(self.uploader.upload_batch(*args, **kwargs))
