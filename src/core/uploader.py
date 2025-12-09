"""
Real-time Upload Module

Handles file uploads with WebSocket progress reporting.
"""
import asyncio
import json
import aiohttp
import websockets
from pathlib import Path
from datetime import datetime
from typing import Callable, Optional
from dataclasses import dataclass


@dataclass
class UploadResult:
    """Upload result"""
    success: bool
    artifact_id: Optional[str] = None
    error: Optional[str] = None


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
    ):
        """
        Initialize the uploader.

        Args:
            server_url: HTTP server URL (e.g., http://localhost:8000)
            ws_url: WebSocket URL (e.g., ws://localhost:8000)
            session_id: Collection session ID
            collection_token: Authentication token for uploads
            case_id: Case ID for the collection
        """
        self.server_url = server_url.rstrip('/')
        self.ws_url = ws_url.rstrip('/')
        self.session_id = session_id
        self.collection_token = collection_token
        self.case_id = case_id
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
                            return UploadResult(
                                success=False,
                                error=f"Upload failed ({response.status}): {error_text}",
                            )

        except aiohttp.ClientError as e:
            return UploadResult(
                success=False,
                error=f"Connection error: {str(e)}",
            )
        except Exception as e:
            return UploadResult(
                success=False,
                error=f"Upload error: {str(e)}",
            )

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
