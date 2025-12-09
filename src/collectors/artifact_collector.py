"""
Artifact Collector Module

Collects forensic artifacts from Windows systems.
Only collects raw files - no parsing is performed.
"""
import os
import glob
import shutil
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Generator, Tuple, Dict, Any, Optional


# Artifact type definitions
ARTIFACT_TYPES = {
    'prefetch': {
        'name': 'Prefetch Files',
        'description': 'Program execution history',
        'paths': [r'C:\Windows\Prefetch\*.pf'],
        'requires_admin': True,
        'collector': 'collect_glob',
    },
    'eventlog': {
        'name': 'Event Logs',
        'description': 'Windows event logs (Security, System, Application)',
        'paths': [
            r'C:\Windows\System32\winevt\Logs\Security.evtx',
            r'C:\Windows\System32\winevt\Logs\System.evtx',
            r'C:\Windows\System32\winevt\Logs\Application.evtx',
            r'C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx',
        ],
        'requires_admin': True,
        'collector': 'collect_files',
    },
    'registry': {
        'name': 'Registry Hives',
        'description': 'System registry hives (SYSTEM, SOFTWARE, SAM)',
        'paths': [
            r'C:\Windows\System32\config\SYSTEM',
            r'C:\Windows\System32\config\SOFTWARE',
            r'C:\Windows\System32\config\SAM',
            r'C:\Windows\System32\config\SECURITY',
        ],
        'requires_admin': True,
        'collector': 'collect_locked_files',
    },
    'amcache': {
        'name': 'Amcache',
        'description': 'Application compatibility cache',
        'paths': [r'C:\Windows\AppCompat\Programs\Amcache.hve'],
        'requires_admin': True,
        'collector': 'collect_locked_files',
    },
    'userassist': {
        'name': 'UserAssist',
        'description': 'User activity tracking (NTUSER.DAT)',
        'paths': [],  # Dynamic paths per user
        'requires_admin': False,
        'collector': 'collect_ntuser',
    },
    'browser_chrome': {
        'name': 'Chrome Browser',
        'description': 'Chrome history and downloads',
        'paths': [
            r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\History',
            r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Downloads',
            r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies',
        ],
        'requires_admin': False,
        'collector': 'collect_user_files',
    },
    'browser_edge': {
        'name': 'Edge Browser',
        'description': 'Edge history and downloads',
        'paths': [
            r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\History',
            r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Downloads',
        ],
        'requires_admin': False,
        'collector': 'collect_user_files',
    },
    'recent': {
        'name': 'Recent Documents',
        'description': 'Recently accessed files',
        'paths': [r'%APPDATA%\Microsoft\Windows\Recent\*.lnk'],
        'requires_admin': False,
        'collector': 'collect_user_glob',
    },
    'recyclebin': {
        'name': 'Recycle Bin',
        'description': 'Deleted files metadata',
        'paths': [r'C:\$Recycle.Bin\*\$I*'],
        'requires_admin': True,
        'collector': 'collect_glob',
    },
    'usb': {
        'name': 'USB History',
        'description': 'USB device connection history',
        'paths': [
            r'C:\Windows\INF\setupapi.dev.log',
        ],
        'requires_admin': True,
        'collector': 'collect_files',
    },
    'srum': {
        'name': 'SRUM Database',
        'description': 'System Resource Usage Monitor',
        'paths': [r'C:\Windows\System32\sru\SRUDB.dat'],
        'requires_admin': True,
        'collector': 'collect_locked_files',
    },
}


class ArtifactCollector:
    """
    Forensic artifact collector.

    Collects raw artifact files without any parsing.
    All parsing is performed server-side.
    """

    def __init__(self, output_dir: str):
        """
        Initialize the collector.

        Args:
            output_dir: Directory to store collected artifacts
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def collect(
        self,
        artifact_type: str,
        progress_callback: Optional[callable] = None
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect artifacts of a specific type.

        Args:
            artifact_type: Type of artifact to collect (e.g., 'prefetch')
            progress_callback: Optional callback for progress updates

        Yields:
            Tuple of (file_path, metadata) for each collected file
        """
        if artifact_type not in ARTIFACT_TYPES:
            raise ValueError(f"Unknown artifact type: {artifact_type}")

        artifact_info = ARTIFACT_TYPES[artifact_type]
        collector_method = getattr(self, artifact_info['collector'])

        # Create artifact-specific output directory
        artifact_dir = self.output_dir / artifact_type
        artifact_dir.mkdir(exist_ok=True)

        # Collect files
        for path_pattern in artifact_info['paths']:
            for result in collector_method(path_pattern, artifact_dir, artifact_type):
                yield result
                if progress_callback:
                    progress_callback(result[0])

    def collect_glob(
        self,
        pattern: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching a glob pattern"""
        for src_path in glob.glob(pattern):
            try:
                dst_path = output_dir / Path(src_path).name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(src_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                print(f"Cannot access {src_path}: {e}")
                continue

    def collect_files(
        self,
        file_path: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect a specific file"""
        src_path = Path(file_path)
        if src_path.exists():
            try:
                dst_path = output_dir / src_path.name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(str(src_path), dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                print(f"Cannot access {file_path}: {e}")

    def collect_locked_files(
        self,
        file_path: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """
        Collect files that may be locked by the OS.

        Uses Volume Shadow Copy or raw file read.
        """
        src_path = Path(file_path)
        if not src_path.exists():
            return

        dst_path = output_dir / src_path.name

        # Try direct copy first
        try:
            shutil.copy2(src_path, dst_path)
            yield str(dst_path), self._get_metadata(str(src_path), dst_path, artifact_type)
            return
        except (PermissionError, OSError):
            pass

        # Try using Volume Shadow Copy
        try:
            vss_path = self._get_vss_path(str(src_path))
            if vss_path and Path(vss_path).exists():
                shutil.copy2(vss_path, dst_path)
                metadata = self._get_metadata(str(src_path), dst_path, artifact_type)
                metadata['collection_method'] = 'vss'
                yield str(dst_path), metadata
                return
        except Exception:
            pass

        # Try raw file read (requires admin)
        try:
            self._raw_copy(str(src_path), str(dst_path))
            metadata = self._get_metadata(str(src_path), dst_path, artifact_type)
            metadata['collection_method'] = 'raw_read'
            yield str(dst_path), metadata
        except Exception as e:
            print(f"Cannot collect locked file {file_path}: {e}")

    def collect_user_files(
        self,
        path_pattern: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files from user profile with environment variable expansion"""
        expanded_path = os.path.expandvars(path_pattern)
        src_path = Path(expanded_path)

        if src_path.exists():
            try:
                dst_path = output_dir / src_path.name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(expanded_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                print(f"Cannot access {expanded_path}: {e}")

    def collect_user_glob(
        self,
        pattern: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect files matching a glob pattern with environment variable expansion"""
        expanded_pattern = os.path.expandvars(pattern)
        for src_path in glob.glob(expanded_pattern):
            try:
                dst_path = output_dir / Path(src_path).name
                shutil.copy2(src_path, dst_path)
                yield str(dst_path), self._get_metadata(src_path, dst_path, artifact_type)
            except (PermissionError, OSError) as e:
                print(f"Cannot access {src_path}: {e}")
                continue

    def collect_ntuser(
        self,
        _: str,
        output_dir: Path,
        artifact_type: str
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Collect NTUSER.DAT files for all users"""
        users_dir = Path(r'C:\Users')

        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue

            ntuser_path = user_dir / 'NTUSER.DAT'
            if ntuser_path.exists():
                dst_path = output_dir / f"NTUSER.DAT_{user_dir.name}"

                # NTUSER.DAT is usually locked
                for result in self.collect_locked_files(
                    str(ntuser_path), output_dir, artifact_type
                ):
                    # Rename to include username
                    if Path(result[0]).exists():
                        final_path = output_dir / f"NTUSER.DAT_{user_dir.name}"
                        Path(result[0]).rename(final_path)
                        result[1]['username'] = user_dir.name
                        yield str(final_path), result[1]

    def _get_metadata(
        self,
        src_path: str,
        dst_path: Path,
        artifact_type: str
    ) -> Dict[str, Any]:
        """Generate metadata for a collected file"""
        src = Path(src_path)

        # Calculate hash
        sha256 = hashlib.sha256()
        with open(dst_path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                sha256.update(chunk)

        try:
            stat = src.stat()
            timestamps = {
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            }
        except (OSError, ValueError):
            timestamps = {}

        return {
            'artifact_type': artifact_type,
            'original_path': str(src_path),
            'filename': src.name,
            'size': dst_path.stat().st_size,
            'sha256': sha256.hexdigest(),
            'timestamps': timestamps,
            'collected_at': datetime.utcnow().isoformat(),
            'collection_method': 'direct_copy',
        }

    def _get_vss_path(self, file_path: str) -> Optional[str]:
        """Get path to file in latest Volume Shadow Copy"""
        try:
            import subprocess
            result = subprocess.run(
                ['vssadmin', 'list', 'shadows'],
                capture_output=True,
                text=True
            )

            # Parse VSS output to find latest shadow copy
            # This is simplified - real implementation would be more robust
            for line in result.stdout.split('\n'):
                if 'Shadow Copy Volume' in line:
                    vss_volume = line.split(':')[-1].strip()
                    # Convert path to VSS path
                    drive = file_path[0]
                    relative_path = file_path[2:]  # Remove 'C:'
                    return f"{vss_volume}{relative_path}"

        except Exception:
            pass

        return None

    def _raw_copy(self, src_path: str, dst_path: str):
        """
        Copy file using raw disk read.

        This is a fallback for locked files.
        Requires administrator privileges.
        """
        # This would use low-level Windows API or pytsk3
        # For now, just raise an exception
        raise NotImplementedError("Raw copy requires pytsk3 library")
