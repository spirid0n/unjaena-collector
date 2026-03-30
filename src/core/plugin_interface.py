"""
Plugin interface for advanced forensic collection methods.

The unjaena-collector public tool ships with non-destructive, non-exploit
collection methods only. Additional methods requiring special authorization
are available via the separately distributed pro plugin:

    pip install unjaena-collector-pro  (licensed forensic agencies only)

Any pro plugin must implement the AdvancedCollectionPlugin interface below.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Generator, List, Optional, Tuple


class AdvancedCollectionPlugin:
    """Interface that unjaena-collector-pro must implement.

    The collector calls _load_advanced_plugin() at runtime. If the pro
    package is installed it returns an instance of this class (or a subclass).
    If not installed, returns None and only built-in methods are used.
    """

    def collect_elevated(
        self,
        artifact_type: str,
        package: str,
        sdk: int,
        security_patch: str,
        db_paths: List[str],
        output_dir: Any,
        progress_callback: Optional[Callable[[str], None]],
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Attempt advanced data access for non-debuggable, non-backup apps.

        Implementations must:
        - Only run under a valid forensic authorization context
        - Log every access attempt to a tamper-evident audit trail
        - Yield (file_path, metadata) tuples in the same format as built-in
          collection methods
        - Clean up all temporary artifacts from the device after collection
        - Never modify app data — read-only access only

        Args:
            artifact_type:     Collector artifact type identifier.
            package:           Target app package name.
            sdk:               Device Android SDK level.
            security_patch:    Device security patch date string (YYYY-MM-DD).
            db_paths:          Expected database paths inside the app sandbox.
            output_dir:        Local Path to write collected files.
            progress_callback: Optional callback for progress messages.

        Yields:
            (local_file_path, metadata_dict) for each collected file.
        """
        return
        yield  # make this a generator

    def collect_apk_downgrade(
        self,
        artifact_type: str,
        package: str,
        db_paths: List[str],
        output_dir: Any,
        progress_callback: Optional[Callable[[str], None]],
    ) -> Generator[Tuple[str, Dict[str, Any]], None, None]:
        """Attempt collection via APK version substitution strategy.

        IMPORTANT: This method installs an alternative APK build over the
        current version, runs backup, then restores the original. It modifies
        device state and must only be used with explicit written authorization.

        Implementations must restore the original APK regardless of outcome.

        Yields:
            (local_file_path, metadata_dict) for each collected file.
        """
        return
        yield

    def is_available(self) -> Dict[str, bool]:
        """Return capability map for this plugin instance.

        Example return value::

            {
                'elevated_access': True,
                'apk_downgrade': False,
                'audit_logging': True,
            }
        """
        return {}

    def get_plugin_version(self) -> str:
        """Return the pro plugin version string."""
        return "0.0.0"

    def get_audit_log_path(self) -> Optional[str]:
        """Return path to the plugin's audit log file, or None."""
        return None
