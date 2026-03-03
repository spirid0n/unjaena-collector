# -*- coding: utf-8 -*-
"""
Path Normalization Tests

Verifies the correctness of path normalization logic.

Test items:
1. Backslash to forward slash conversion
2. Case normalization
3. Path pattern matching
"""

import pytest
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "collectors"))


class TestPathNormalization:
    """Path normalization tests"""

    def normalize_path(self, path: str) -> str:
        """Path normalization function (same logic as base_mft_collector.py)"""
        return path.lower().replace('\\', '/')

    @pytest.mark.parametrize("input_path,expected", [
        # Backslash to forward slash
        (r"Windows\System32\config\SYSTEM", "windows/system32/config/system"),
        (r"Users\Admin\NTUSER.DAT", "users/admin/ntuser.dat"),
        (r"Windows\INF\setupapi.dev.log", "windows/inf/setupapi.dev.log"),

        # Already using forward slash
        ("Windows/System32/config/SYSTEM", "windows/system32/config/system"),

        # Mixed case
        (r"Windows\System32/config\SYSTEM", "windows/system32/config/system"),

        # Letter case
        ("WINDOWS/SYSTEM32/CONFIG/SYSTEM", "windows/system32/config/system"),
        ("windows/system32/config/system", "windows/system32/config/system"),
    ])
    def test_path_normalization(self, input_path, expected):
        """Verify that path normalization works correctly"""
        result = self.normalize_path(input_path)
        assert result == expected, f"Expected '{expected}', got '{result}'"

    @pytest.mark.parametrize("path,pattern,should_match", [
        # Registry
        ("windows/system32/config/system", r"windows/system32/config/", True),
        (r"Windows\System32\config\SYSTEM", r"windows/system32/config/", True),

        # USB
        ("windows/inf/setupapi.dev.log", r"windows/inf/", True),
        (r"Windows\INF\setupapi.dev.log", r"windows/inf/", True),

        # Prefetch
        ("windows/prefetch/calc.exe-12345678.pf", r"windows/prefetch/", True),
        (r"Windows\Prefetch\CALC.EXE-12345678.pf", r"windows/prefetch/", True),

        # User paths
        ("users/admin/appdata/local/", r"users/[^/]+/appdata/", True),
        ("Users\\Admin\\AppData\\Local\\file.txt", r"users/[^/]+/appdata/", True),

        # Non-matching
        ("program files/app/file.txt", r"windows/system32/", False),
    ])
    def test_pattern_matching_with_normalization(self, path, pattern, should_match):
        """Verify that normalized paths match patterns correctly"""
        normalized = self.normalize_path(path)
        compiled_pattern = re.compile(pattern, re.IGNORECASE)

        matches = bool(compiled_pattern.search(normalized))
        assert matches == should_match, \
            f"Path '{path}' (normalized: '{normalized}') " \
            f"{'should' if should_match else 'should not'} match pattern '{pattern}'"


class TestE01PathNormalization:
    """Path normalization test for paths extracted from E01 images"""

    @pytest.mark.parametrize("mft_path,expected_normalized", [
        # Common path formats extracted from MFT
        ("Windows\\System32\\config\\SYSTEM", "windows/system32/config/system"),
        ("Users\\Administrator\\NTUSER.DAT", "users/administrator/ntuser.dat"),
        ("$Extend\\$UsnJrnl", "$extend/$usnjrnl"),

        # Root paths
        ("\\Windows\\System32", "/windows/system32"),
        ("Windows\\System32", "windows/system32"),

        # Including special characters
        ("Users\\User Name\\Documents", "users/user name/documents"),
        ("Program Files (x86)\\App", "program files (x86)/app"),
    ])
    def test_mft_path_normalization(self, mft_path, expected_normalized):
        """Verify that paths extracted from MFT are normalized correctly"""
        normalized = mft_path.lower().replace('\\', '/')
        assert normalized == expected_normalized


class TestFilenameCaseNormalization:
    """Filename case normalization tests"""

    @pytest.mark.parametrize("filename,target_files,should_match", [
        # Exact match
        ("setupapi.dev.log", {"setupapi.dev.log"}, True),
        ("NTUSER.DAT", {"ntuser.dat"}, True),
        ("SYSTEM", {"system"}, True),

        # Match after case conversion
        ("SetupAPI.dev.log", {"setupapi.dev.log"}, True),
        ("Ntuser.dat", {"ntuser.dat"}, True),

        # No match
        ("other.log", {"setupapi.dev.log"}, False),
        ("ntuser.dat.LOG1", {"ntuser.dat"}, False),
    ])
    def test_filename_matching(self, filename, target_files, should_match):
        """Verify that case-insensitive filename matching works correctly"""
        filename_lower = filename.lower()
        matches = filename_lower in target_files
        assert matches == should_match, \
            f"Filename '{filename}' (lower: '{filename_lower}') " \
            f"{'should' if should_match else 'should not'} match {target_files}"
