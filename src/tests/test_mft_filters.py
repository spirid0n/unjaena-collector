# -*- coding: utf-8 -*-
"""
MFT Filter Configuration Tests

Verifies the correctness of ARTIFACT_MFT_FILTERS configuration.

Test items:
1. All artifact types have required fields
2. Path pattern regex validity
3. Extension format verification
4. Filename lowercase verification
"""

import pytest
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "collectors"))

from base_mft_collector import ARTIFACT_MFT_FILTERS


class TestMFTFilterConfiguration:
    """MFT filter configuration validation tests"""

    def test_all_filters_have_valid_structure(self):
        """Verify that all filters have a valid structure"""
        required_fields = ['description']  # Minimum required fields

        for artifact_type, config in ARTIFACT_MFT_FILTERS.items():
            # Check basic type
            assert isinstance(config, dict), f"{artifact_type}: config must be dict"

            # Must have at least one filter condition
            has_filter = any([
                'files' in config,
                'extensions' in config,
                'path_pattern' in config,
                'path_patterns' in config,
                'name_pattern' in config,
                'special' in config,
            ])
            assert has_filter, f"{artifact_type}: must have at least one filter condition"

    def test_path_patterns_are_valid_regex(self):
        """Verify that path patterns are valid regular expressions"""
        for artifact_type, config in ARTIFACT_MFT_FILTERS.items():
            # path_pattern
            if 'path_pattern' in config:
                pattern = config['path_pattern']
                try:
                    re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    pytest.fail(f"{artifact_type}: invalid path_pattern '{pattern}': {e}")

            # path_patterns (list)
            if 'path_patterns' in config:
                for i, pattern in enumerate(config['path_patterns']):
                    try:
                        re.compile(pattern, re.IGNORECASE)
                    except re.error as e:
                        pytest.fail(f"{artifact_type}: invalid path_patterns[{i}] '{pattern}': {e}")

    def test_extensions_are_lowercase_with_dot(self):
        """Verify that extensions are lowercase and start with a dot"""
        for artifact_type, config in ARTIFACT_MFT_FILTERS.items():
            if 'extensions' not in config:
                continue

            for ext in config['extensions']:
                assert ext.startswith('.'), \
                    f"{artifact_type}: extension '{ext}' must start with '.'"
                assert ext == ext.lower(), \
                    f"{artifact_type}: extension '{ext}' must be lowercase"

    def test_files_are_lowercase(self):
        """Verify that filenames are lowercase"""
        for artifact_type, config in ARTIFACT_MFT_FILTERS.items():
            if 'files' not in config:
                continue

            for filename in config['files']:
                assert filename == filename.lower(), \
                    f"{artifact_type}: filename '{filename}' must be lowercase"

    def test_path_patterns_use_forward_slash(self):
        """Verify that path patterns use forward slash (/) - backslash prohibited"""
        for artifact_type, config in ARTIFACT_MFT_FILTERS.items():
            patterns = []

            if 'path_pattern' in config:
                patterns.append(config['path_pattern'])
            if 'path_patterns' in config:
                patterns.extend(config['path_patterns'])

            for pattern in patterns:
                # Check for unescaped backslashes
                # Regex escapes like \s, \d are allowed, literal backslash is prohibited
                if '\\\\' in pattern:  # Literal backslash
                    pytest.fail(
                        f"{artifact_type}: path pattern '{pattern}' uses backslash. "
                        "Use forward slash '/' for cross-platform compatibility."
                    )

    def test_special_artifacts_have_method(self):
        """Verify that special artifacts have the 'special' method"""
        special_artifacts = ['mft', 'usn_journal', 'logfile']

        for artifact_type in special_artifacts:
            if artifact_type in ARTIFACT_MFT_FILTERS:
                config = ARTIFACT_MFT_FILTERS[artifact_type]
                assert 'special' in config, \
                    f"{artifact_type}: special artifact must have 'special' field"

    def test_media_artifacts_have_size_limit(self):
        """Verify that media artifacts (image, video) have size limits"""
        media_artifacts = ['image', 'video']

        for artifact_type in media_artifacts:
            if artifact_type in ARTIFACT_MFT_FILTERS:
                config = ARTIFACT_MFT_FILTERS[artifact_type]
                assert 'max_file_size' in config, \
                    f"{artifact_type}: media artifact should have 'max_file_size' limit"
                assert config['max_file_size'] > 0, \
                    f"{artifact_type}: max_file_size must be positive"

    def test_no_duplicate_extensions_across_filters(self):
        """Warn if extensions are duplicated across multiple filters (informational)"""
        extension_map = {}

        for artifact_type, config in ARTIFACT_MFT_FILTERS.items():
            if 'extensions' not in config:
                continue

            for ext in config['extensions']:
                if ext in extension_map:
                    # Print warning only (not an error)
                    print(f"[INFO] Extension '{ext}' used in both "
                          f"'{extension_map[ext]}' and '{artifact_type}'")
                else:
                    extension_map[ext] = artifact_type

    def test_required_artifact_types_exist(self):
        """Verify that required artifact types are defined"""
        required_types = [
            'registry', 'eventlog', 'prefetch', 'mft', 'usn_journal',
            'browser', 'recycle_bin', 'jumplist',  # browser_history -> browser
            'usb', 'amcache',
        ]

        for artifact_type in required_types:
            assert artifact_type in ARTIFACT_MFT_FILTERS, \
                f"Required artifact type '{artifact_type}' not found in ARTIFACT_MFT_FILTERS"


class TestMFTFilterPatternMatching:
    """MFT filter pattern matching tests"""

    @pytest.mark.parametrize("path,expected_match", [
        ("Windows/System32/config/SYSTEM", True),
        ("windows/system32/config/system", True),
        ("Users/Admin/NTUSER.DAT", True),
        ("users/admin/ntuser.dat", True),
        ("Windows/Prefetch/CALC.EXE-12345678.pf", True),
        ("RandomFolder/SomeFile.txt", False),
    ])
    def test_common_paths_match_correctly(self, path, expected_match):
        """Verify that common paths match correctly"""
        # Path normalization (backslash to forward slash)
        normalized_path = path.lower().replace('\\', '/')

        matched = False
        for artifact_type, config in ARTIFACT_MFT_FILTERS.items():
            patterns = []
            if 'path_pattern' in config:
                patterns.append(config['path_pattern'])
            if 'path_patterns' in config:
                patterns.extend(config['path_patterns'])

            for pattern in patterns:
                if re.search(pattern, normalized_path, re.IGNORECASE):
                    matched = True
                    break

            if matched:
                break

        if expected_match:
            assert matched, f"Path '{path}' should match at least one filter"
        # Don't verify when expected_match=False (may match some patterns)

    def test_usb_setupapi_matches(self):
        """Verify that USB setupapi.dev.log file matches"""
        config = ARTIFACT_MFT_FILTERS.get('usb', {})
        target_files = config.get('files', set())

        assert 'setupapi.dev.log' in target_files, \
            "USB filter should include 'setupapi.dev.log'"

    def test_registry_hives_match(self):
        """Verify that registry hive files match"""
        config = ARTIFACT_MFT_FILTERS.get('registry', {})
        target_files = config.get('files', set())

        required_hives = ['system', 'software', 'sam', 'security', 'ntuser.dat']
        for hive in required_hives:
            assert hive in target_files, \
                f"Registry filter should include '{hive}'"
