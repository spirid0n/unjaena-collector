#!/usr/bin/env python3
"""
E2E Cross-Platform Artifact Type Cross-Check Test
==================================================
Validates that ALL collector artifact types have matching server ArtifactType
enum entries. Checks collector → server enum alignment per platform.
"""

import ast
import re
import sys
from pathlib import Path
from typing import Set

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent


def extract_dict_keys(filepath: str, dict_name: str) -> Set[str]:
    """Extract string keys from a dict assignment using AST."""
    keys = set()
    with open(filepath, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read())

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == dict_name:
                    if isinstance(node.value, ast.Dict):
                        for key in node.value.keys:
                            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                                keys.add(key.value)
    return keys


def extract_server_enum_values() -> Set[str]:
    """Extract all ArtifactType enum string values."""
    fpath = PROJECT_ROOT / 'migration' / 'backend' / 'services' / 'agents' / 'artifact_types.py'
    values = set()
    with open(fpath, 'r', encoding='utf-8') as f:
        for line in f:
            m = re.match(r'\s+\w+\s*=\s*["\']([^"\']+)["\']', line)
            if m:
                values.add(m.group(1))
    return values


def extract_parser_registered_values() -> Set[str]:
    """Extract all artifact type values registered with parsers."""
    fpath = PROJECT_ROOT / 'migration' / 'backend' / 'services' / 'server_parsing_service.py'
    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()

    enum_names = set()

    # Direct: self._parsers[ArtifactType.ENUM_NAME] = ...
    for m in re.finditer(r'self\._parsers\[ArtifactType\.(\w+)\]\s*=', content):
        enum_names.add(m.group(1).lower())

    # List-based: find ArtifactType.X inside any *_types = [...] block
    # Match all multi-line list assignments containing ArtifactType references
    for m in re.finditer(r'\w+_types\s*=\s*\[(.*?)\]', content, re.DOTALL):
        block = m.group(1)
        for em in re.finditer(r'ArtifactType\.(\w+)', block):
            enum_names.add(em.group(1).lower())

    # Also catch: _ANDROID_BINARY_TYPES = {ArtifactType.X, ...}
    for m in re.finditer(r'\w+\s*=\s*\{(.*?)\}', content, re.DOTALL):
        block = m.group(1)
        for em in re.finditer(r'ArtifactType\.(\w+)', block):
            enum_names.add(em.group(1).lower())

    return enum_names


def run_test():
    print("=" * 70)
    print("  ARTIFACT TYPE CROSS-CHECK")
    print("=" * 70)

    server_enums = extract_server_enum_values()
    server_parsers = extract_parser_registered_values()

    collector_dir = PROJECT_ROOT / 'collector' / 'src' / 'collectors'

    # Platform configs: (name, dict_file, dict_name, prefix_filter)
    platforms = [
        ('Linux', 'linux_collector.py', 'LINUX_ARTIFACT_TYPES', 'linux_'),
        ('macOS-filters', 'macos_artifacts.py', 'MACOS_ARTIFACT_FILTERS', 'macos_'),
        ('macOS-explicit', 'macos_collector.py', 'MACOS_ARTIFACT_TYPES', 'macos_'),
        ('iOS', 'ios_collector.py', 'IOS_ARTIFACT_TYPES', 'mobile_ios_'),
    ]

    all_ok = 0
    all_enum_gaps = []
    all_parser_gaps = []
    all_checked = 0

    for name, fname, dname, prefix in platforms:
        fpath = collector_dir / fname
        if not fpath.exists():
            print(f"\n  [{name}] File not found: {fname}")
            continue

        types = extract_dict_keys(str(fpath), dname)
        # Filter to platform-specific types only
        types = {t for t in types if t.startswith(prefix)}

        if not types:
            print(f"\n  [{name}] No types with prefix '{prefix}' in {dname}")
            continue

        enum_gaps = sorted([t for t in types if t not in server_enums])
        parser_gaps = sorted([t for t in types if t in server_enums and t not in server_parsers])
        ok = len(types) - len(enum_gaps) - len(parser_gaps)

        all_ok += ok
        all_enum_gaps.extend([(name, t) for t in enum_gaps])
        all_parser_gaps.extend([(name, t) for t in parser_gaps])
        all_checked += len(types)

        status = "PASS" if not enum_gaps and not parser_gaps else "GAPS"
        print(f"\n  [{name}] {len(types)} types | {ok} OK | "
              f"{len(enum_gaps)} no-enum | {len(parser_gaps)} no-parser | {status}")
        for t in enum_gaps:
            print(f"    CRITICAL no-enum: {t}")
        for t in parser_gaps:
            print(f"    WARNING no-parser: {t}")

    # Android: special handling (types defined via artifact_type strings, not a single dict)
    android_types = set()
    for fname in ['android_collector.py', 'android_collector_extended.py']:
        fpath = collector_dir / fname
        if not fpath.exists():
            continue
        for dname in ['PROVIDER_ARTIFACTS', 'EXTENDED_ARTIFACT_TYPES',
                       'APP_ARTIFACTS', 'CONTENT_PROVIDERS']:
            android_types |= extract_dict_keys(str(fpath), dname)

    # Also extract from explicit string assignments
    for fname in ['android_collector.py', 'android_collector_extended.py']:
        fpath = collector_dir / fname
        if not fpath.exists():
            continue
        with open(fpath, 'r', encoding='utf-8') as f:
            content = f.read()
        for m in re.finditer(r"['\"]artifact_type['\"]\s*:\s*['\"]"
                             r"(mobile_android_\w+)['\"]", content):
            android_types.add(m.group(1))

    # Advanced collection types
    for fname, dname in [
        ('android_frida_collector.py', None),
        ('android_edl_collector.py', None),
        ('android_fastboot_collector.py', None),
        ('android_mtk_collector.py', None),
    ]:
        fpath = collector_dir / fname
        if not fpath.exists():
            continue
        with open(fpath, 'r', encoding='utf-8') as f:
            content = f.read()
        for m in re.finditer(r"['\"]artifact_type['\"]\s*:\s*['\"]"
                             r"((?:mobile_)?android_\w+)['\"]", content):
            android_types.add(m.group(1))

    # Filter out non-artifact-type strings
    android_types = {t for t in android_types
                     if t.startswith('mobile_android_') or t.startswith('android_')
                     if '_collector' not in t and t not in {
                         'android_version', 'android_id', 'android_backup_',
                         'android_id_out', 'android_backup',
                     }}

    if android_types:
        enum_gaps = sorted([t for t in android_types if t not in server_enums])
        parser_gaps = sorted([t for t in android_types if t in server_enums and t not in server_parsers])
        ok = len(android_types) - len(enum_gaps) - len(parser_gaps)

        all_ok += ok
        all_enum_gaps.extend([('Android', t) for t in enum_gaps])
        all_parser_gaps.extend([('Android', t) for t in parser_gaps])
        all_checked += len(android_types)

        status = "PASS" if not enum_gaps and not parser_gaps else "GAPS"
        print(f"\n  [Android] {len(android_types)} types | {ok} OK | "
              f"{len(enum_gaps)} no-enum | {len(parser_gaps)} no-parser | {status}")
        for t in enum_gaps:
            print(f"    CRITICAL no-enum: {t}")
        for t in parser_gaps:
            print(f"    WARNING no-parser: {t}")

    # Windows: filter ARTIFACT_TYPES to Windows-only (exclude mobile_, linux_, macos_)
    win_all = extract_dict_keys(str(collector_dir / 'artifact_collector.py'), 'ARTIFACT_TYPES')
    win_types = {t for t in win_all
                 if not t.startswith('mobile_') and not t.startswith('linux_')
                 and not t.startswith('macos_') and not t.startswith('android_')}

    if win_types:
        enum_gaps = sorted([t for t in win_types if t not in server_enums])
        parser_gaps = sorted([t for t in win_types if t in server_enums and t not in server_parsers])
        ok = len(win_types) - len(enum_gaps) - len(parser_gaps)

        all_ok += ok
        all_enum_gaps.extend([('Windows', t) for t in enum_gaps])
        all_parser_gaps.extend([('Windows', t) for t in parser_gaps])
        all_checked += len(win_types)

        status = "PASS" if not enum_gaps and not parser_gaps else "GAPS"
        print(f"\n  [Windows] {len(win_types)} types | {ok} OK | "
              f"{len(enum_gaps)} no-enum | {len(parser_gaps)} no-parser | {status}")
        for t in enum_gaps:
            print(f"    CRITICAL no-enum: {t}")
        for t in parser_gaps:
            print(f"    WARNING no-parser: {t}")

    # Final summary
    coverage = (all_ok / all_checked * 100) if all_checked > 0 else 0
    print(f"\n{'=' * 70}")
    print(f"  SUMMARY: {all_checked} types checked")
    print(f"  Enum matched:   {all_ok + len(all_parser_gaps)}/{all_checked}")
    print(f"  Parser matched: {all_ok}/{all_checked}")
    print(f"  Enum gaps:      {len(all_enum_gaps)} (CRITICAL - upload will fail)")
    print(f"  Parser gaps:    {len(all_parser_gaps)} (WARNING - parsing will skip)")
    print(f"  Full coverage:  {coverage:.1f}%")

    if all_enum_gaps:
        print(f"\n  CRITICAL ENUM GAPS:")
        for plat, t in all_enum_gaps:
            print(f"    [{plat}] {t}")

    result = "PASS" if not all_enum_gaps else "FAIL"
    print(f"\n  RESULT: {result}")
    print(f"{'=' * 70}")

    return len(all_enum_gaps) == 0


if __name__ == '__main__':
    success = run_test()
    sys.exit(0 if success else 1)
