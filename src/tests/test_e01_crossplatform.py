# -*- coding: utf-8 -*-
"""
E01 Cross-Platform Support Unit Tests
Test Linux/macOS support for E01 collector
"""
import sys
import os

# Add collector src to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.e01_artifact_collector import (
    E01ArtifactCollector,
    ARTIFACT_PATHS,
    PartitionInfo,
)
from collectors.base_mft_collector import detect_os_type


def test_artifact_paths_structure():
    """Verify ARTIFACT_PATHS structure"""
    print("\n" + "=" * 60)
    print("[TEST] ARTIFACT_PATHS Structure")
    print("=" * 60)

    windows_artifacts = []
    linux_artifacts = []
    macos_artifacts = []
    skipped = []

    for name, config in ARTIFACT_PATHS.items():
        if config.get('skip'):
            skipped.append(name)
        elif config.get('os_type') == 'linux':
            linux_artifacts.append(name)
        elif config.get('os_type') == 'macos':
            macos_artifacts.append(name)
        else:
            windows_artifacts.append(name)

    print(f"\n  Windows artifacts: {len(windows_artifacts)}")
    print(f"  Linux artifacts: {len(linux_artifacts)}")
    print(f"  macOS artifacts: {len(macos_artifacts)}")
    print(f"  Skipped (mobile): {len(skipped)}")

    # Verify minimum count
    assert len(windows_artifacts) >= 15, f"Windows artifacts too few: {len(windows_artifacts)}"
    assert len(linux_artifacts) >= 10, f"Linux artifacts too few: {len(linux_artifacts)}"
    assert len(macos_artifacts) >= 8, f"macOS artifacts too few: {len(macos_artifacts)}"

    print("\n  [PASS] Artifact counts OK")
    return True


def test_linux_artifact_paths():
    """Verify Linux artifact paths"""
    print("\n" + "=" * 60)
    print("[TEST] Linux Artifact Paths")
    print("=" * 60)

    required_linux = [
        'linux_auth_log',
        'linux_bash_history',
        'linux_crontab',
        'linux_passwd',
        'linux_ssh_authorized_keys',
    ]

    for artifact in required_linux:
        config = ARTIFACT_PATHS.get(artifact)
        assert config is not None, f"Missing: {artifact}"
        assert config.get('os_type') == 'linux', f"{artifact} os_type != linux"
        assert 'paths' in config or 'user_paths' in config, f"{artifact} has no paths"
        print(f"  [OK] {artifact}")

    print("\n  [PASS] All required Linux artifacts defined")
    return True


def test_macos_artifact_paths():
    """Verify macOS artifact paths"""
    print("\n" + "=" * 60)
    print("[TEST] macOS Artifact Paths")
    print("=" * 60)

    required_macos = [
        'macos_launch_agent',
        'macos_launch_daemon',
        'macos_zsh_history',
        'macos_tcc_db',
        'macos_safari_history',
    ]

    for artifact in required_macos:
        config = ARTIFACT_PATHS.get(artifact)
        assert config is not None, f"Missing: {artifact}"
        assert config.get('os_type') == 'macos', f"{artifact} os_type != macos"
        assert 'paths' in config or 'user_paths' in config, f"{artifact} has no paths"
        print(f"  [OK] {artifact}")

    print("\n  [PASS] All required macOS artifacts defined")
    return True


def test_detect_os_type():
    """Test OS type detection"""
    print("\n" + "=" * 60)
    print("[TEST] OS Type Detection")
    print("=" * 60)

    test_cases = [
        # Windows filesystems
        ('NTFS', 'windows'),
        ('ntfs', 'windows'),
        ('FAT32', 'windows'),
        ('FAT16', 'windows'),
        # Linux filesystems
        ('ext4', 'linux'),
        ('ext3', 'linux'),
        ('ext2', 'linux'),
        ('xfs', 'linux'),
        ('btrfs', 'linux'),
        ('f2fs', 'linux'),
        ('zfs', 'linux'),
        # macOS filesystems
        ('APFS', 'macos'),
        ('apfs', 'macos'),
        ('HFS+', 'macos'),
        ('hfs+', 'macos'),
        ('hfs', 'macos'),
        # Cross-platform / Unknown
        ('exfat', 'unknown'),  # Cross-platform
        ('unknown', 'unknown'),
    ]

    for filesystem, expected in test_cases:
        result = detect_os_type(filesystem)
        status = "[OK]" if result == expected else "[FAIL]"
        print(f"  {status} {filesystem} -> {result} (expected: {expected})")
        assert result == expected, f"detect_os_type('{filesystem}') = {result}, expected {expected}"

    print("\n  [PASS] All OS type detection tests passed")
    return True


def test_partition_info_dataclass():
    """Test PartitionInfo dataclass"""
    print("\n" + "=" * 60)
    print("[TEST] PartitionInfo Dataclass")
    print("=" * 60)

    partition = PartitionInfo(
        index=0,
        offset=1048576,
        size=107374182400,  # 100GB
        filesystem='ext4',
        type_name='Linux filesystem',
        bootable=False
    )

    assert partition.index == 0
    assert partition.filesystem == 'ext4'
    assert partition.size == 107374182400
    print(f"  Partition: index={partition.index}, fs={partition.filesystem}, size={partition.size/1024**3:.1f}GB")

    print("\n  [PASS] PartitionInfo works correctly")
    return True


def test_user_path_expansion():
    """Verify user path expansion"""
    print("\n" + "=" * 60)
    print("[TEST] User Path Expansion Logic")
    print("=" * 60)

    # Linux user paths
    linux_config = ARTIFACT_PATHS.get('linux_bash_history', {})
    user_paths = linux_config.get('user_paths', [])
    assert len(user_paths) > 0, "linux_bash_history should have user_paths"
    print(f"  Linux bash_history user_paths: {user_paths}")

    # macOS user paths
    macos_config = ARTIFACT_PATHS.get('macos_zsh_history', {})
    user_paths = macos_config.get('user_paths', [])
    assert len(user_paths) > 0, "macos_zsh_history should have user_paths"
    print(f"  macOS zsh_history user_paths: {user_paths}")

    print("\n  [PASS] User paths defined correctly")
    return True


def main():
    """Run main tests"""
    print("\n" + "#" * 60)
    print("# E01 Cross-Platform Support Unit Tests")
    print("#" * 60)

    results = {}

    # Run tests
    results['artifact_paths_structure'] = test_artifact_paths_structure()
    results['linux_artifact_paths'] = test_linux_artifact_paths()
    results['macos_artifact_paths'] = test_macos_artifact_paths()
    results['detect_os_type'] = test_detect_os_type()
    results['partition_info_dataclass'] = test_partition_info_dataclass()
    results['user_path_expansion'] = test_user_path_expansion()

    # Results summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for name, result in results.items():
        status = "[PASS]" if result else "[FAIL]"
        print(f"  {status} {name}")

    print(f"\n  Total: {passed}/{total} tests passed")
    print("=" * 60)

    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
