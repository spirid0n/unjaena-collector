# -*- coding: utf-8 -*-
"""
Volume Image Detection Test

Test for detecting E01 volume images (single partition images, not full disk images)

Usage:
    python -m tests.test_volume_image D:\Images\GMD_EXAM_IMAGE.E01
"""

import sys
import os

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.forensic_disk import ForensicDiskAccessor, FORENSIC_DISK_AVAILABLE


def test_volume_image(e01_path: str):
    """Volume image detection test"""
    print("=" * 60)
    print("Volume Image Detection Test")
    print("=" * 60)

    if not FORENSIC_DISK_AVAILABLE:
        print("[ERROR] ForensicDiskAccessor not available (pyewf not installed)")
        return False

    print(f"\n[Input] E01 Path: {e01_path}")

    try:
        # Create ForensicDiskAccessor
        print("\n[Step 1] Loading E01 image...")
        accessor = ForensicDiskAccessor.from_e01(e01_path)

        # List partitions
        print("\n[Step 2] Listing partitions...")
        partitions = accessor.list_partitions()

        print(f"\n[Result] Found {len(partitions)} partition(s):")
        for i, p in enumerate(partitions):
            print(f"  [{i}] {p.filesystem} - {p.type_name}")
            print(f"      Offset: {p.offset}, Size: {p.size / (1024**3):.2f} GB")

        if not partitions:
            print("\n[FAIL] No partitions detected!")
            accessor.close()
            return False

        # Select first partition
        print("\n[Step 3] Selecting partition 0...")
        accessor.select_partition(0)

        partition = accessor.get_selected_partition()
        print(f"  Filesystem: {partition.filesystem}")
        print(f"  Type: {partition.type_name}")

        # Test file system access
        print("\n[Step 4] Testing file access...")

        # Check if Windows folder exists
        if accessor.path_exists("/Windows"):
            print("  [OK] /Windows folder exists")
        else:
            print("  [--] /Windows folder not found")

        # Check if Users folder exists
        if accessor.path_exists("/Users"):
            print("  [OK] /Users folder exists")
        else:
            print("  [--] /Users folder not found")

        # Check registry hives
        registry_paths = [
            "/Windows/System32/config/SYSTEM",
            "/Windows/System32/config/SOFTWARE",
            "/Windows/System32/config/SAM",
        ]

        for reg_path in registry_paths:
            if accessor.path_exists(reg_path):
                print(f"  [OK] {reg_path} exists")
            else:
                print(f"  [--] {reg_path} not found")

        accessor.close()
        print("\n[SUCCESS] Volume image detection working correctly!")
        return True

    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m tests.test_volume_image <E01_PATH>")
        print("Example: python -m tests.test_volume_image D:\\Images\\GMD_EXAM_IMAGE.E01")
        sys.exit(1)

    e01_path = sys.argv[1]

    if not os.path.exists(e01_path):
        print(f"[ERROR] File not found: {e01_path}")
        sys.exit(1)

    success = test_volume_image(e01_path)
    sys.exit(0 if success else 1)
