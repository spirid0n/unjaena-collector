# -*- coding: utf-8 -*-
r"""
USN Journal Collection Test

Test USN Journal collection from E01 images (skipping sparse regions)

Usage:
    python -m tests.test_usn_journal D:\Images\GMD_EXAM_IMAGE.E01
"""

import sys
import os
import time

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from collectors.forensic_disk import ForensicDiskAccessor, FORENSIC_DISK_AVAILABLE


def test_usn_journal(e01_path: str):
    """USN Journal collection test"""
    print("=" * 60)
    print("USN Journal Collection Test (skip_sparse=True)")
    print("=" * 60)

    if not FORENSIC_DISK_AVAILABLE:
        print("[ERROR] ForensicDiskAccessor not available")
        return False

    print(f"\n[Input] E01 Path: {e01_path}")

    try:
        # Create ForensicDiskAccessor
        print("\n[Step 1] Loading E01 image...")
        accessor = ForensicDiskAccessor.from_e01(e01_path)

        # Select partition
        partitions = accessor.list_partitions()
        print(f"  Found {len(partitions)} partition(s)")

        if not partitions:
            print("[FAIL] No partitions found")
            return False

        accessor.select_partition(0)
        print(f"  Selected partition 0: {partitions[0].filesystem}")

        # Test USN Journal collection
        print("\n[Step 2] Collecting USN Journal ($UsnJrnl:$J)...")
        print("  Using skip_sparse=True (only read actual data)")

        start_time = time.time()

        try:
            data = accessor.read_usnjrnl_raw(skip_sparse=True)
            elapsed = time.time() - start_time

            print(f"\n[Result]")
            print(f"  Data size: {len(data):,} bytes ({len(data) / (1024*1024):.2f} MB)")
            print(f"  Elapsed time: {elapsed:.2f} seconds")

            # Validate data
            if len(data) > 0:
                # Check USN record signature (first few bytes)
                non_zero = sum(1 for b in data[:min(len(data), 10000)] if b != 0)
                print(f"  Non-zero bytes (first 10KB): {non_zero}")

                # Check USN_RECORD_V2 header
                if len(data) >= 8:
                    # RecordLength (offset 0, 4 bytes)
                    record_len = int.from_bytes(data[0:4], 'little')
                    # MajorVersion (offset 4, 2 bytes)
                    major_ver = int.from_bytes(data[4:6], 'little')
                    # MinorVersion (offset 6, 2 bytes)
                    minor_ver = int.from_bytes(data[6:8], 'little')

                    print(f"  First record: len={record_len}, version={major_ver}.{minor_ver}")

                    if major_ver in (2, 3) and record_len > 0 and record_len < 65536:
                        print("  [OK] Valid USN record header detected")
                    else:
                        print("  [WARN] USN record header may be invalid or data starts mid-record")

                print("\n[SUCCESS] USN Journal collected successfully!")
                accessor.close()
                return True
            else:
                print("  [WARN] Empty data returned")
                accessor.close()
                return False

        except Exception as e:
            print(f"\n[ERROR] Collection failed: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            accessor.close()
            return False

    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_comparison(e01_path: str):
    """Compare sparse inclusion vs skipping (Warning: including sparse may cause memory issues)"""
    print("\n" + "=" * 60)
    print("Comparison: skip_sparse=True vs False")
    print("=" * 60)
    print("[WARN] skip_sparse=False may cause memory issues!")

    accessor = ForensicDiskAccessor.from_e01(e01_path)
    accessor.select_partition(0)

    # skip_sparse=True (safe)
    print("\n[Test 1] skip_sparse=True")
    start = time.time()
    data_skip = accessor.read_usnjrnl_raw(skip_sparse=True)
    time_skip = time.time() - start
    print(f"  Size: {len(data_skip):,} bytes")
    print(f"  Time: {time_skip:.2f}s")

    accessor.close()
    print("\n[Comparison skipped] skip_sparse=False may cause OOM")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m tests.test_usn_journal <E01_PATH>")
        sys.exit(1)

    e01_path = sys.argv[1]

    if not os.path.exists(e01_path):
        print(f"[ERROR] File not found: {e01_path}")
        sys.exit(1)

    success = test_usn_journal(e01_path)
    sys.exit(0 if success else 1)
