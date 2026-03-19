#!/usr/bin/env python3
"""
BitLocker 복호화 진단 스크립트
관리자 권한으로 실행 필요

사용법:
  python diag_bitlocker.py "123456-234567-345678-456789-567890-678901-789012-890123"
"""
import sys
import struct
import traceback


def read_disk(drive_number, offset, size):
    """물리 디스크에서 직접 읽기"""
    path = f"\\\\.\\PhysicalDrive{drive_number}"
    with open(path, 'rb') as f:
        f.seek(offset)
        return f.read(size)


def find_bitlocker_partitions(drive_number=0):
    """MBR/GPT에서 BitLocker 파티션 찾기"""
    print(f"\n{'='*60}")
    print(f"[1단계] 물리 디스크 PhysicalDrive{drive_number} 파티션 탐색")
    print(f"{'='*60}")

    mbr = read_disk(drive_number, 0, 512)
    print(f"  MBR 시그니처: {mbr[510:512].hex()} (예상: 55aa)")

    # GPT 체크
    gpt_header = read_disk(drive_number, 512, 512)
    is_gpt = gpt_header[:8] == b'EFI PART'
    print(f"  디스크 타입: {'GPT' if is_gpt else 'MBR'}")

    partitions = []

    if is_gpt:
        entries_lba = struct.unpack('<Q', gpt_header[72:80])[0]
        num_entries = struct.unpack('<I', gpt_header[80:84])[0]
        entry_size = struct.unpack('<I', gpt_header[84:88])[0]
        print(f"  GPT 엔트리: {num_entries}개, 크기: {entry_size}B, LBA: {entries_lba}")

        entries_data = read_disk(drive_number, entries_lba * 512, min(num_entries, 128) * entry_size)

        for i in range(min(num_entries, 128)):
            entry = entries_data[i * entry_size:(i + 1) * entry_size]
            type_guid = entry[:16]
            if type_guid == b'\x00' * 16:
                continue

            first_lba = struct.unpack('<Q', entry[32:40])[0]
            last_lba = struct.unpack('<Q', entry[40:48])[0]
            offset = first_lba * 512
            size = (last_lba - first_lba + 1) * 512

            # VBR 읽기
            vbr = read_disk(drive_number, offset, 512)
            fs_sig = _detect_fs(vbr)

            print(f"\n  파티션 #{i}: offset={offset} ({offset/1024/1024:.0f}MB), "
                  f"size={size/1024/1024/1024:.1f}GB, FS={fs_sig}")
            print(f"    VBR OEM: {vbr[3:11]}")
            print(f"    VBR 첫 16바이트: {vbr[:16].hex()}")

            partitions.append({
                'index': i,
                'offset': offset,
                'size': size,
                'filesystem': fs_sig,
                'vbr_oem': vbr[3:11],
            })
    else:
        # MBR 파티션
        for i in range(4):
            entry = mbr[446 + i * 16:446 + (i + 1) * 16]
            ptype = entry[4]
            if ptype == 0:
                continue

            lba = struct.unpack('<I', entry[8:12])[0]
            sectors = struct.unpack('<I', entry[12:16])[0]
            offset = lba * 512
            size = sectors * 512

            vbr = read_disk(drive_number, offset, 512)
            fs_sig = _detect_fs(vbr)

            print(f"\n  파티션 #{i}: type=0x{ptype:02x}, offset={offset}, "
                  f"size={size/1024/1024/1024:.1f}GB, FS={fs_sig}")
            print(f"    VBR OEM: {vbr[3:11]}")
            print(f"    VBR 첫 16바이트: {vbr[:16].hex()}")

            partitions.append({
                'index': i,
                'offset': offset,
                'size': size,
                'filesystem': fs_sig,
                'vbr_oem': vbr[3:11],
            })

    bitlocker_parts = [p for p in partitions if p['filesystem'] == 'BitLocker']
    print(f"\n  BitLocker 파티션: {len(bitlocker_parts)}개")
    return bitlocker_parts


def _detect_fs(vbr):
    """VBR에서 파일시스템 식별"""
    oem = vbr[3:11]
    if oem == b'-FVE-FS-':
        return 'BitLocker'
    elif oem.startswith(b'NTFS'):
        return 'NTFS'
    elif oem.startswith(b'MSDOS') or oem.startswith(b'mkfs.fat'):
        return 'FAT'
    elif vbr[:6] == b'LUKS\xba\xbe':
        return 'LUKS'
    return f'Unknown({oem})'


def test_bde_direct(drive_number, partition, recovery_key):
    """dissect.fve로 직접 BDE 테스트"""
    print(f"\n{'='*60}")
    print(f"[2단계] dissect.fve BDE 직접 테스트")
    print(f"{'='*60}")

    # dissect.fve 가용성
    try:
        from dissect.fve.bde import BDE
        import dissect.fve
        version = getattr(dissect.fve, '__version__', 'unknown')
        print(f"  dissect.fve 버전: {version}")
        print(f"  BDE 클래스: {BDE}")
    except ImportError as e:
        print(f"  [FAIL] dissect.fve 미설치: {e}")
        return

    offset = partition['offset']
    size = partition['size']
    print(f"  대상 파티션: #{partition['index']}, offset={offset}, size={size}")
    print(f"  Recovery Key: {recovery_key[:12]}...{recovery_key[-6:]}")

    # PartitionSliceReader 생성
    print(f"\n  [2a] 파티션 데이터 읽기...")
    disk_path = f"\\\\.\\PhysicalDrive{drive_number}"
    disk_fh = open(disk_path, 'rb')

    class SliceReader:
        def __init__(self, fh, offset, size):
            self._fh = fh
            self._offset = offset
            self._size = size
            self._pos = 0

        def read(self, n=-1):
            if n < 0:
                n = self._size - self._pos
            n = min(n, self._size - self._pos)
            if n <= 0:
                return b''
            self._fh.seek(self._offset + self._pos)
            data = self._fh.read(n)
            self._pos += len(data)
            return data

        def seek(self, offset, whence=0):
            if whence == 0:
                self._pos = offset
            elif whence == 1:
                self._pos += offset
            elif whence == 2:
                self._pos = self._size + offset
            self._pos = max(0, min(self._pos, self._size))
            return self._pos

        def tell(self):
            return self._pos

        @property
        def size(self):
            return self._size

        def seekable(self):
            return True

        def readable(self):
            return True

    reader = SliceReader(disk_fh, offset, size)

    # 파티션 시작 데이터 확인
    first_bytes = reader.read(16)
    reader.seek(0)
    print(f"  파티션 시작 16바이트: {first_bytes.hex()}")
    oem = first_bytes[3:11]
    print(f"  OEM ID: {oem} (예상: b'-FVE-FS-')")
    if oem != b'-FVE-FS-':
        print(f"  [WARN] BitLocker 시그니처 불일치!")

    # BDE 생성
    print(f"\n  [2b] BDE 객체 생성...")
    try:
        bde = BDE(reader)
        print(f"  [OK] BDE 생성 성공")
        print(f"  BDE 속성:")
        for attr in ['encryption_method', 'volume_identifier', 'protectors']:
            try:
                val = getattr(bde, attr, 'N/A')
                if attr == 'protectors':
                    protectors = list(val)
                    print(f"    {attr}: {len(protectors)}개")
                    for j, p in enumerate(protectors):
                        ptype = getattr(p, 'type', 'unknown')
                        pid = getattr(p, 'identifier', 'unknown')
                        print(f"      [{j}] type={ptype}, id={pid}")
                else:
                    print(f"    {attr}: {val}")
            except Exception as e:
                print(f"    {attr}: ERROR ({e})")
    except Exception as e:
        print(f"  [FAIL] BDE 생성 실패: {type(e).__name__}: {e}")
        traceback.print_exc()
        disk_fh.close()
        return

    # Recovery Key 검증
    print(f"\n  [2c] Recovery Key 형식 검증...")
    try:
        from dissect.fve.bde import check_recovery_password
        check_recovery_password(recovery_key)
        print(f"  [OK] Recovery Key 형식 유효")
    except Exception as e:
        print(f"  [FAIL] Recovery Key 형식 오류: {type(e).__name__}: {e}")

    # Unlock 시도
    print(f"\n  [2d] unlock_with_recovery_password() 호출...")
    try:
        result = bde.unlock_with_recovery_password(recovery_key)
        print(f"  [OK] 언락 성공! 반환값: {result}")
        print(f"  반환 타입: {type(result)}")
    except ValueError as e:
        print(f"  [FAIL] ValueError: {e}")
        print(f"  (복구 키가 잘못되었거나 지원되지 않는 암호화 방식)")
        traceback.print_exc()
        disk_fh.close()
        return
    except Exception as e:
        print(f"  [FAIL] {type(e).__name__}: {e}")
        traceback.print_exc()
        disk_fh.close()
        return

    # Stream 열기
    print(f"\n  [2e] bde.open() — 복호화 스트림 생성...")
    try:
        stream = bde.open()
        print(f"  [OK] 스트림 생성 성공")
        print(f"  스트림 타입: {type(stream)}")
        print(f"  스트림 size: {getattr(stream, 'size', 'N/A')}")

        # 읽기 테스트
        stream.seek(0)
        data = stream.read(512)
        print(f"  첫 512바이트 읽기 성공: {len(data)}바이트")
        print(f"  NTFS 시그니처 체크: {data[3:7]} (예상: b'NTFS')")

        if data[3:7] == b'NTFS':
            print(f"\n  [SUCCESS] BitLocker 복호화 완전 성공!")
        else:
            print(f"\n  [WARN] 복호화는 성공했으나 NTFS 시그니처 없음")
            print(f"    첫 16바이트: {data[:16].hex()}")

    except Exception as e:
        print(f"  [FAIL] {type(e).__name__}: {e}")
        traceback.print_exc()

    disk_fh.close()
    print(f"\n{'='*60}")
    print("진단 완료")
    print(f"{'='*60}")


def main():
    if len(sys.argv) < 2:
        print("사용법: python diag_bitlocker.py \"XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX\"")
        print("        python diag_bitlocker.py \"XXXXXX-XXXXXX-...\" [drive_number]")
        sys.exit(1)

    recovery_key = sys.argv[1].strip()
    drive_number = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    # 키 형식 정리
    digits = ''.join(c for c in recovery_key if c.isdigit())
    if len(digits) == 48:
        groups = [digits[i:i+6] for i in range(0, 48, 6)]
        recovery_key = '-'.join(groups)
        print(f"Recovery Key (정규화): {recovery_key[:12]}...{recovery_key[-6:]}")
    else:
        print(f"[WARN] 숫자 {len(digits)}자리 (예상: 48자리)")

    try:
        bitlocker_parts = find_bitlocker_partitions(drive_number)
    except PermissionError:
        print("\n[ERROR] 관리자 권한이 필요합니다!")
        print("  → 관리자 권한으로 cmd/PowerShell을 열고 다시 실행하세요.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] 디스크 읽기 실패: {e}")
        traceback.print_exc()
        sys.exit(1)

    if not bitlocker_parts:
        print("\n[ERROR] BitLocker 파티션을 찾을 수 없습니다.")
        sys.exit(1)

    for part in bitlocker_parts:
        test_bde_direct(drive_number, part, recovery_key)


if __name__ == '__main__':
    main()
