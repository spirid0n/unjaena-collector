# Collector Tools

iOS 포렌식 수집에 필요한 외부 도구들을 관리하는 디렉토리입니다.

## libimobiledevice

iOS 기기 직접 연결을 위한 오픈소스 라이브러리입니다.

### 자동 설치 (권장)

```bash
# Windows
python tools/download_libimobiledevice.py

# 설치 확인
python tools/download_libimobiledevice.py --check

# 강제 재설치
python tools/download_libimobiledevice.py --force

# 제거
python tools/download_libimobiledevice.py --uninstall
```

### 수동 설치

1. [libimobiledevice-win32 Releases](https://github.com/libimobiledevice-win32/imobiledevice-net/releases)에서 최신 버전 다운로드
2. `libimobiledevice.*.zip` 파일 압축 해제
3. 실행 파일들을 `tools/libimobiledevice/` 디렉토리에 복사

### 디렉토리 구조

```
tools/
├── download_libimobiledevice.py    # 다운로드 스크립트
├── README.md                        # 이 문서
└── libimobiledevice/               # 바이너리 (자동 생성)
    ├── idevice_id.exe
    ├── ideviceinfo.exe
    ├── idevicesyslog.exe
    ├── idevicecrashreport.exe
    ├── ideviceinstaller.exe
    ├── idevicebackup2.exe
    ├── *.dll                        # 의존성 라이브러리
    └── LICENSE                      # LGPL-2.1 라이선스
```

### 라이선스

libimobiledevice는 **LGPL-2.1** 라이선스로 배포됩니다.

- 소스코드: https://github.com/libimobiledevice/libimobiledevice
- Windows 빌드: https://github.com/libimobiledevice-win32/imobiledevice-net
- 라이선스 전문: https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html

LGPL-2.1에 따라 사용자는 이 바이너리를 자신이 빌드한 버전으로 교체할 수 있습니다.

### 포함된 도구

| 도구 | 설명 |
|------|------|
| `idevice_id` | 연결된 iOS 기기 UDID 목록 |
| `ideviceinfo` | 기기 상세 정보 (모델, iOS 버전 등) |
| `idevicesyslog` | 실시간 시스템 로그 |
| `idevicecrashreport` | 크래시 리포트 추출 |
| `ideviceinstaller` | 설치된 앱 목록 |
| `idevicebackup2` | iOS 백업 생성/복원 |

### 사용 조건

- iOS 기기가 USB로 연결되어 있어야 함
- 기기에서 "이 컴퓨터 신뢰" 승인 필요
- Windows의 경우 iTunes 또는 Apple Mobile Device Support 드라이버 필요

### 문제 해결

**"기기를 찾을 수 없습니다"**
1. USB 케이블 및 연결 확인
2. 기기 잠금 해제
3. "이 컴퓨터 신뢰" 팝업 확인
4. iTunes 설치 확인 (드라이버 포함)

**"권한 오류"**
- Windows: 관리자 권한으로 실행
- macOS/Linux: `sudo` 사용 또는 udev 규칙 설정
