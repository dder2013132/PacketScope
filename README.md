# PacketScope

**PacketScope**는 Windows에서 네트워크 어댑터를 선택하고 패킷을 캡처·분석하는 **C 기반 학습용 네트워크 패킷 분석기**입니다. Npcap을 통해 실제 패킷을 수신하며, 콘솔 프로그램에서 시작해 Win32 GUI로 기능을 확장하고 있습니다.

> **개발 상태 (2026-11-09): Work in Progress**  
> 콘솔 측 패킷 수신·EtherType 분석은 이전 개발 과정에서 실제 동작을 확인했습니다. GUI는 캡처 워커 스레드와 종료 알림 구조를 구현 중이지만, **최신 소스의 빌드·실행 및 모든 종료/예외 경로는 아직 검증되지 않았습니다.** 안정적인 패킷 모니터링 도구로 사용하기 전 추가 수정이 필요합니다.

## 주요 기능 및 구현 상태

| 기능 | 상태 | 비고 |
| --- | --- | --- |
| Npcap 네트워크 어댑터 검색 | ✅ 구현 및 이전 실행 확인 | `pcap_findalldevs()` |
| 콘솔에서 어댑터 번호 선택 | ✅ 구현 및 이전 실행 확인 | 연결 리스트 순회 및 인덱스 검증 |
| 패킷 1개 수신 | ✅ 콘솔 구현 및 이전 실행 확인 | `pcap_next_ex()` |
| 패킷 크기 및 처음 16바이트 출력 | ✅ 콘솔 구현 및 이전 실행 확인 | `caplen`, `len`, 16진수 출력 |
| Ethernet EtherType 식별 | ✅ 콘솔 구현 및 이전 실행 확인 | IPv4 / ARP / IPv6 / Unknown |
| Win32 창과 어댑터 콤보박스 | ✅ 구현 및 이전 실행 확인 | 표시 문자열과 장치 식별자 분리 보관 |
| GUI Start/Stop 버튼 | 🟡 코드 작성 | 최신 동작 검증 필요 |
| GUI 반복 패킷 수신 워커 스레드 | 🟡 코드 작성 | 결과는 현재 `printf()` 중심 |
| 스레드 종료 알림(`WM_CAPTURE_FINISHED`) | 🟡 코드 작성 | `RegisterWaitForSingleObject()` 기반, 오류 경로 보완 필요 |
| GUI 패킷 목록/상세 화면 | ⬜ 미구현 | 현재 콘솔 출력과 분리되지 않음 |
| TCP/UDP 포트, IP 주소 상세 해석 | ⬜ 미구현 | 현재는 주로 EtherType 식별 |
| 파일 저장·필터링·통계 | ⬜ 미구현 | 향후 계획 |

✅ 완료/과거 실행 확인 · 🟡 구현 중/최신 검증 필요 · ⬜ 미구현

## 기술 스택

- **언어:** C (`/std:c17`)
- **운영체제:** Windows 11
- **컴파일러:** Microsoft Visual C++ (`cl`, Visual Studio Build Tools 2026)
- **개발 환경:** VS Code, Developer Command Prompt / `VsDevCmd.bat`
- **패킷 캡처:** Npcap, Npcap SDK 1.17 (`wpcap.lib`, `pcap.h`)
- **GUI:** Win32 API (`user32.lib`)
- **동시성:** Windows 스레드·메시지 큐 및 C 원자 변수(`atomic_bool`)

## 프로젝트 구조

```text
PacketScope/
├── build.cmd
├── README.md
├── include/
│   ├── capture.h
│   ├── gui.h
│   └── packet_parser.h
└── src/
    ├── main.c          # 콘솔 실행 진입점 및 캡처 흐름
    ├── gui_main.c      # GUI 실행 진입점
    ├── capture.c       # 장치 탐색, 열기 및 패킷 수신 공통 함수
    ├── parser.c        # 패킷 요약 및 EtherType 분석
    └── gui.c           # Win32 UI, 캡처 스레드와 종료 관리
```

현재 빌드 스크립트는 **콘솔과 GUI를 별도 실행 파일**로 만듭니다. `parser.c`는 콘솔 빌드에만 포함되어 있으므로 **GUI에서는 현재 `analyze_packet()`을 사용하지 않습니다.**

## 사전 준비

1. Windows에 **Npcap 런타임** 설치
2. **Npcap SDK 1.17** 준비
3. **Visual Studio Build Tools**의 MSVC C/C++ 빌드 환경 설치
4. 프로젝트의 `src/`, `include/`, `build.cmd` 파일 배치

현재 `build.cmd`는 개발 PC의 아래 위치를 하드코딩하고 있습니다. 다른 PC에서는 실제 설치 경로로 수정해야 합니다.

```text
C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\Common7\Tools\VsDevCmd.bat
C:\Dev\npcap-sdk-1.17\Include
C:\Dev\npcap-sdk-1.17\Lib\x64
```

## 빌드

프로젝트 루트의 명령 프롬프트에서 실행합니다.

**콘솔 빌드**

```bat
build.cmd console
```

출력 대상: `PacketScope.exe`

**GUI 빌드**

```bat
build.cmd gui
```

출력 대상: `PacketScopeGUI.exe`

빌드 스크립트는 `cl /W4 /utf-8 /std:c17 /Zi`를 사용하며, **GUI 빌드에만 `/experimental:c11atomics` 옵션을 추가**합니다. 컴파일 결과 파일은 프로젝트 루트에 생성되도록 설정되어 있습니다.

> **알려진 빌드 점검 항목:** 현재 제공된 `gui.c`는 `printf()`를 사용하면서 `<stdio.h>`를 포함하지 않습니다. GUI 최신 소스의 컴파일 성공 여부는 아직 확인되지 않았으며, 빌드 전 해당 헤더를 추가해야 합니다. 이 README는 소스 수정 없이 작성되었습니다.

## 실행

```powershell
# 콘솔
.\PacketScope.exe

# GUI (개발 중)
.\PacketScopeGUI.exe
```

### Npcap DLL 경로

이전 개발 과정에서 실행 파일이 즉시 종료되는 `0xC0000135` (`STATUS_DLL_NOT_FOUND`) 오류가 있었고, PowerShell에서 다음 경로를 PATH에 추가한 뒤 GUI 실행에 성공했습니다.

```powershell
$env:PATH = "C:\Windows\System32\Npcap;$env:PATH"
.\PacketScopeGUI.exe
```

이는 당시 환경의 해결 기록입니다. Npcap 설치 방식이나 실행 환경에 따라 DLL 검색 경로가 다를 수 있습니다.

## 사용 흐름

### 콘솔 (`PacketScope.exe`)

1. Npcap 어댑터 목록 출력
2. 캡처할 어댑터의 **1부터 시작하는 번호** 입력
3. `pcap_open_live()`로 해당 장치 열기
4. `pcap_next_ex()`로 **패킷 1개** 수신
5. 수신에 성공한 경우 크기, 처음 16바이트, EtherType 출력
6. `pcap_close()` 및 `pcap_freealldevs()`로 자원 정리

현재 콘솔 프로그램은 **지속 수신 루프가 아니라 단일 수신 시도**를 수행합니다.

### GUI (`PacketScopeGUI.exe`, 개발 중)

1. Win32 창 생성 및 어댑터 콤보박스 채우기
2. 선택된 항목에 연결된 실제 Npcap 장치 식별자로 캡처 핸들 열기
3. Start 버튼 → `CaptureContext` 초기화 및 `CreateThread()` 실행
4. 캡처 스레드 → `running`이 참인 동안 `pcap_next_ex()` 반복 호출
5. Stop 버튼 또는 창 닫기 → `atomic_store(..., false)` 및 `pcap_breakloop()` 요청
6. 스레드 종료 감시 → 콜백이 `WM_CAPTURE_FINISHED` 메시지 게시
7. GUI 메시지 처리 → 스레드 종료 확인, 감시 등록 해제, 캡처 자원 정리

**이 순서는 현재 목표로 한 정상 경로를 설명하며, 모든 오류 경로가 안전하게 완성되었다는 뜻은 아닙니다.** 현재 GUI는 패킷 목록을 창에 표시하지 않고, 수신 스레드에서 `printf()`로 패킷 길이/상태를 출력하도록 작성되어 있습니다.

## 소스별 역할

| 파일 | 주요 기능 |
| --- | --- |
| `capture.c` / `capture.h` | `find_devices()`, `list_devices()`, `get_device_by_index()`, `open_capture()`, `receive_packet()` 및 `CaptureContext` |
| `parser.c` / `packet_parser.h` | `analyze_packet()`; 패킷 길이, 16진수 앞 16바이트, EtherType 식별 |
| `main.c` | 콘솔에서 장치 선택, 1회 수신 및 종료 처리 |
| `gui_main.c` / `gui.h` | `run_gui()` 호출 및 GUI 공개 함수 선언 |
| `gui.c` | Win32 메시지 루프, 콤보박스·버튼, 스레드 생성·중단·종료 통지 |

### Npcap 캡처 설정

`capture.c`에서는 아래 설정을 사용합니다.

```c
pcap_open_live(device_name, 65535, 0, 1000, errbuf);
```

- `65535`: 패킷당 캡처할 최대 바이트 수(`snaplen`)
- `0`: 무차별 모드 사용 안 함을 요청
- `1000`: 읽기 버퍼 관련 타임아웃 설정(밀리초)
- `errbuf`: 오류/경고 메시지 버퍼

**주의:** 1000ms 설정이 `pcap_next_ex()`의 반환을 매번 정확히 1초 안에 보장하지는 않습니다. 무차별 모드가 꺼져 있어도 브로드캐스트나 멀티캐스트 등은 수신할 수 있습니다.

### 현재 패킷 분석 범위

`analyze_packet()`은 `pcap_datalink(handle) == DLT_EN10MB`이고 캡처 길이가 14바이트 이상일 때, 프레임의 12~13번째 바이트를 EtherType으로 해석합니다.

| 값 | 표시 |
| --- | --- |
| `0x0800` | IPv4 |
| `0x0806` | ARP |
| `0x86DD` | IPv6 |
| 그 외 | Unknown |

Ethernet II가 아닌 프레임, VLAN 태그, 루프백 등은 별도 해석이 필요합니다. IPv4로 분류되었다고 해서 TCP 또는 UDP까지 분석한 것은 아닙니다.

## GUI 종료 처리 설계 (진행 중)

현재 `GuiState`는 캡처 컨텍스트, 스레드 핸들, 감시 등록 핸들 및 창 종료 요청 상태를 관리합니다.

```c
typedef struct
{
    CaptureContext *capture;
    HANDLE thread;
    HANDLE waitHandle;
    bool closing;
} GuiState;
```

`CaptureContext`는 Npcap 핸들과 원자적 실행 플래그를 가집니다.

```c
typedef struct
{
    pcap_t *handle;
    atomic_bool running;
} CaptureContext;
```

- **캡처 워커:** `atomic_load(&ctx->running)`으로 루프 지속 여부 확인
- **중지 요청:** `atomic_store(..., false)`와 `pcap_breakloop()` 호출
- **종료 감시:** `RegisterWaitForSingleObject(..., WT_EXECUTEONLYONCE)`
- **GUI 통지:** 콜백에서 `PostMessageW(hwnd, WM_CAPTURE_FINISHED, 0, 0)`
- **정상 종료 처리:** GUI에서 `WaitForSingleObject(thread, 0)` 확인 → `UnregisterWaitEx()` → `cleanup_capture()`
- **등록 실패 시:** 비상용 `WM_TIMER` 폴링 경로가 있으나 **이중 실패 복구가 미완성**

### 현재 확인된 위험·미완성 항목

1. **종료 감시 등록과 타이머가 모두 실패한 경우:** 스레드 종료 확인·자원 회수 경로가 완성되지 않았습니다.
2. **비상 타이머 실패 경로의 UI 동작:** 오류 대화상자만 표시하며 안전한 복구가 구현되지 않았습니다.
3. **감시 등록 해제 실패:** 메시지 처리에서 오류 후 반환하므로 완전한 회복·재시도 정책이 없습니다.
4. **창 파괴/콜백 수명:** `HWND`를 사용하는 콜백이 살아 있을 때 창이 파괴되지 않도록 모든 경로의 수명 보장이 필요합니다.
5. **스레드 정리 실패 시 자원 소유권:** `WM_DESTROY`는 현재 `GuiState`를 해제하므로 스레드가 남아 있는 오류 경로를 별도로 점검해야 합니다.
6. **`WM_CREATE` 초기화 실패:** `find_devices()` 실패 후 `return 0`을 사용하고 있어 실패 반환(`-1`) 및 초기화 중 자원 정리를 검토해야 합니다.
7. **GUI 출력:** 캡처 스레드에서 `printf()`를 사용하지만 GUI에 표시할 패킷 데이터 전달 방식은 미구현입니다.
8. **컴파일·실행 재검증:** 최신 `gui.c`의 `<stdio.h>` 누락, 오류 경로 및 반복 Start/Stop 동작을 점검해야 합니다.

> 패킷 수신 스레드의 종료가 확인되기 전에 `pcap_close()`, `CloseHandle()` 또는 `free(ctx)`를 수행하지 않도록 주의합니다. `CloseHandle()` 자체가 스레드를 종료시키지는 않습니다.

## 개발 로드맵

- [x] Npcap 개발 환경 구축 및 어댑터 열거
- [x] 콘솔 패킷 수신·16진수 출력
- [x] Ethernet EtherType 기반 기본 프로토콜 구분
- [x] 공통 캡처/파서 모듈 분리
- [x] Win32 GUI 창·어댑터 목록 구현
- [x] GUI 캡처 스레드 및 종료 통지 코드 작성
- [ ] GUI 최신 소스 컴파일 및 기본 실행 확인
- [ ] 종료 감시 해제와 비상 타이머 이중 실패 복구 완성
- [ ] Start → Stop → 재시작 → 창 닫기 시나리오 반복 테스트
- [ ] 워커에서 GUI로 패킷 정보를 안전하게 전달
- [ ] 패킷 목록과 선택 패킷 상세 보기
- [ ] IPv4/IPv6, TCP/UDP, ARP 상세 파싱
- [ ] 캡처 필터(BPF), 통계 및 패킷 저장 기능

## 개발 원칙

- **기능 단위로 구현하고 실제 동작을 검증**합니다.
- **소유권과 수명**을 명확히 구분합니다. (`pcap_t*`, `CaptureContext*`, `HANDLE`, 콤보박스의 복사된 장치 이름)
- **GUI 스레드를 장시간 블로킹하지 않는 구조**를 지향합니다.
- **실제로 검증한 기능과 작성만 한 코드를 구분**해서 기록합니다.
- 콘솔과 GUI를 별도 타깃으로 유지하면서 캡처·파서 로직의 재사용성을 높입니다.

---

**최종 문서 갱신:** 2026-11-09  
**상태:** 학습·개발용 프로토타입 (WIP)
