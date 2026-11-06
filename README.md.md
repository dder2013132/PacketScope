정리 :

1. pcap_if_t 변수 2개 선언,
장치 목록의 첫 노드,
목록을 순회할 때 쓸 노드.
그리고 errbuf를 pcap의 버퍼 사이즈만큼 선언하여 오류 메시지를 저장

2. 다음, 모든 장치를 찾았는지 아닌지를 판단(if(pcap_findalldevs))

3. 성공했다면, integer 타입의 count 변수를 하나 만듦.
그리고, 현재 노드에 첫 노드를 담음.(current = alldevs)
다음, 반복문을 통하여, current에 NULL이 담기는, 즉, 끝까지 갈 때까지, count++을 해가면서, 현재 장치의 순번과 이름을 printf를 통하여 출력.
그러나 이 중, description이 없는 경우가 있으므로,
description이 없는 경우에는, 없다고 출력하도록 if문을 걸어줌.
마지막으로, count 변수를 통하여 검색된 모든 장치의 갯수를 출력.

4. integer 타입의 num 변수를 선언.
scanf를 통하여 num에 사용자가 검색할 네트워크 어댑터의 번호를 받음.
번호는 위에서 찾아낸 목록 순번.
만약, 번호를 invalid하게 입력하였다면, 오류를 출력하고,
pcap_freealldevs를 통하여 장치 해제,
return 1로 종료.
번호 자체가 없는 번호라면, 해당 오류를 출력하고 위와 같은 조치.
제대로 입력 되었다면, 
current에 다시 첫 노드를 담고(위에서 끝까지 갔기 때문)
입력받은 num만큼 current=current->next를 통하여 반복.
역시 description이 없을 수 있으므로 if문을 통해 사전 작업.

5. 찾아낸 번호의 어댑터 정보를 출력해주어야하므로,
pcap_pkthdr 타입의 *header 구조체, u_char 타입의 *data 변수를 const로 선언(변경불가), 그리고 integer 타입의 result 변수 선언.
pcap_t 타입으로 *handle 구조체에 pcap_open_live 함수를 통해 불러온 정보를 삽입.
여기에는 current에 담긴 name과 65535(IP 패킷이 이론상 담을 수 있는 최대 크기), 0 (무차별 모드의 비활성화, 이를 통해 내 PC에 직접적으로 전송된 패킷만 캡처함), 1000 (Read Timeout 설정, 프로그램이 무한 대기-block-상태에 빠지는 것을 방지하고, 최소 1초마다 제어권을 얻어 다음 동작을 처리하게 하기 위함), errbuf를 인수로 담는다.


6. 다음, if문을 통해 handle에 값이 담겼을 때만 가정하고 
result에 pcap_next_ex 메소드를 통해 handle, &header, &data를 담는다.
그 다음, if문을 통해, result에 담긴 값을 검사한다.
1인 경우 : header->caplen과 header->len을 출력,
for문을 통해 패킷 정보를 출력.
for문은, unsigned int i; i<16 && i<header->caplen; i++을 통해 진행시키고, %02X 출력형식을 통해 (unsigned int)data[i]를 printf로 출력.
0인 경우 : 패킷을 받지 못했다는 오류 메시지 출력.
-1인 경우 : 캡쳐 오류, pcap_geterr(handle)을 통해 받은 오류 메시지를 %s 출력 형식으로 출력.
-2인 경우 : 캡쳐가 끝난 경우이므로 해당 메시지 출력.
이것이 다 끝나면, pcap_close(handle)로 pcap 종료.
- 그 외 : errbuf에 담긴 오류를 출력, pcap_freealldevs로 전부 해소하고, return 1로 프로그램 종료.

위의 모든 작업이 끝나고 아래로 내려가게 되면,
pcap_freealldevs(alldevs); 를 통해 모든 장치를 해소하고,
return 0으로 프로그램 종료.


============================================================
[추가 정리] PacketScope 개발 진행 기록 (2026-11-06 기준)
============================================================

7. 첫 실제 패킷 수신과 16진수 출력
- Wi-Fi 어댑터(Realtek 8852CE WiFi 6E PCI-E NIC)를 선택하여 실제 패킷 수신 성공.
- pcap_next_ex(handle, &header, &data)의 반환값 1이면 header와 data를 사용할 수 있음.
- header->caplen: 실제 캡처되어 이용 가능한 바이트 수.
- header->len: 원래 패킷 길이(캡처 인터페이스가 보고한 길이).
- 처음 16바이트만 출력할 때:
    for (unsigned int i = 0; i < 16 && i < header->caplen; i++) {
        printf("%02X ", (unsigned int)data[i]);
    }
    printf("\n");
- i < 16과 i < header->caplen을 함께 검사하는 것은 범위 밖 읽기를 피하기 위해서임.
- %02X: 최소 두 자리, 0 채움, 대문자 16진수 출력.

8. Ethernet II 헤더와 EtherType 분석
- 일반적인 Ethernet II 헤더는 최소 14바이트.
  data[0]~data[5]   : 목적지 MAC 주소(6바이트)
  data[6]~data[11]  : 출발지 MAC 주소(6바이트)
  data[12]~data[13] : EtherType(2바이트)
- 분석 전 필수 확인: pcap_datalink(handle) == DLT_EN10MB, header->caplen >= 14.
- DLT = Data Link Type, EN = Ethernet, 10MB = 과거 10Mb/s Ethernet에서 유래한 이름.  DLT_EN10MB = 1
- 본 프로그램에서는 Ethernet 패킷의 첫 14바이트를, 위와 같이 해석하고 있는데, 모든 네트워크 캡처가 해당 방식은 아님.
 - 예를 들어, 루프백이나 Wi-Fi 모니터 모드 캡처에서는 헤더의 구조가 달라질 수 있음. 따라서 무조건 data[12], data[13]을 읽으면 잘못 해석할 여지가 있음.
 - 따라서 두가지 조건을 검사해야함.
  - 첫 번째 조건 : 데이터 형식이 Ethernet?
  - 두 번째 조건 : 헤더를 읽을 만큼 충분한 바이트가 있는가?
  - 참고 : DLT_EN10MB는 Ethernet 링크 계층 형식을 뜻할 뿐, 모든 프레임이 Ethernet II라는 보장을 해주지는 않음. VLAN 태그나 길이 필드를 사용하는 프레임은 추가 해석이 필요.
- EtherType 계산:
    unsigned int etherType = ((unsigned int)data[12] << 8) | data[13];
  첫 바이트를 8비트 왼쪽 이동하고 두 번째 바이트와 비트 OR로 결합.
- 알려진 타입:
    0x0800 = IPv4
    0x0806 = ARP
    0x86DD = IPv6
    나머지 = Unknown (현재 분류표에 없다는 뜻이지 캡처 실패는 아님)
- 0x는 16진수 정수 리터럴을 나타냄. 예: 0x10 == 16은 참.
- 비교에는 따옴표를 사용하지 않음: etherType == 0x0806.
  '0x0806'는 숫자가 아니라 C의 다중 문자 상수여서 부적절함.
- 출력은 printf("EtherType: 0x%04X\n", etherType);
- 실제 캡처 예시:
    FF FF FF FF FF FF 68 CC AE C3 ED E7 08 06 00 01 -> ARP
    01 00 5E 7F FF FA 40 1A 58 D5 2C DE 08 00 45 00 -> IPv4
    FF FF FF FF FF FF 00 E5 F1 16 E5 EC 88 99 23 B4 -> 0x8899 / Unknown
- FF:FF:FF:FF:FF:FF 목적지 MAC은 브로드캐스트를 의미.
- 01:00:5E로 시작하는 목적지 MAC은 IPv4 멀티캐스트 범위에 해당할 수 있음.
- IPv4 EtherType만 보고 TCP/UDP 여부까지 단정할 수는 없음. 추가 헤더 분석이 필요.
- 향후 VLAN 태그 등 일반적인 Ethernet II 외의 프레임 변형도 별도로 다뤄야 함.

9. 프로젝트 모듈화(리팩터링)
- 목표: 기존 동작을 유지하면서 역할별 파일로 분리해 나중에 GUI를 쉽게 붙이기.
- 현재 구조(대화에서 확인한 파일명 기준):
    PacketScope/
      src/main.c                : 전체 실행 흐름, 콘솔 사용자 입력, 결과 처리, 자원 해제
      src/gui_main.c            : GUI 실행 진입점 (GUI 빌드용)
      src/capture.c             : 장치 탐색/출력/선택 및 캡처 API 호출
      src/parser.c              : 수신한 패킷 해석 및 출력
      src/gui.c                 : Win32 GUI 창, 콤보박스, 버튼 및 선택 항목 표시
      include/capture.h         : 캡처 관련 함수 선언
      include/packet_parser.h   : 패킷 분석 함수 선언
      include/gui.h             : GUI 시작 함수 선언
      build.cmd                 : MSVC 빌드 스크립트
- 헤더(.h)는 다른 소스에서 사용할 함수/타입을 선언하고, 소스(.c)는 실제 기능을 구현.
- 헤더 가드 예: #ifndef CAPTURE_H / #define CAPTURE_H / #endif.
- 각 .c 파일을 빌드 명령에 포함해야 링커가 함수 구현을 찾을 수 있음.
  예: src\main.c src\capture.c src\parser.c
  (GUI 빌드에는 src\gui.c가 포함되어 있음)
- /I"include"와 Npcap SDK의 Include 경로가 필요.
- 문법/선언 오류는 컴파일 단계, 함수 구현을 찾지 못하는 LNK2019는 링크 단계의 문제.
- 실제 겪은 오류: get_device_by_indx와 get_device_by_index의 철자 차이로 LNK2019 발생.
- Windows SDK에도 parser.h가 있어 같은 이름의 헤더가 잘못 검색되는 충돌이 발생함.
  프로젝트 헤더를 packet_parser.h로 변경하여 해결.
- 리팩터링 후 실제로 패킷 캡처 및 IPv4/ARP 판별이 다시 동작하는 것 확인.
- 안정적인 상태는 Git에 커밋함.

10. capture.c에 분리한 함수와 역할
- int find_devices(pcap_if_t **alldevs, char *errbuf);
    pcap_findalldevs(alldevs, errbuf)의 결과를 반환.
    main에서는 find_devices(&alldevs, errbuf)처럼 포인터 변수의 주소를 전달.
- int list_devices(pcap_if_t *alldevs);
    연결 리스트를 순회하며 장치 이름/설명을 출력하고 개수를 반환.
- pcap_if_t *get_device_by_index(pcap_if_t *alldevs, int index);
    1번부터 시작하는 장치 번호를 받아 해당 노드 포인터 반환.
    index가 1 미만이거나 탐색 도중 리스트 끝에 닿으면 NULL 반환.
    current = current->next를 index-1회 수행. 반복문 안에서 정상 반환을 조기에 하면 안 됨.
    main에서는 반환 후 NULL 확인하고 접근해야 함.
- pcap_t *open_capture(const char *device_name, char *errbuf);
    pcap_open_live(device_name, 65535, 0, 1000, errbuf)를 호출하고 핸들 반환.
- int receive_packet(pcap_t *handle, struct pcap_pkthdr **header, const u_char **data);
    pcap_next_ex(handle, header, data)의 반환값을 그대로 반환.
    main에서 receive_packet(handle, &header, &data)처럼 호출.
- 패킷 분석은 parser.c의 analyze_packet(handle, header, data) 담당.
- 자원 관리: 현재 main에서 pcap_close(handle)와 pcap_freealldevs(alldevs) 호출.
  실패 경로에서도 필요한 해제가 빠지지 않도록 주의.

11. 포인터와 const 학습
- pcap_if_t *current = alldevs; : 노드 포인터를 복사해 현재 위치를 이동할 수 있음.
- current->next : 현재 노드의 다음 노드를 가리키는 포인터.
- NULL : C에서 널 포인터 상수를 표현할 때 사용. 소문자 null은 기본 C 식별자가 아님.
- 이중 포인터는 호출자 쪽 포인터 변수의 값을 바꾸기 위해 사용.
  main: struct pcap_pkthdr *header = NULL;
        receive_packet(handle, &header, &data);
  capture.c: struct pcap_pkthdr **header 매개변수
             pcap_next_ex(handle, header, data);
  main의 &header는 pcap_pkthdr **, capture.c의 header도 이미 pcap_pkthdr **이므로
  capture.c에서 다시 &header를 넘기면 포인터 깊이가 하나 더 증가함.
- pcap_if_t ** 매개변수를 받는 find_devices()도 동일한 원리:
    main: find_devices(&alldevs, errbuf)
    capture: pcap_findalldevs(alldevs, errbuf)
    capture에서 &alldevs를 넘기면 ***가 되어 타입 경고(C4047/C4024) 발생.
- int number=50; int *ptr=&number; int **header=&ptr; 에서
    header : ptr 변수의 주소
    *header : number의 주소
    **header : number의 값
    **header=200을 실행하면 number도 200으로 바뀜.
- const u_char *data : 이 포인터를 통해 가리키는 데이터의 수정은 금지,
  포인터 변수 자체를 다른 주소로 바꾸는 것은 가능.
- u_char * const data : 포인터 변수 자체의 재지정 금지, 가리키는 데이터 변경은 가능.
- const u_char * const data : 두 제한 모두 적용.
- Npcap이 제공한 packet data는 후속 캡처 호출 또는 핸들 종료로 무효화될 수 있으므로
  필요할 때는 유효한 동안 분석하거나 별도 메모리에 복사해야 함.

12. Win32 GUI 구현 현황 (2026-11-06, 이후 기능 확장 내용은 17~19절 참고)
- 목표: 기존 콘솔 패킷 분석기를 유지하면서 별도의 Win32 GUI 제공.
- gui.h: int run_gui(void); 선언.
- gui_main.c: GUI 프로그램 진입점. gui.c의 run_gui()를 호출하는 빌드 구성.
- gui.c의 실제 구현:
  1) GetModuleHandleW(NULL)로 실행 모듈 핸들 획득.
  2) WNDCLASSW의 lpfnWndProc에 WindowProc 설정, RegisterClassW로 창 클래스 등록.
  3) CreateWindowExW로 PacketScope 메인 창(900x600) 생성.
  4) ShowWindow, UpdateWindow로 표시하고 GetMessageW/TranslateMessage/DispatchMessageW 루프 실행.
  5) WM_CREATE에서 Start Capture 버튼(ID 1001), 드롭다운 콤보박스(ID 1002) 생성.
  6) find_devices(&alldevs, errbuf)로 Npcap 장치 검색.
  7) pcap_if_t 연결 리스트를 순회해 description(없으면 name)을 CB_ADDSTRING으로 콤보박스에 추가.
  8) CB_SETCURSEL로 첫 번째 항목을 기본 선택하고 pcap_freealldevs(alldevs) 호출.
  9) WM_COMMAND에서 버튼 ID 1001 + BN_CLICKED를 확인해 선택 항목을 읽음.
 10) WM_DESTROY에서 PostQuitMessage(0)를 호출해 메시지 루프 종료.
- 2026-11-06 실제 검증: GUI 창 표시, 어댑터 목록 표시, 항목 선택 후
  'Selected Adapter' 메시지 박스에 선택한 설명 문자열이 정확하게 나타남.
  예: Microsoft Wi-Fi Direct Virtual Adapter #2.
- 당시 Start Capture 버튼은 선택 항목 확인까지만 구현되어 있었음.
  이후 GUI에서 장치 식별자 저장 및 캡처 핸들 열기까지 확인됨(17~19절 참고).
- 중요: 콤보박스의 표시 문자열(description)과 캡처 API에 전달할 장치 식별자(name)는 다름.
  pcap_freealldevs() 호출 뒤 pcap_if_t 노드나 그 내부 name 포인터를 계속 사용하면 안 됨.
- 사용 API 및 개념:
  * GetDlgItem(hwnd, 1002): 콤보박스 핸들 조회.
  * CB_GETCURSEL: 선택한 항목 인덱스 반환(선택 없으면 CB_ERR).
  * CB_GETLBTEXTLEN: 선택 문자열의 길이 조회.
  * CB_GETLBTEXT: 선택 문자열을 wchar_t 배열에 복사.
  * wchar_t adapterName[256]: 와이드 문자 배열. 종료 문자 공간을 위해 길이 < 256 검사.
  * MessageBoxW(hwnd, adapterName, L"Selected Adapter", ...): 선택 항목 표시.
  * SendMessageA(... CB_ADDSTRING ...)와 SendMessageW(... CB_GETLBTEXT ...) 사용 중.
    유니코드 컨트롤/문자 인코딩 처리는 추후 정리할 수 있으나 현재 표시 동작은 검증됨.
- 학습한 Win32 개념:
  * HINSTANCE: 프로그램 모듈 핸들, GetModuleHandleW(NULL)로 획득.
  * WNDCLASSW: 창 클래스 정의; lpfnWndProc는 메시지 처리 함수 포인터.
  * L"...": Windows W API에서 사용하는 와이드 문자열 리터럴.
  * WM_CREATE: 창 생성 중 발생하므로 ShowWindow() 이전에 처리될 수 있음.
  * WM_COMMAND/BN_CLICKED: 버튼 클릭 등 컨트롤 이벤트 처리.
  * 문자열 버퍼는 임시 저장 공간이며 C에는 Java의 String 기본 자료형이 없음.

13. 기존 기록의 정정 / 주의점
- [원본 4번] 노드 이동 횟수는 입력 num번이 아니라 num-1번(1부터 시작하는 번호 기준).
- [원본 5번] pcap_pkthdr와 data는 장치 정보가 아니라 캡처된 패킷 메타데이터 및 바이트.
- [원본 5번] 65535는 캡처 버퍼로 확보할 최대 패킷 데이터 길이(snaplen) 설정.
  'IP 패킷의 최대 크기'라는 설명으로만 이해하면 부정확함.
- [원본 5번] promisc=0은 무차별 모드 비활성화 요청이며 내 PC에 직접 온 패킷만
  캡처한다고 단정할 수 없음(브로드캐스트/멀티캐스트 등 포함 가능).
- [원본 5번] timeout=1000(ms)은 읽기 타임아웃 설정이지만 모든 환경에서 반드시
  1초마다 제어권이 돌아온다고 보장하는 것은 아님.
- [원본 6번] pcap_next_ex()의 결과 0은 읽기 타임아웃으로, 반드시 오류는 아님.
- [원본 6번] pcap_open_live() 실패 처리와 pcap_next_ex() 결과 처리의 else를 구분.
- [추가 주의] 패킷 수신에 실패(-1)했는데도 마지막에 return 0을 실행하는 구조는
  종료 코드상 성공으로 보일 수 있으므로 추후 오류 반환 정책을 개선할 수 있음.

14. 바로 다음 할 일 (2026-11-06 최신 진행 기준)
- [완료] 별도 GUI 실행 파일 빌드 및 창 표시.
- [완료] Npcap 어댑터 목록 콤보박스 표시 및 선택 설명 문자열 출력.
- [완료] CB_SETITEMDATA/CB_GETITEMDATA로 실제 장치 식별자 포인터 연결.
- [완료] malloc/memcpy로 장치 이름 복사, free_adapter_data() 정리 함수 구현.
- [완료/실행 검증] 선택한 장치의 open_capture() 성공, pcap_close() 호출.
- [코드 작성, 미검증] capture_thread()에서 receive_packet() 1회 호출, result == 1이면 caplen 출력.
- [우선] GUI 스레드의 WaitForSingleObject(INFINITE) 제거를 포함한 비동기 완료/정리 방식 설계.
- [우선] 스레드/pcap_t* 핸들 소유권, 종료 확인, 실패 경로, 중복 시작 방지 정리.
- [우선] WM_CREATE 실패/부분 초기화 시 자원 해제 경로와 free_adapter_data() 이중 호출 가능성 재검토.
- [다음] 워커 스레드가 PostMessageW 등으로 수신 결과를 UI에 전달하고 GUI에서 확인.
- [다음] Start/Stop Capture, 반복 수신, 패킷 목록 및 상세 보기 추가.
- [장기] printf() 중심 parser 결과를 GUI에서 재사용 가능한 구조체로 분리.

15. 2026-11-06 실행 및 DLL 오류 진단 기록
- 개발 환경: Windows 11, MSVC C17, Npcap SDK 1.17, VS Code C/C++ 디버거.
- VS Code는 콘솔/GUI 각각 별도 빌드·디버깅 구성:
  * Console: PacketScope.exe
  * GUI: PacketScopeGUI.exe
  * GUI 빌드: build.cmd gui -> gui_main.c, gui.c, capture.c 기반.
- 현상: GUI 실행 전 창이 보이지 않고 중단점에도 도달하지 않는 것으로 보였음.
- 실행 파일을 PowerShell에서 직접 실행하자 즉시 종료.
- $LASTEXITCODE 결과 -1073741515 = 0xC0000135 (STATUS_DLL_NOT_FOUND).
- 현재 터미널에 다음 PATH를 임시 추가하자 GUI가 정상 실행됨:
    $env:PATH = "C:\Windows\System32\Npcap;$env:PATH"
    .\PacketScopeGUI.exe
- 원인: 직접 실행 시 Npcap 관련 DLL을 찾기 위한 검색 경로가 부족했음.
  구체적으로 어떤 DLL에서 실패했는지는 직접 확인하지 않았으므로 단정하지 않음.
- 이후 'Run PacketScope GUI' 디버깅 로그에서 다음 사항 확인:
  * PacketScopeGUI.exe 로드, Symbols loaded.
  * C:\Windows\System32\Npcap\wpcap.dll 및 Packet.dll 로드.
  * GUI 창을 사용자가 닫은 후 종료 코드 0 (0x0).
- 주의: 다른 시점의 디버깅 로그는 PacketScope.exe(콘솔 타깃)였음.
  디버그 콘솔 맨 앞에 표시된 실행 파일 이름으로 현재 타깃을 확인할 수 있음.
- launch.json에는 Npcap PATH 경로가 설정되어 있었음. 성공 사례가 있으므로
  작동하는 빌드/실행 설정을 근거 없이 반복 수정하지 말 것.
- 중단점/단계 실행의 정확한 동작은 별도 검증 완료로 기록하지 않음.
- 디버그 콘솔에 SKYSEA Client View 관련 DLL 로드 로그도 확인했으나,
  이것이 문제 원인이라는 증거는 없음. 관련 소프트웨어를 수정하지 않음.

16. 현재 달성 범위와 주의 사항 (최신)
- 콘솔 버전: 실제 패킷 수신, 앞 16바이트 16진수 출력, Ethernet 형식 확인 후
  EtherType(IPv4/ARP/IPv6 등) 분석까지 이전 기록에서 검증함.
- GUI 버전: 창/장치 목록/선택 설명 표시가 검증되었고, 선택한 Npcap 장치로
  open_capture() 후 성공 메시지 확인 및 pcap_close()까지 실제 실행으로 확인함.
- 스레드: CreateThread(), WaitForSingleObject()를 사용하는 시험 코드가 작성됨.
  capture_thread()의 실제 receive_packet() 코드와 printf 출력은 최근 작성되었으나
  이 버전의 실행/패킷 수신 성공은 아직 확인하지 않음.
- GUI 실시간 패킷 목록 표시, 비차단 이벤트 전달, 안전한 종료/Stop 기능은 미구현.
- 코드 스니펫과 실행 검증은 구별해 기록. 원본 최신 전체 소스는 별도 업로드되지 않았으므로
  마지막 대화에 공유된 부분을 기준으로 진행 상황을 기록함.
- 개발 방식: 사용자가 직접 코드를 작성하고, 한 단계씩 실제 동작/로그를 확인하며 진행.

17. GUI 콤보박스와 Npcap 장치 식별자 연결 (2026-11-06 추가)
- WM_CREATE에서 pcap_if_t 목록을 순회하여 description(없으면 name)을 표시 문자열로 추가.
- CB_ADDSTRING 반환 인덱스를 LRESULT index로 받으며 CB_ERR / CB_ERRSPACE 검사.
- 각 current->name은 Npcap의 장치 식별자(예: \Device\NPF_{...})로,
  pcap_freealldevs(alldevs) 이후에는 원본 메모리를 참조할 수 없음.
- size_t len = strlen(current->name); char *deviceName = malloc(len + 1);
  malloc 반환 NULL 검사 후 memcpy(deviceName, current->name, len + 1)로 널 종료까지 복사.
- CB_SETITEMDATA(combo, index, (LPARAM)deviceName)로 복사된 포인터를 해당 항목에 보관.
  실패 시 free(deviceName)와 CB_DELETESTRING(index) 처리 코드를 추가함.
- malloc 실패 시에도 방금 추가한 콤보박스 항목을 CB_DELETESTRING으로 제거.
- 세 실패 지점(CB_ADDSTRING, malloc, CB_SETITEMDATA)에서 initializationFailed = 1;
  설정한 후 while 종료. 실패 시 pcap_freealldevs(alldevs)와 WM_CREATE return -1 적용.
- WM_COMMAND에서 CB_GETCURSEL로 인덱스를 얻고 CB_GETITEMDATA로 저장된 포인터를 읽음.
  CB_ERR 및 0 검사 후 char *deviceName = (char *)itemData 사용.
- GUI 표시용 wchar_t adapterName[256]은 CB_GETLBTEXTLEN / CB_GETLBTEXT로 별도 조회.
  표시 문자열(adapterName)과 캡처용 식별자(deviceName)는 서로 다른 데이터임.
- free_adapter_data(HWND combo)를 별도 함수로 작성: CB_GETCOUNT 후 각 항목을
  CB_GETITEMDATA로 읽고 malloc 포인터 free, CB_SETITEMDATA(..., 0)으로 초기화하도록 설계.
  WM_DESTROY에서 호출하고, WM_CREATE 실패 시에도 호출하는 코드 작성.
- 수정 이력: free_adapter_data에서 free(deviceName)을 두 번 호출한 실수를 발견함.
  중복 호출을 제거하도록 수정 안내했고 사용자가 이후 진행함. 최종 소스 재점검 필요.

18. GUI에서 Npcap 캡처 핸들 열기 및 스레드 기초 (2026-11-06 추가)
- WM_COMMAND의 Start Capture 클릭 시 저장한 deviceName으로
  char errbuf[PCAP_ERRBUF_SIZE] = {0}; pcap_t *handle = open_capture(deviceName, errbuf);
  호출하고 NULL이면 오류 메시지 표시 후 반환하도록 구현.
- 정상 경로에서는 pcap_close(handle)로 닫는 방식으로 시작했으며,
  사용자 실행 테스트에서 캡처 핸들 열기 성공 메시지 및 GUI 정상 동작 확인.
- 스레드 도입을 위해 DWORD WINAPI capture_thread(LPVOID param) 선언/정의.
  작업 함수에서 pcap_t *handle = (pcap_t *)param; 으로 전달받은 핸들 복원.
- WM_COMMAND에서 HANDLE thread = CreateThread(NULL, 0, capture_thread, handle, 0, NULL);
  작성 후 thread == NULL 오류 검사를 추가함.
- 스레드 생성 실패 시 이미 열린 pcap_t*를 pcap_close(handle)로 닫아야 함.
  실패 경로에 해당 호출을 추가하라는 리뷰가 있었으므로 최종 코드에서 확인 필요.
- DWORD waitResult = WaitForSingleObject(thread, INFINITE); 와
  WAIT_FAILED / WAIT_OBJECT_0 분기 코드를 작성.
  WAIT_OBJECT_0 이후 CloseHandle(thread), pcap_close(handle) 정리 순서를 학습함.
- 실수 수정: 실패 시 NULL 캡처 핸들을 닫거나, 성공 경로에서 pcap_close(handle)를
  중복 호출했던 코드를 바로잡음.
- 중요한 제한: WAIT_OBJECT_0은 스레드 종료를 뜻하며 실제 작업 성공을 뜻하지 않음.
  WAIT_FAILED는 스레드가 아직 실행 중일 가능성을 배제하지 못함.
  이런 상태에서 pcap_close(handle)를 즉시 수행하면 위험하며, 단순 return은 누수를 남길 수 있음.
- GUI 이벤트 처리 안의 WaitForSingleObject(thread, INFINITE)는 작업이 오래 걸리면
  UI 메시지 루프를 막으므로 실제 실시간 캡처에는 부적합. 구조 변경 전까지 실행 주의.
- CloseHandle(thread)는 스레드를 강제 종료하지 않고 Windows 핸들 참조만 닫음.

19. capture_thread()의 패킷 하나 수신 코드 (2026-11-06 마지막 작성 단계)
- 마지막으로 사용자가 작성한 함수의 핵심 코드:
    DWORD WINAPI capture_thread(LPVOID param)
    {
        pcap_t *handle = (pcap_t *)param;
        struct pcap_pkthdr *header = NULL;
        const u_char *data = NULL;
        int result = receive_packet(handle, &header, &data);
        if (result == 1) {
            printf("%u", header->caplen);
        }
        return 0;
    }
- receive_packet()는 pcap_next_ex() 결과를 그대로 반환하는 기존 capture.c 함수.
- 반환값: 1 패킷 수신 성공 / 0 읽기 타임아웃 / -1 오류 / -2 종료 또는 EOF.
- result == 1일 때만 header->caplen을 읽어 printf("%u", ...)로 출력하는 코드 작성.
- printf를 사용하려면 <stdio.h>가 필요. GUI 서브시스템 빌드에서는
  printf가 표시될 콘솔이 없을 수 있어 결과를 확인하기 어려움.
- 이 최종 capture_thread() 버전의 실제 실행 여부와 패킷 수신 성공 여부는 미확인.
- 아직 결과를 GUI에 전달하는 PostMessageW 처리, HWND 전달, 재시작/중지 로직은 미작성.
- 다음 세션에서는 즉시 코드 실행을 지시하기보다 먼저 스레드/캡처 핸들 수명과
  GUI 비차단 종료 정책을 설계하고 검증한 다음 실제 수신 결과를 UI로 전달할 것.
