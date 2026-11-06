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
  (GUI를 실제로 사용하기 시작할 때 src\gui.c도 추가)
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

12. Win32 GUI 구현 현황 (2026-11-06 확인)
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
- 현재 Start Capture 버튼은 '선택 항목 확인'까지만 구현됨.
  GUI에서 실제 패킷 캡처를 시작하는 기능은 아직 없음.
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

14. 바로 다음 할 일 (2026-11-06 기준)
- [완료] 별도 GUI 실행 파일을 빌드하고 창 표시.
- [완료] Npcap 어댑터 목록을 GUI 콤보박스에 표시.
- [완료] 선택 항목 인덱스를 읽고 선택한 설명 문자열을 메시지 박스로 출력.
- [다음] CB_ADDSTRING의 반환 인덱스와 CB_SETITEMDATA/CB_GETITEMDATA를 활용해
  콤보박스의 각 항목과 실제 장치 식별자(current->name)를 연결할 방법 설계.
  문자열은 별도로 복사해 수명을 관리하고 WM_DESTROY에서 필요한 자원 해제.
- [다음] Wi-Fi 등 사용자가 선택한 실제 장치 식별자를 open_capture()에 전달.
- [다음] GUI가 멈추지 않도록 패킷 수신 루프를 UI 메시지 루프와 분리(스레드/메시지 전달 등).
- [다음] Start/Stop Capture, 수신 결과 목록 및 패킷 상세 보기 추가.
- [장기] printf() 중심 parser 결과를 구조체 등 GUI 재사용 가능한 데이터로 분리.

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

16. 현재 달성 범위와 주의 사항
- 콘솔 버전: 실제 패킷 수신, 앞 16바이트 16진수 출력, Ethernet 형식 확인 후
  EtherType(IPv4/ARP/IPv6 등) 분석까지 이전 기록에서 검증함.
- GUI 버전: 창 + 장치 목록 + 선택된 장치 '설명' 표시까지 검증함.
  GUI에서 pcap_open_live() 호출 및 실시간 패킷 표시 기능은 미구현.
- 개발 방식: 사용자가 C 코드를 직접 작성하며, 한 단계씩 실제 동작과 오류를 확인.
  추측으로 설정을 변경하지 않고 종료 코드/디버그 로그/실행 화면을 증거로 진단.
