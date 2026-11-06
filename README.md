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
      src/capture.c             : 장치 탐색/출력/선택 및 캡처 API 호출
      src/parser.c              : 수신한 패킷 해석 및 출력
      src/gui.c                 : Win32 GUI 준비 단계
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

12. Win32 GUI 시작(현재 최신 진행 상태)
- 목표: 콘솔 기능을 유지하면서 별도 GUI 모듈을 만들어 PacketScope 창을 띄우기.
- gui.h에 int run_gui(void); 선언을 작성.
- gui.c 현재 작성 코드:
    #include <windows.h>
    #include "gui.h"

    int run_gui(void) {
        HINSTANCE hInstance = GetModuleHandleW(NULL);
        WNDCLASSW wc = {0};
        wc.hInstance = hInstance;
        wc.lpszClassName = L"PacketScopeWindow";
        return 0;
    }
- HINSTANCE: 현재 실행 파일 모듈의 핸들 타입.
- GetModuleHandleW(NULL): 현재 프로세스의 실행 파일 모듈 핸들 취득.
- WNDCLASSW: Win32 창 클래스에 관한 정보를 담는 구조체.
- {0}: 구조체의 멤버를 0으로 초기화.
- wc.hInstance: 창 클래스가 속한 모듈 핸들.
- wc.lpszClassName: 창 클래스 이름을 지정하는 널 종료 와이드 문자열 포인터.
- lpsz라는 명명 관례: lp = Long Pointer(역사적인 Windows 표기),
  sz = zero-terminated string(널 종료 문자열).
- L"PacketScopeWindow": 와이드 문자열 리터럴. Windows API의 W 버전에서 사용.
- 창 클래스 이름과 실제 창 제목은 다름.
- 다음 단계(아직 미구현): WndProc 메시지 처리 함수, wc.lpfnWndProc 설정,
  RegisterClassW, CreateWindowExW, ShowWindow, GetMessage/DispatchMessage 메시지 루프.
- 현재 GUI 함수는 창을 실제로 생성하지 않으며 main에서도 GUI 실행으로 전환하지 않았음.
  GUI가 동작한다고 기록하지 말 것.

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

14. 바로 다음 할 일
- gui.c에 WndProc(창 메시지 처리 함수) 추가.
- WNDCLASSW의 lpfnWndProc 설정 뒤 창 클래스 등록 및 실제 창 생성 기능 순차 구현.
- 기존 CLI 캡처 프로그램은 그대로 유지하고 GUI 기능을 작게 나눠 검증.
- 새 GUI 소스를 빌드에 포함할 때 기존 include 경로/연결 라이브러리 설정 점검.
- 장기적으로 printf() 중심 parser 결과를 구조체 등 GUI에서 재사용 가능한 데이터로 분리.
