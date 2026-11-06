#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include "gui.h"
#include "capture.h"

LRESULT CALLBACK WindowProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam);

void free_adapter_data(HWND combo);

DWORD WINAPI capture_thread(LPVOID param);

int run_gui(void)
{
    HINSTANCE hInstance = GetModuleHandleW(NULL);

    WNDCLASSW wc = {0};
    wc.hInstance = hInstance;
    wc.lpszClassName = L"PacketScopeWindow";
    wc.lpfnWndProc = WindowProc;

    if (RegisterClassW(&wc) == 0)
    {
        MessageBoxW(
            NULL,
            L"Window class registration failed!",
            L"PacketScope Error",
            MB_OK | MB_ICONERROR);

        return 1;
    }

    HWND hwnd = CreateWindowExW(
        0,                    // 추가 창 스타일
        L"PacketScopeWindow", // 등록된 창 클래스 이름
        L"PacketScope",       // 창 제목
        WS_OVERLAPPEDWINDOW,  // 창 스타일
        CW_USEDEFAULT,        // 창 X 위치
        CW_USEDEFAULT,        // 창 Y 위치
        900,                  // 창 너비
        600,                  // 창 높이
        NULL,                 // 부모 창 핸들
        NULL,                 // 부모 메뉴 핸들
        hInstance,            // 프로그램 모듈 핸들
        NULL);                // 추가 생성 데이터 여부

    if (hwnd == NULL)
    {
        MessageBoxW(
            NULL,
            L"Window creation failed!",
            L"PacketScope Error",
            MB_OK | MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg = {0};
    BOOL status;

    while ((status = GetMessageW(&msg, NULL, 0, 0)) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (status == -1)
    {
        return 1;
    }

    return (int)msg.wParam;
}

LRESULT CALLBACK WindowProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_DESTROY:
    {
        HWND combo = GetDlgItem(hwnd, 1002);

        if (combo != NULL)
        {
            free_adapter_data(combo);
        }

        PostQuitMessage(0);
        return 0;
    }
    case WM_CREATE:
    {
        CreateWindowExW(
            0,
            L"BUTTON",
            L"Start Capture",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            20, 20,
            140, 35,
            hwnd,
            (HMENU)1001,
            GetModuleHandleW(NULL),
            NULL);
        HWND combo = CreateWindowExW(
            0,
            L"COMBOBOX",
            NULL,
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
            180, 20,
            300, 200,
            hwnd,
            (HMENU)1002,
            GetModuleHandleW(NULL),
            NULL);
        pcap_if_t *alldevs = NULL;
        char errbuf[PCAP_ERRBUF_SIZE] = {0};

        if (find_devices(&alldevs, errbuf) != 0)
        {
            MessageBoxW(
                hwnd,
                L"Failed to find network adapters.",
                L"PacketScope Error",
                MB_OK | MB_ICONERROR);
            return 0;
        }
        pcap_if_t *current = alldevs;
        int initializationFailed = 0;
        while (current != NULL)
        {
            const char *name =
                current->description != NULL
                    ? current->description
                    : current->name;

            LRESULT index = SendMessageA(
                combo,
                CB_ADDSTRING,
                0,
                (LPARAM)name);

            if (index == CB_ERR || index == CB_ERRSPACE)
            {
                MessageBoxW(
                    hwnd,
                    L"Failed to add adapter.",
                    L"PacketScope Error",
                    MB_OK | MB_ICONERROR);

                initializationFailed = 1;
                break;
            }

            size_t len = strlen(current->name);
            char *deviceName = malloc(len + 1);

            if (deviceName == NULL)
            {
                MessageBoxW(
                    hwnd,
                    L"Memory allocation failed.",
                    L"PacketScope Error",
                    MB_OK | MB_ICONERROR);

                SendMessageW(
                    combo,
                    CB_DELETESTRING,
                    (WPARAM)index,
                    0);
                initializationFailed = 1;
                break;
            }

            memcpy(deviceName, current->name, len + 1);

            LRESULT result = SendMessageW(
                combo,
                CB_SETITEMDATA,
                (WPARAM)index,
                (LPARAM)deviceName);

            if (result == CB_ERR)
            {
                MessageBoxW(
                    hwnd,
                    L"Failed to set adapter data.",
                    L"PacketScope Error",
                    MB_OK | MB_ICONERROR);
                free(deviceName);
                SendMessageW(
                    combo,
                    CB_DELETESTRING,
                    (WPARAM)index,
                    0);
                initializationFailed = 1;
                break;
            }

            current = current->next;
        }

        if (initializationFailed)
        {
            free_adapter_data(combo);
            // Npcap 장치 목록 해제
            pcap_freealldevs(alldevs);

            // 창 생성 실패 반환
            return -1;
        }
        SendMessageW(combo, CB_SETCURSEL, 0, 0);
        pcap_freealldevs(alldevs);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == 1001 &&
            HIWORD(wParam) == BN_CLICKED)
        {
            HWND combo = GetDlgItem(hwnd, 1002);
            LRESULT selectedIndex = SendMessageW(
                combo, CB_GETCURSEL, 0, 0);
            if (selectedIndex == CB_ERR)
            {
                return 0;
            }
            else
            {
                LRESULT itemData = SendMessageW(
                    combo,
                    CB_GETITEMDATA,
                    (WPARAM)selectedIndex,
                    0);

                if (itemData == CB_ERR || itemData == 0)
                {
                    MessageBoxW(
                        hwnd,
                        L"Failed to get adapter data.",
                        L"PacketScope Error",
                        MB_OK | MB_ICONERROR);
                    return 0;
                }

                char *deviceName = (char *)itemData;
                char errbuf[PCAP_ERRBUF_SIZE] = {0};
                pcap_t *handle = open_capture(deviceName, errbuf);
                if (handle == NULL)
                {
                    MessageBoxW(
                        hwnd,
                        L"Failed to open capture handle.",
                        L"PacketScope Error",
                        MB_OK | MB_ICONERROR);
                    pcap_close(handle);
                    return 0;
                }
                HANDLE thread = CreateThread(
                    NULL,
                    0,
                    capture_thread,
                    handle,
                    0,
                    NULL);
                if (thread == NULL)
                {
                    MessageBoxW(
                        hwnd,
                        L"Failed to create capture thread.",
                        L"PacketScope Error",
                        MB_OK | MB_ICONERROR);
                    pcap_close(handle);
                    return 0;
                }
                DWORD waitResult = WaitForSingleObject(thread, INFINITE);
                if (waitResult == WAIT_FAILED)
                {
                    MessageBoxW(
                        hwnd,
                        L"Failed to wait for capture thread.",
                        L"PacketScope Error",
                        MB_OK | MB_ICONERROR);
                    return 0;
                }
                if (waitResult == WAIT_OBJECT_0)
                {
                    // 스레드 핸들 닫기
                    CloseHandle(thread);

                    // Npcap 캡처 핸들 닫기
                    pcap_close(handle);
                }
                wchar_t adapterName[256] = {0};

                LRESULT length = SendMessageW(
                    combo,
                    CB_GETLBTEXTLEN,
                    (WPARAM)selectedIndex,
                    0);

                if (length == CB_ERR || length >= 256)
                {
                    return 0;
                }

                LRESULT copied = SendMessageW(
                    combo,
                    CB_GETLBTEXT,
                    (WPARAM)selectedIndex,
                    (LPARAM)adapterName);

                if (copied == CB_ERR)
                {
                    return 0;
                }

                MessageBoxW(
                    hwnd,
                    adapterName,
                    L"Selected Adapter",
                    MB_OK | MB_ICONINFORMATION);

                return 0;
            }
        }
        break;

    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
    return DefWindowProcW(hwnd, uMsg, wParam, lParam);
}

void free_adapter_data(HWND combo)
{
    LRESULT count = SendMessageW(
        combo,
        CB_GETCOUNT,
        0,
        0);

    if (count == CB_ERR)
    {
        return;
    }
    // 콤보박스에 저장된 모든 포인터 해제
    for (LRESULT i = 0; i < count; i++)
    {
        LRESULT itemData = SendMessageW(
            combo,
            CB_GETITEMDATA,
            (WPARAM)i,
            0);

        if (itemData != CB_ERR)
        {
            char *deviceName = (char *)itemData;
            free(deviceName);

            SendMessageW(
                combo,
                CB_SETITEMDATA,
                (WPARAM)i,
                0);
        }
    }
}

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