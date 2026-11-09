#include <winsock2.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <commctrl.h>
#include "gui.h"
#include "capture.h"
#include "packet_parser.h"

#define WM_CAPTURE_FINISHED (WM_APP + 1)
#define WM_PACKET_RECEIVED (WM_APP + 2)

LRESULT CALLBACK WindowProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam);

typedef struct
{
    CaptureContext *capture;
    HANDLE thread;
    HANDLE waitHandle;
    bool closing;
} GuiState;

typedef struct
{
    int number;
    wchar_t source[46];
    wchar_t destination[46];
    wchar_t protocol[16];
} PacketRow;

void drain_packet_messages(HWND hwnd);

void cleanup_capture(GuiState *state);

void free_adapter_data(HWND combo);

void add_packet_row(
    HWND listView,
    const PacketRow *packet);

VOID CALLBACK capture_finished_callback(
    PVOID param,
    BOOLEAN timedOut);

DWORD WINAPI capture_thread(LPVOID param);

int run_gui(void)
{
    HINSTANCE hInstance = GetModuleHandleW(NULL);

    INITCOMMONCONTROLSEX icc = {0};

    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;

    if (!InitCommonControlsEx(&icc))
    {
        return 1;
    }

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

        GuiState *state = (GuiState *)GetWindowLongPtrW(
            hwnd,
            GWLP_USERDATA);

        if (state != NULL)
        {
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            free(state);
        }

        PostQuitMessage(0);
        return 0;
    }
    case WM_CREATE:
    {
        GuiState *state = calloc(1, sizeof(GuiState));

        if (state == NULL)
        {
            return -1;
        }

        SetWindowLongPtrW(
            hwnd,
            GWLP_USERDATA,
            (LONG_PTR)state);
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
        CreateWindowExW(
            0,
            L"BUTTON",
            L"Stop Capture",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            20, 65,
            140, 35,
            hwnd,
            (HMENU)1003,
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
        HWND listView = CreateWindowExW(
            WS_EX_CLIENTEDGE,
            WC_LISTVIEWW,
            L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT,
            20, 120,
            840, 380,
            hwnd,
            (HMENU)1004,
            GetModuleHandleW(NULL),
            NULL);

        if (listView == NULL)
        {
            return -1;
        }
        LVCOLUMNW column = {0};

        column.mask = LVCF_TEXT | LVCF_WIDTH;

        // 0번 열
        column.cx = 60;
        column.pszText = L"No.";
        SendMessageW(listView, LVM_INSERTCOLUMNW, 0, (LPARAM)&column);

        // 1번 열
        column.cx = 220;
        column.pszText = L"Source";
        SendMessageW(listView, LVM_INSERTCOLUMNW, 1, (LPARAM)&column);

        // 2번 열
        column.cx = 220;
        column.pszText = L"Destination";
        SendMessageW(listView, LVM_INSERTCOLUMNW, 2, (LPARAM)&column);

        // 3번 열
        column.cx = 340;
        column.pszText = L"Protocol";
        SendMessageW(listView, LVM_INSERTCOLUMNW, 3, (LPARAM)&column);

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
            GuiState *state = (GuiState *)GetWindowLongPtrW(
                hwnd,
                GWLP_USERDATA);

            if (state == NULL)
            {
                MessageBoxW(
                    hwnd,
                    L"Failed to get GUI state.",
                    L"PacketScope Error",
                    MB_OK | MB_ICONERROR);
                return 0;
            }
            if (state->thread != NULL)
            {
                return 0;
            }
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
                    return 0;
                }
                CaptureContext *ctx = malloc(sizeof(CaptureContext));
                if (ctx == NULL)
                {
                    MessageBoxW(
                        hwnd,
                        L"Failed to allocate capture context.",
                        L"PacketScope Error",
                        MB_OK | MB_ICONERROR);
                    pcap_close(handle);
                    return 0;
                }
                ctx->handle = handle;
                atomic_init(&ctx->running, true);
                atomic_init(&ctx->pendingPackets, 0);
                ctx->hwnd = hwnd;
                HANDLE thread = CreateThread(
                    NULL,
                    0,
                    capture_thread,
                    ctx,
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
                    free(ctx);
                    return 0;
                }
                state->capture = ctx;
                state->thread = thread;

                BOOL registered = RegisterWaitForSingleObject(
                    &state->waitHandle,
                    state->thread,
                    capture_finished_callback,
                    hwnd,
                    INFINITE,
                    WT_EXECUTEONLYONCE);

                if (!registered)
                {
                    DWORD error = GetLastError();

                    atomic_store(&ctx->running, false);
                    pcap_breakloop(handle);

                    MessageBoxW(
                        hwnd,
                        L"Failed to register wait for capture thread.",
                        L"PacketScope Error",
                        MB_OK | MB_ICONERROR);

                    UINT_PTR timerId = SetTimer(
                        hwnd,
                        1,
                        100,
                        NULL);

                    if (timerId == 0)
                    {
                        {
                            MessageBoxW(
                                hwnd,
                                L"Failed to wait for capture thread.",
                                L"PacketScope Error",
                                MB_OK | MB_ICONERROR);
                        }
                    }
                    return 0;
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
        if (LOWORD(wParam) == 1003 &&
            HIWORD(wParam) == BN_CLICKED)
        {
            GuiState *state = (GuiState *)GetWindowLongPtrW(
                hwnd,
                GWLP_USERDATA);

            if (state == NULL || state->capture == NULL)
            {
                return 0;
            }

            atomic_store(&state->capture->running, false);

            pcap_breakloop(state->capture->handle);

            return 0;
        }
        break;
    case WM_CAPTURE_FINISHED:
    {
        GuiState *state = (GuiState *)GetWindowLongPtrW(
            hwnd,
            GWLP_USERDATA);

        if (state == NULL || state->thread == NULL)
        {
            return 0;
        }

        DWORD result = WaitForSingleObject(state->thread, 0);

        if (result != WAIT_OBJECT_0)
        {
            return 0;
        }

        if (state->waitHandle != NULL)
        {
            BOOL unregistered = UnregisterWaitEx(
                state->waitHandle,
                INVALID_HANDLE_VALUE);

            if (!unregistered)
            {
                MessageBoxW(
                    hwnd,
                    L"Failed to unregister capture wait.",
                    L"PacketScope Error",
                    MB_OK | MB_ICONERROR);
                return 0;
            }

            state->waitHandle = NULL;
        }

        drain_packet_messages(hwnd);
        cleanup_capture(state);

        if (state->closing)
        {
            DestroyWindow(hwnd);
        }

        return 0;
    }
    case WM_TIMER:
    {
        if (wParam != 1)
        {
            break;
        }
        GuiState *state = (GuiState *)GetWindowLongPtrW(
            hwnd,
            GWLP_USERDATA);

        if (state == NULL || state->thread == NULL)
        {
            KillTimer(hwnd, 1);
            return 0;
        }

        DWORD result = WaitForSingleObject(state->thread, 0);

        if (result == WAIT_OBJECT_0)
        {
            KillTimer(hwnd, 1);
            drain_packet_messages(hwnd);
            cleanup_capture(state);

            if (state->closing)
            {
                DestroyWindow(hwnd);
            }
        }
        else if (result == WAIT_TIMEOUT)
        {
            // 아직 실행 중
        }
        else if (result == WAIT_FAILED)
        {
            // 오류 발생
        }

        return 0;
    }
    case WM_CLOSE:
    {
        GuiState *state = (GuiState *)GetWindowLongPtrW(
            hwnd,
            GWLP_USERDATA);

        if (state == NULL || state->thread == NULL)
        {
            DestroyWindow(hwnd);
            return 0;
        }

        state->closing = true;

        atomic_store(&state->capture->running, false);

        pcap_breakloop(state->capture->handle);

        return 0;
    }
    case WM_PACKET_RECEIVED:
    {
        PacketRow *packet = (PacketRow *)lParam;

        if (packet != NULL)
        {
            GuiState *state = (GuiState *)GetWindowLongPtrW(
                hwnd,
                GWLP_USERDATA);

            if (state != NULL && !state->closing)
            {
                HWND listView = GetDlgItem(hwnd, 1004);

                if (listView != NULL)
                {
                    add_packet_row(listView, packet);
                }
            }

            if (state != NULL && state->capture != NULL)
            {
                atomic_fetch_sub(&state->capture->pendingPackets, 1);
            }

            free(packet);
        }

        return 0;
    }
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
    CaptureContext *ctx = (CaptureContext *)param;
    pcap_t *handle = ctx->handle;
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        printf("Unsupported link-layer type.\n");
        return 0;
    }
    struct pcap_pkthdr *header = NULL;
    const u_char *data = NULL;
    while (atomic_load(&ctx->running))
    {
        int result = receive_packet(handle, &header, &data);
        if (result == 1)
        {
            unsigned char source[4];
            unsigned char destination[4];

            if (!parse_ipv4_addresses(
                    data,
                    header->caplen,
                    source,
                    destination))
            {
                continue;
            }
            unsigned short sourcePort = 0;
            unsigned short destinationPort = 0;

            int hasPorts = parse_transport_ports(
                data,
                header->caplen,
                &sourcePort,
                &destinationPort);
            PacketRow *packet = calloc(1, sizeof(PacketRow));
            if (packet == NULL)
            {
                printf("Failed to allocate PacketRow.\n");
                break;
            }
            packet->number = 1;
            if (hasPorts)
            {
                swprintf(
                    packet->source,
                    46,
                    L"%u.%u.%u.%u:%u",
                    source[0], source[1], source[2], source[3],
                    (unsigned int)sourcePort);

                swprintf(
                    packet->destination,
                    46,
                    L"%u.%u.%u.%u:%u",
                    destination[0], destination[1],
                    destination[2], destination[3],
                    (unsigned int)destinationPort);
            }
            else
            {
                swprintf(
                    packet->source,
                    46,
                    L"%u.%u.%u.%u",
                    source[0], source[1], source[2], source[3]);

                swprintf(
                    packet->destination,
                    46,
                    L"%u.%u.%u.%u",
                    destination[0], destination[1],
                    destination[2], destination[3]);
            }
            int protocol = get_ipv4_protocol(data, header->caplen);

            switch (protocol)
            {
            case 1:
                wcscpy_s(packet->protocol, 16, L"ICMP");
                break;

            case 6:
                wcscpy_s(packet->protocol, 16, L"TCP");
                break;

            case 17:
                wcscpy_s(packet->protocol, 16, L"UDP");
                break;

            default:
                swprintf(packet->protocol, 16, L"IP %d", protocol);
                break;
            }

            if (atomic_load(&ctx->pendingPackets) >= 100)
            {
                free(packet);
                continue;
            }
            atomic_fetch_add(&ctx->pendingPackets, 1);
            BOOL posted = PostMessageW(
                ctx->hwnd,
                WM_PACKET_RECEIVED,
                0,
                (LPARAM)packet);

            if (!posted)
            {
                atomic_fetch_sub(&ctx->pendingPackets, 1);
                free(packet);
                break;
            }
            printf("%u\n", header->caplen);
        }
        else if (result == 0)
        {
            printf("Timeout occurred\n");
        }
        else if (result == -1)
        {
            printf("Error occurred: %s\n", pcap_geterr(handle));
            break;
        }
        else if (result == -2)
        {
            printf("No more packets to read from the savefile\n");
            break;
        }
    }
    return 0;
}

void drain_packet_messages(HWND hwnd)
{
    MSG msg;

    while (PeekMessageW(
        &msg,
        hwnd,
        WM_PACKET_RECEIVED,
        WM_PACKET_RECEIVED,
        PM_REMOVE))
    {
        PacketRow *packet = (PacketRow *)msg.lParam;
        free(packet);
    }
}

void cleanup_capture(GuiState *state)
{
    if (state == NULL || state->capture == NULL)
    {
        return;
    }

    pcap_close(state->capture->handle);

    if (state->thread != NULL)
    {
        CloseHandle(state->thread);
    }

    free(state->capture);

    state->capture = NULL;
    state->thread = NULL;
}

VOID CALLBACK capture_finished_callback(
    PVOID param,
    BOOLEAN timedOut)
{
    (void)timedOut; // 사용되지 않는 매개변수 무시
    HWND hwnd = (HWND)param;

    PostMessageW(
        hwnd,
        WM_CAPTURE_FINISHED,
        0,
        0);
}

void add_packet_row(
    HWND listView,
    const PacketRow *packet)
{
    HWND hwnd = GetParent(listView);
    LVITEMW item = {0};

    wchar_t numberText[32];

    item.mask = LVIF_TEXT;
    item.iItem = ListView_GetItemCount(listView);
    item.iSubItem = 0;

    swprintf(
        numberText,
        32,
        L"%d",
        item.iItem + 1);

    item.pszText = numberText;

    LRESULT index = SendMessageW(
        listView,
        LVM_INSERTITEMW,
        0,
        (LPARAM)&item);

    if (index == -1)
    {
        MessageBoxW(
            hwnd,
            L"Failed to insert packet row.",
            L"PacketScope Error",
            MB_OK | MB_ICONERROR);
        return;
    }

    item.iItem = (int)index;
    item.iSubItem = 1;
    item.pszText = (LPWSTR)packet->source;

    SendMessageW(
        listView,
        LVM_SETITEMTEXTW,
        (WPARAM)index,
        (LPARAM)&item);

    item.iItem = (int)index;
    item.iSubItem = 2;
    item.pszText = (LPWSTR)packet->destination;

    SendMessageW(
        listView,
        LVM_SETITEMTEXTW,
        (WPARAM)index,
        (LPARAM)&item);

    item.iItem = (int)index;
    item.iSubItem = 3;
    item.pszText = (LPWSTR)packet->protocol;

    SendMessageW(
        listView,
        LVM_SETITEMTEXTW,
        (WPARAM)index,
        (LPARAM)&item);
}