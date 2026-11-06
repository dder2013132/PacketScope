#include <windows.h>
#include "gui.h"

LRESULT CALLBACK WindowProc(
    HWND hwnd,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam);

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
        PostQuitMessage(0);
        return 0;
    case WM_CREATE:
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
        return 0;

    default:
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);
    }
}