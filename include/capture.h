#ifndef CAPTURE_H
#define CAPTURE_H

#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <stdatomic.h>

typedef struct
{
    pcap_t *handle;
    atomic_bool running;
    HWND hwnd;
    atomic_int pendingPackets;
} CaptureContext;

// #ifndef, #define, #endif는 헤더 파일이
// 한 번의 컴파일 과정에서 중복으로 포함되더라도
// 선언이 반복 처리되지 않도록 하는 헤더 가드
int list_devices(pcap_if_t *alldevs);
pcap_t *open_capture(const char *device_name, char *errbuf);
int receive_packet(pcap_t *handle, struct pcap_pkthdr **header, const u_char **data);
int find_devices(pcap_if_t **alldevs, char *errbuf);
pcap_if_t *get_device_by_index(pcap_if_t *alldevs, int index);

#endif