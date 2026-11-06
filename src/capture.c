#include <stdio.h>
#include "capture.h"

int list_devices(pcap_if_t *alldevs)
{
    pcap_if_t *current = alldevs;     // 목록을 순회할 때 사용하는 포인터
    int count = 0;

    while (current != NULL)
    {
        count++;
        printf("[%d] %s\n", count, current->name);
        if (current->description != NULL)
        {
            printf("%s\n", current->description);
        }
        else
        {
            printf("No description\n");
        }
        current = current->next;
    }
    printf("Total: %d adapters\n", count);

    return count;
}

pcap_t *open_capture(const char *device_name, char *errbuf)
{
    // pcap_open_live() 호출
    pcap_t *handle = pcap_open_live(device_name, 65535, 0, 1000, errbuf);
    // 반환된 handle을 return
    return handle;
}

int receive_packet(pcap_t *handle, struct pcap_pkthdr **header, const u_char **data) {
    int result = pcap_next_ex(handle, header, data);
    return result;
}