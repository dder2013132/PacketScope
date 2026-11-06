#include <stdio.h>
#include <pcap.h>
#include "capture.h"
#include "packet_parser.h"

int main()
{
    pcap_if_t *alldevs = NULL;     // 장치 목록의 첫 노드
    pcap_if_t *current = NULL;     // 목록을 순회할 때 사용하는 포인터
    char errbuf[PCAP_ERRBUF_SIZE]; // 오류 메시지를 저장할 공간

    if (pcap_findalldevs(&alldevs, errbuf) == 0)
    {
        printf("SUCCESS\n");
    }
    else
    {
        printf("Error: %s\n", errbuf);
        return 1;
    }

    current = alldevs;
    int count = list_devices(alldevs);

    int num = 0;

    printf("Select network adapter: ");

    if (scanf("%d", &num) != 1)
    {
        printf("Invalid input\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (num < 1 || num > count)
    {
        printf("Invalid adapter number\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    current = alldevs;

    for (int i = 0; i < num - 1; i++)
    {
        current = current->next;
    }

    if (current->description != NULL)
    {
        printf("%s\n", current->description);
    }
    else
    {
        printf("No description\n");
    }

    struct pcap_pkthdr *header = NULL;
    const u_char *data = NULL;
    int result;

    pcap_t *handle = pcap_open_live(current->name, 65535, 0, 1000, errbuf);

    if (handle == NULL)
    {
        printf("Error: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return 1;
    }

    printf("Capture device opened!\n");

    result = pcap_next_ex(handle, &header, &data);

    if (result == 1)
    {
        analyze_packet(handle, header, data);
    }
    else if (result == 0)
    {
        printf("No packet received (timeout)\n");
    }
    else if (result == -1)
    {
        printf("Capture error: %s\n", pcap_geterr(handle));
    }
    else if (result == -2)
    {
        printf("Capture ended\n");
    }

    pcap_close(handle);

    pcap_freealldevs(alldevs);

    return 0;
}