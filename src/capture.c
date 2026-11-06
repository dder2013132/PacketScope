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