#include <stdio.h>
#include "packet_parser.h"

void analyze_packet(
    pcap_t *handle,
    const struct pcap_pkthdr *header,
    const u_char *data)
{
    printf("Captured: %u bytes\n", header->caplen);
    printf("Original: %u bytes\n", header->len);

    for (unsigned int i = 0; i < 16 && i < header->caplen; i++)
    {
        printf("%02X ", (unsigned int)data[i]);
    }
    printf("\n");
    if (pcap_datalink(handle) == DLT_EN10MB)
    {
        if (header->caplen >= 14)
        {
            unsigned int etherType = ((unsigned int)data[12] << 8) | data[13];
            printf("EtherType: 0x%04X\n", etherType);
            if (etherType == 0x0800)
            {
                printf("Protocol : IPv4\n");
            }
            else if (etherType == 0x0806)
            {
                printf("Protocol : ARP\n");
            }
            else if (etherType == 0x86DD)
            {
                printf("Protocol : IPv6\n");
            }
            else
            {
                printf("Protocol : Unknown\n");
            }
        }
    }
};