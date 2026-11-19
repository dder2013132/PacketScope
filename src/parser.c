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

int is_ipv4_packet(const unsigned char *data, unsigned int length)
{
    if (length < 14)
    {
        return 0; // 없당
    }

    unsigned int etherType = ((unsigned int)data[12] << 8) | data[13];
    return etherType == 0x0800;
};

int parse_ipv4_addresses(
    const unsigned char *data,
    unsigned int length,
    unsigned char source[4],
    unsigned char destination[4])
{
    if (data == NULL || source == NULL || destination == NULL)
    {
        return 0;
    }

    if (length < 34)
    {
        return 0;
    }

    if (!is_ipv4_packet(data, length))
    {
        return 0;
    }

    unsigned int version = data[14] >> 4;
    unsigned int ihl = data[14] & 0x0F;

    if (version != 4 || ihl < 5)
    {
        return 0;
    }

    if (length < 14 + ihl * 4)
    {
        return 0;
    }

    for (int i = 0; i < 4; i++)
    {
        source[i] = data[26 + i];
        destination[i] = data[30 + i];
    }

    return 1;
};

int get_ipv4_protocol(
    const unsigned char *data,
    unsigned int length)
{
    if (data == NULL || length < 34)
    {
        return -1;
    }

    if (!is_ipv4_packet(data, length))
    {
        return -1;
    }

    unsigned int version = data[14] >> 4;
    unsigned int ihl = data[14] & 0x0F;

    if (version != 4 || ihl < 5 || length < 14 + ihl * 4)
    {
        return -1;
    }

    return data[23];
};

int parse_transport_ports(
    const unsigned char *data,
    unsigned int length,
    unsigned short *sourcePort,
    unsigned short *destinationPort)
{
    if (data == NULL || sourcePort == NULL || destinationPort == NULL)
    {
        return 0;
    }

    if (!is_ipv4_packet(data, length) || length < 34)
    {
        return 0;
    }

    unsigned int version = data[14] >> 4;
    unsigned int ihl = data[14] & 0x0F;

    if (version != 4 || ihl < 5)
    {
        return 0;
    }

    unsigned int ipHeaderLength = ihl * 4;
    unsigned int transportHeaderOffset = 14 + ipHeaderLength;

    if (length < transportHeaderOffset + 4)
    {
        return 0;
    }

    unsigned int protocol = data[23];

    if (protocol != 6 && protocol != 17)
    {
        return 0;
    }

    unsigned int fragmentOffset =
        (((unsigned int)data[20] << 8) | data[21]) & 0x1FFF;

    if (fragmentOffset != 0)
    {
        return 0;
    }

    unsigned int totalLength =
        ((unsigned int)data[16] << 8) | data[17];

    if (totalLength < ipHeaderLength + 4 ||
        length < transportHeaderOffset + 4)
    {
        return 0;
    }

    *sourcePort =
        ((unsigned int)data[transportHeaderOffset] << 8) | data[transportHeaderOffset + 1];

    *destinationPort =
        ((unsigned int)data[transportHeaderOffset + 2] << 8) | data[transportHeaderOffset + 3];

    return 1;
}

int parse_ethernet_header(
    const unsigned char *data,
    unsigned int length,
    unsigned char destination[6],
    unsigned char source[6],
    unsigned short *etherType   
)
{   
    // 1. NULL 검사

    if(destination == NULL || source == NULL || etherType == NULL) {
        return 0;
    }

    if(data == NULL){
        return 0;
    }

    // 2. 최소 길이 검사
    if(length < 14) {
        return 0;
    }
    // 3. Destination MAC 추출
    for(int i=0;i<6;i++){
        destination[i] = data[i];
    }

    // 4. Source MAC 추출
    for(int i=0;i<6;i++){
        source[i] = data[i+6];
    }

    // 5. EtherType 추출 (다음 미션)
    *etherType = (data[12] << 8) | data[13];

    return 1;
}

void print_mac_address(const unsigned char mac[6])
{
    if(mac == NULL) {
        return;
    }
    // 직접 구현
    for(int i=0;i<6;i++){
        if(i==5){printf("%02X", mac[i]); break;}
        printf("%02X:", mac[i]);
    }
}