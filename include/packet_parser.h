#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>

void analyze_packet(
    pcap_t *handle,
    const struct pcap_pkthdr *header,
    const u_char *data
);

int is_ipv4_packet(const unsigned char *data, unsigned int length);

int parse_ipv4_addresses (
    const unsigned char *data,
    unsigned int length,
    unsigned char source[4],
    unsigned char destination[4]
);

int get_ipv4_protocol(
    const unsigned char *data,
    unsigned int length
);

int parse_transport_ports(
    const unsigned char *data,
    unsigned int length,
    unsigned short *sourcePort,
    unsigned short *destinationPort
);

int parse_ethernet_header(
    const unsigned char *data,
    unsigned int length,
    unsigned char destination[6],
    unsigned char source[6],
    unsigned short *etherType
);

void print_mac_address(const unsigned char mac[6]);

#endif