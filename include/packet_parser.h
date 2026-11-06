#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <pcap.h>

void analyze_packet(
    pcap_t *handle,
    const struct pcap_pkthdr *header,
    const u_char *data
);

#endif