#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

//#ifndef, #define, #endif는 헤더 파일이 
//한 번의 컴파일 과정에서 중복으로 포함되더라도 
//선언이 반복 처리되지 않도록 하는 헤더 가드
int list_devices(pcap_if_t *alldevs);

#endif