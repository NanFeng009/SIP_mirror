#ifndef _SIPP_PREPARE_PCAP_H_
#define _SIPP_PREPARE_PCAP_H_


#include <stdint.h>


typedef struct {
    u_char* data;
    u_long pktlen;
    struct timeval ts;
    int partial_check;

} pcap_pkt;

typedef struct {
    char* file;
    uint16_t base;
    u_long max_length;
    pcap_pkt* max;
    pcap_pkt* pkt;

} pcap_pkts;

#endif/*_SIPP_PREPARE_PCAP_H_*/
