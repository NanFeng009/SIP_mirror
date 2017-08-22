#ifndef _SIPP_SEND_PACKETS_H_
#define _SIPP_SEND_PACKETS_H_

#include <sys/socket.h>
#include "prepare_pcap.h"
#include <stdint.h>

/* call specific vars for RTP sending */
typedef struct {
    /* pointer to a RTP pkts container */
    pcap_pkts* pcap;
    /* Used in send_packets thread */
    struct sockaddr_storage to;
    struct sockaddr_storage from;

    /* non-zero if the thread should destroy the *pcap when done playing or aborted */
    int free_pcap_when_done;
    uint16_t last_seq_no;
} play_args_t;


/* compare tvp and uvp using cmp */
#ifndef timercmp
#define timercmp(tvp, uvp, cmp) \
        (((tvp)->tv_sec == (uvp)->tv_sec) ? \
         ((tvp)->tv_usec cmp (uvp)->tv_usec) :  \
         ((tvp)->tv_sec cmp (uvp)->tv_sec))
#endif
#endif/*_SIPP_SEND_PACKETS_H_*/
