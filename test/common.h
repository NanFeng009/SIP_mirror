#define MAX_RECV_LOOPS             1000
#define SIPP_MAXFDS                65536
#define SIPP_MAX_MSG_SIZE          65536
#define PCAP_MAXPACKET 1500

/************************** protocol length********************/
#define IP4_HDRLEN   20
#define TCP_HDRLEN   20
#define UDP_HDRLEN   8

/* This is an abstraction of a socket, which provides buffers for input and
 * output. 
 */
typedef struct {
    int ss_count; /* How many users are there of this sockets? */
    int ss_transport; /*T_TCP, T_UDP, or */
    int ss_fd;  /* The underlying file descriptor for this socket. */
    int ss_port; /* The port used by this socket */
    struct sockaddr_storage ss_dest; /* Who we are talking to. */
    int ss_pollidx; /* The index of this socket in our poll structures. */
    struct socketbuf *ss_in;    /* Buffered input. */
    struct socketbuf *ss_out;   /* Buffered output. */
    size_t ss_msglen;           /* Is there a complete SIP message waiting, and if so how big? */

    bool ss_congested; /* Is this socket congested? */
    bool ss_invalid; /* Has this socket been closed remotely? */

    bool ss_changed_dest;   /* Has the destination changed from default. */

} SIPpSocket;

/* These buffers lets us read past the end of the message, and then split it if
 * required.  This eliminates the need for reading a message octet by octet and
 * performing a second read for the content length. */
typedef struct socketbuf {
    u_char* pktdata;
    u_long pktlen;
    long interval;
    struct timeval ts;
    int partial_check;
    char *pkt_src; //need to free when end
    char *pkt_dst;
    struct socketbuf *next;
} socketbuf;
/************************** wireshark packet********************/
typedef struct pkt_type{
    protocol type;
    uint16_t num;
} pkt_type;

typedef struct pcap_pkts{
    char* file;
    uint16_t count;
    pkt_type pkt;
} pcap_pkts;

typedef struct _ether_type_hdr {
    uint16_t ether_type; /* we only need the type, so we can determine, if the next header is IPv4 or IPv6 */
} ether_type_hdr;

/************************** ethernet type **************************/

typedef enum{
    ARP = 0x0806,
    IP = 0x0800,
    LLDP = 0x88cc,
    CDP = 0x2000,
    TLS =  0x888e,
    IPV6 = 0x86dd
}protocol;

/************************** Constants **************************/

#define T_UDP                      0
#define T_TCP                      1
#define T_TLS                      2
#define T_RAW                      3

#define TRANSPORT_TO_STRING(p)     ((p==T_TCP) ? "TCP" : ((p==T_TLS)? "TLS" : ((p==T_UDP)? "UDP" : "RAW")))

/* Socket Buffer Management. */
#define NO_COPY 0
#define DO_COPY 1

#define sipp_socklen_t int
typedef enum { false, true  } bool;

#define LOG(format, args...) do {                \
    printf("%s: "format"\n", __func__, ##args);  \
} while(0)

#define MICROSECONDS_PER_SECOND 1000000LL
#define MICROSECONDS_PER_MILLISECOND 1000LL
#define NANOSECONDS_PER_MICROSECOND 1000LL

#define _RCAST(type, val) ((type)(val))


/* call specific vars for RTP sending */
typedef struct play_args_t{
    /* pointer to a RTP pkts container */
    socketbuf* payload;
    /* Used in send_packets thread */
    struct sockaddr_storage to;
    struct sockaddr_storage from;

    /* non-zero if the thread should destroy the *pcap when done playing or aborted */
    int free_pcap_when_done;
    uint16_t last_seq_no;

} play_args_t;
