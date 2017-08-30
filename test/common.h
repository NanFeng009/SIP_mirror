#define MAX_RECV_LOOPS             1000
#define SIPP_MAXFDS                65536
#define SIPP_MAX_MSG_SIZE          65536
/* These buffers lets us read past the end of the message, and then split it if
 * required.  This eliminates the need for reading a message octet by octet and
 * performing a second read for the content length. */
struct socketbuf {
    char *buf;
    size_t len;
    size_t offset;
    struct sockaddr_storage addr;
    struct socketbuf *next;

};

struct SIPpSocket{
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

}

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
