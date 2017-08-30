/* This file was automatically generated.  Do not edit! */
int main();
typedef enum { false, true  }bool;
typedef struct SIPpSocket SIPpSocket;
void invalidate(SIPpSocket *sock);
#define T_TCP                      1
#define T_TLS                      2
#define T_UDP                      0
#define TRANSPORT_TO_STRING(p)     ((p==T_TCP) ? "TCP" : ((p==T_TLS)? "TLS" : ((p==T_UDP)? "UDP" : "RAW")))
bool reconnect_allowed();
void abort1(SIPpSocket *sock);
int check_for_message(SIPpSocket *sock);
void sipp_customize_socket(SIPpSocket *socket);
extern int buff_size;
#define LOCAL static
extern int transport;
LOCAL int socket_fd(int transport);
SIPpSocket *Initialize_SIPpSocket(SIPpSocket *p,int transport,int fd);
LOCAL SIPpSocket *sipp_allocate_socket(int transport,int fd);
SIPpSocket *new_sipp_socket(int transport);
int open_connections();
LOCAL char *get_inet_address(const struct sockaddr_storage *addr,char *dst,int len);
extern struct sockaddr_storage local_sockaddr;
extern struct addrinfo *local_addr_storage;
extern char hostname[80];
extern char local_ip_escaped[42];
extern char local_ip[40];
extern int local_port;
#define NO_COPY 0
typedef struct socketbuf socketbuf;
void buffer_read(SIPpSocket *sock,struct socketbuf *newbuf);
#define DO_COPY 1
struct socketbuf *alloc_socketbuf(char *buffer,size_t size,int copy,struct sockaddr_storage *dest);
void buffer_write(SIPpSocket *sock,const char *buffer,size_t len,struct sockaddr_storage *dest);
int sipp_bind_socket(SIPpSocket *socket,struct sockaddr_storage *saddr,int *port);
#define sipp_socklen_t int
void process_message(SIPpSocket *socket,char *msg,ssize_t msg_size,struct sockaddr_storage *src);
ssize_t read_message(SIPpSocket *sock,char *buf,size_t len,struct sockaddr_storage *src);
#define SIPP_MAX_MSG_SIZE          65536
int message_ready(SIPpSocket *sock);
unsigned long getmilliseconds();
int empty(SIPpSocket *sock);
SIPpSocket *sipp_accept(SIPpSocket *sock);
#define MAX_RECV_LOOPS             1000
void pollset_process(int wait);
LOCAL int enter_congestion(SIPpSocket *sock,int again);
int write_error(SIPpSocket *sock,int ret);
int flush(SIPpSocket *sock);
socklen_t socklen_from_addr(const struct sockaddr_storage *ss);
LOCAL int send_nowait(int s,const void *msg,int len,int flags);
ssize_t write_primitive(SIPpSocket *sock,const char *buffer,size_t len,struct sockaddr_storage *dest);
struct socketbuf {
    char *buf;
    size_t len;
    size_t offset;
    struct sockaddr_storage addr;
    struct socketbuf *next;

};
void free_socketbuf(struct socketbuf *socketbuf);
#define LOG(format, args...) do {                \
    printf("%s: "format"\n", __func__, ##args);  \
} while(0)
LOCAL void merge_socketbufs(struct socketbuf *socketbuf);
extern SIPpSocket *main_socket;
extern int reset_number;
extern int pending_messages;
extern struct sockaddr_storage remote_sockaddr;
#define SIPP_MAXFDS                65536
extern SIPpSocket *sockets[SIPP_MAXFDS];
struct SIPpSocket {
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

};
extern struct epoll_event *epollevents;
extern struct epoll_event epollfiles[SIPP_MAXFDS];
extern int epollfd;
extern unsigned pollnfds;
