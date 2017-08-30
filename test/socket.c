#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include "socket.h"
#include <netinet/tcp.h>

/******************** Recv Poll Processing *********************/
unsigned pollnfds;
int epollfd;
struct epoll_event epollfiles[SIPP_MAXFDS];
struct epoll_event*  epollevents;
SIPpSocket  *sockets[SIPP_MAXFDS];

struct sockaddr_storage remote_sockaddr;

int pending_messages = 0;

int reset_number = 0;
/*********************** Global Sockets  **********************/

SIPpSocket   *main_socket;

LOCAL void merge_socketbufs(struct socketbuf* socketbuf)
{
    struct socketbuf *next = socketbuf->next;
    int newsize;
    char *newbuf;

    if (!next) {
        return;

    }
    if (next->offset) {
        LOG("Internal error: can not merge a socketbuf with a non-zero offset.");
    }
    if (socketbuf->offset) {
        memmove(socketbuf->buf, socketbuf->buf + socketbuf->offset, socketbuf->len - socketbuf->offset);
        socketbuf->len -= socketbuf->offset;
        socketbuf->offset = 0;
    }
    newsize = socketbuf->len + next->len;
    newbuf = (char *)realloc(socketbuf->buf, newsize);
    if (!newbuf) {
        LOG("Could not allocate memory to merge socket buffers!");
    }
    memcpy(newbuf + socketbuf->len, next->buf, next->len);
    socketbuf->buf = newbuf;
    socketbuf->len = newsize;
    socketbuf->next = next->next;
    free_socketbuf(next);
}

ssize_t write_primitive(SIPpSocket* sock, const char* buffer, size_t len,
        struct sockaddr_storage* dest)
{
    ssize_t rc;

    /* Refuse to write to invalid sockets. */
    if (sock->ss_invalid) {
        LOG("Returning EPIPE on invalid socket: (%d)\n",  sock->ss_fd);
        errno = EPIPE;
        return -1;

    }

    /* Always check congestion before sending. */
    if (sock->ss_congested) {
        errno = EWOULDBLOCK;
        return -1;

    }

    switch(sock->ss_transport) {
        case T_TCP:
            rc = send_nowait(sock->ss_fd, buffer, len, 0);
            break;
        case T_UDP:
            rc = sendto(sock->ss_fd, buffer, len, 0, (struct sockaddr*)dest,
                    socklen_from_addr(dest));
            break;

        default:
            LOG("Internal error, unknown transport type %d\n", sock->ss_transport);

    }

    return rc;

}

/* Flush any output buffers for this socket. */
int flush(SIPpSocket* sock)
{
    struct socketbuf *buf;
    int ret;

    while(buf = sock->ss_out){
        ssize_t size = buf->len - buf->offset;
        ret = write_primitive(sock, buf->buf + buf->offset, size, &buf->addr);
        LOG("Wrote %d of %zu bytes in an output buffer.\n", ret, size);
        if (ret == size) {
            /* Everything is great, throw away this buffer. */
            sock->ss_out = buf->next;
            free_socketbuf(buf);

        } else if (ret <= 0) {
            /* Handle connection closes and errors. */
            return write_error(sock, ret);

        } else {
            /* We have written more of the partial buffer. */
            buf->offset += ret;
            errno = EWOULDBLOCK;
            enter_congestion(sock, EWOULDBLOCK);
            return -1;
        }
    }
    return 0;
}

int transport = T_UDP;
void pollset_process(int wait)
{
    /* Number of times to execute recv()*/
    int rs; 

    /* Get socket events. */
    /* Ignore the wait parameter and always wait - when establishing TCP
     * connections, the alternative is that we tight-loop. */
    rs = epoll_wait(epollfd, epollevents, MAX_RECV_LOOPS, 1);

    if(rs < 0 && errno == EINTR){
        return;
    }

    for(int event_idx = 0; event_idx < rs; event_idx++){
        int poll_idx = (int)epollevents[event_idx].data.u32;
        SIPpSocket *sock = sockets[poll_idx];
        int events = 0;
        int ret = 0;

        assert(sock);

        if(epollevents[event_idx].events & EPOLLOUT){
            epollfiles[poll_idx].events &= ~EPOLLOUT;
            int rc = epoll_ctl(epollfd, EPOLL_CTL_MOD, sock->ss_fd, &epollfiles[poll_idx]);
            if (rc == -1) {
                LOG("Failed to clear EPOLLOUT");
            }
            sock->ss_congested = false;

            flush(sock);
            events++;

        } 
        if(epollevents[event_idx].events & EPOLLIN){
            /* We can empty this socket */
            if((transport == T_TCP ) && sock == main_socket) {
                SIPpSocket *new_sock = sipp_accept(sock);
                if (!new_sock) {
                    LOG("Accepting new TCP connection.\n");
                }
            }else{
                if((ret = empty(sock)) <= 0) {
                    //                    ret = sock->read_error(ret);
                    if(ret == 0) {
                        /* If read_error() then the poll_idx now belongs
                         * to the newest/last socket added to the sockets[].
                         * Need to re-do the same poll_idx for the "new" socket.
                         * We do this differently when using epoll. */
                        for(int event_idx2 = event_idx + 1; event_idx2 < rs; event_idx2++) {
                            if (epollevents[event_idx2].data.u32 == pollnfds) {
                                epollevents[event_idx2].data.u32 = poll_idx;
                            }
                        }
                        continue;
                    }
                }
            }
            events++;
        }
        /* Here the logic diverges; if we're using epoll, we want to stay in the
         * for-each-socket loop and handle messages on that socket. If we're not using
         * epoll, we want to wait until after that loop, and spin through our
         * pending_messages queue again. */
        unsigned old_pollnfds = pollnfds;
        getmilliseconds();
        /* Keep processing messages until this socket is freed (changing the number of file descriptors) or we run out of messages. */
        while ((pollnfds == old_pollnfds) &&
                (message_ready(sock))) {
            char msg[SIPP_MAX_MSG_SIZE];
            struct sockaddr_storage src;
            ssize_t len;

            len = read_message(sock, msg, sizeof(msg), &src);
            if (len > 0) {
                process_message(sock, msg, len, &src);

            } else {
                assert(0);

            }

        }

        if (pollnfds != old_pollnfds) {
            /* Processing messages has changed the number of pollnfds, so update any remaining events */
            for (int event_idx2 = event_idx + 1; event_idx2 < rs; event_idx2++) {
                if (epollevents[event_idx2].data.u32 == pollnfds) {
                    epollevents[event_idx2].data.u32 = poll_idx;
                }
            }
        }
    }
}

LOCAL int send_nowait(int s, const void* msg, int len, int flags)
{
    int fd_flags = fcntl(s, F_GETFL , NULL);
    int initial_fd_flags;
    int rc;

    initial_fd_flags = fd_flags;
    //  fd_flags &= ~O_ACCMODE; // Remove the access mode from the value
    fd_flags |= O_NONBLOCK;
    fcntl(s, F_SETFL , fd_flags);

    rc = send(s, msg, len, flags);

    fcntl(s, F_SETFL , initial_fd_flags);

    return rc;

}

SIPpSocket* sipp_accept(SIPpSocket* sock) {
    SIPpSocket *ret;
    struct sockaddr_storage remote_sockaddr;
    int fd;
    sipp_socklen_t addrlen = sizeof(remote_sockaddr);

    if ((fd = accept(sock->ss_fd, (struct sockaddr *)&remote_sockaddr, &addrlen))== -1) {
        LOG("Unable to accept on socket: %s", strerror(errno));

    }

    ret = (struct SIPpSocket *)malloc(sizeof(struct SIPpSocket));
    if (!ret) {
        close(fd);
        LOG("Could not allocate new socket!");

    }
    ret->ss_transport = sock->ss_transport;
    ret->ss_fd = sock->ss_fd;

    /* We should connect back to the address which connected to us if we
     *      * experience a TCP failure. */
    memcpy(&ret->ss_dest, &remote_sockaddr, sizeof(ret->ss_dest));


    return ret;

}

int sipp_bind_socket(SIPpSocket *socket, struct sockaddr_storage *saddr, int *port)
{
    int ret;
    int len;

    len = sizeof(struct sockaddr_in);

    if ((ret = bind(socket->ss_fd, (struct sockaddr *)saddr, len))) {
        return ret;
    }
    if (!port) {
        return 0;
    }
    if ((ret = getsockname(socket->ss_fd, (struct sockaddr *) saddr, (sipp_socklen_t *) &len))) {
        return ret;
    }
    socket->ss_port = ntohs((short)(((struct sockaddr_in *) saddr)->sin_port));

    *port = socket->ss_port;

    return 0;
}

void buffer_write(SIPpSocket *sock, const char *buffer, size_t len, struct sockaddr_storage *dest)
{
    struct socketbuf *buf = sock->ss_out;
    if (!buf) {
        sock->ss_out = alloc_socketbuf((char*)(buffer), len, DO_COPY, dest); /* NO BUG BECAUSE OF DO_COPY */
        LOG("Added first buffered message to socket %d\n", sock->ss_fd);
        return;

    }

    while (buf->next) {
        buf = buf->next;

    }

    buf->next = alloc_socketbuf((char*)(buffer), len, DO_COPY, dest); /* NO BUG BECAUSE OF DO_COPY */
    LOG("Appended buffered message to socket %d\n", sock->ss_fd);

}

void buffer_read(SIPpSocket *sock, struct socketbuf *newbuf)
{
    struct socketbuf *buf = sock->ss_in;
    struct socketbuf *prev = buf;

    if (!buf) {
        sock->ss_in = newbuf;
        return;

    }
    while (buf->next) {
        prev = buf;
        buf = buf->next;

    }
    prev->next = newbuf;
}


/* Pull up to tcp_readsize data bytes out of the socket into our local buffer. */
int empty(SIPpSocket *sock)
{

    int readsize=0;
    readsize = SIPP_MAX_MSG_SIZE;

    struct socketbuf *socketbuf;
    char *buffer;
    int ret = -1;
    /* Where should we start sending packets to, ideally we should begin to parse
     *      * the Via, Contact, and Route headers.  But for now SIPp always sends to the
     *           * host specified on the command line; or for UAS mode to the address that
     *                * sent the last message. */
    sipp_socklen_t addrlen = sizeof(struct sockaddr_storage);

    buffer = (char *)malloc(readsize);
    if (!buffer) {
        LOG("Could not allocate memory for read!");

    }
    socketbuf = alloc_socketbuf(buffer, readsize, NO_COPY, NULL);

    switch(sock->ss_transport) {
        case T_TCP:
        case T_UDP:
            ret = recvfrom(sock->ss_fd, buffer, readsize, 0, (struct sockaddr *)&socketbuf->addr,  &addrlen);
            break;

    }
    if (ret <= 0) {
        free_socketbuf(socketbuf);
        return ret;

    }
    socketbuf->len = ret;
    buffer_read(sock, socketbuf);

    return ret;

}


/*************************** I/O functions ***************************/

/* Allocate a socket buffer. */
struct socketbuf *alloc_socketbuf(char *buffer, size_t size, int copy, struct sockaddr_storage *dest)
{
    struct socketbuf *socketbuf;

    socketbuf = (struct socketbuf *)malloc(sizeof(struct socketbuf));
    if (!socketbuf) {
        LOG("Could not allocate socket buffer!\n");

    }
    memset(socketbuf, 0, sizeof(struct socketbuf));
    if (copy) {
        socketbuf->buf = (char *)malloc(size);
        if (!socketbuf->buf) {
            LOG("Could not allocate socket buffer data!\n");

        }
        memcpy(socketbuf->buf, buffer, size);

    } else {
        socketbuf->buf = buffer;

    }
    socketbuf->len = size;
    socketbuf->offset = 0;
    if (dest) {
        memcpy(&socketbuf->addr, dest, sizeof(*dest));

    }
    socketbuf->next = NULL;

    return socketbuf;

}

/* Free a poll buffer. */
void free_socketbuf(struct socketbuf *socketbuf)
{
    free(socketbuf->buf);
    free(socketbuf);
}

int  local_port=0;
char local_ip[40];
char local_ip_escaped[42];
char hostname[80];
struct addrinfo *local_addr_storage;
struct sockaddr_storage local_sockaddr;


socklen_t socklen_from_addr(const struct sockaddr_storage* ss) {
    if (ss->ss_family == AF_INET) {
        return sizeof(struct sockaddr_in);
    } else if (ss->ss_family == AF_INET6) {
        return sizeof(struct sockaddr_in6);
    }
    return 0;
}
LOCAL char* get_inet_address(const struct sockaddr_storage* addr, char* dst, int len)
{
    if (getnameinfo((struct sockaddr*)addr, socklen_from_addr(addr),
                dst, len, NULL, 0, NI_NUMERICHOST) != 0) {
        snprintf(dst, len, "addr not supported");
    }
    return dst;
}
int open_connections()
{
    int status=0;
    local_port = 0;

    if (gethostname(hostname, 64) != 0) {
        LOG("Can't get local hostname in 'gethostname(hostname, 64)'");
    }

    {
        char            * local_host = NULL;
        struct addrinfo * local_addr;
        struct addrinfo   hints;

        memset(local_ip, 0, sizeof(local_ip));
        local_host = (char *)hostname;
        memset((char*)&hints, 0, sizeof(hints));
        hints.ai_flags  = AI_PASSIVE;
        hints.ai_family = AF_UNSPEC;

        /* Resolving local IP */
        if(getaddrinfo(local_host, NULL, &hints, &local_addr) != 0){
            LOG("Can't get local IP address in getaddrinfo, local_host='%s'",
                    local_host);
        }
        // store local addr info for rsa option
        getaddrinfo(local_host, NULL, &hints, &local_addr_storage);

        memset(&local_sockaddr, 0, sizeof(struct sockaddr_storage));
        local_sockaddr.ss_family = local_addr->ai_addr->sa_family;

        if (!strlen(local_ip)) {
            get_inet_address((struct sockaddr_storage*)local_addr->ai_addr,
                    local_ip, sizeof(local_ip));
        } else {
            memcpy(&local_sockaddr,
                    local_addr->ai_addr,
                    local_addr->ai_addrlen);
        }
        freeaddrinfo(local_addr);

        strcpy(local_ip_escaped, local_ip);
    }

    /* Creating and binding the local socket */
    if ((main_socket = new_sipp_socket(transport)) == NULL) {
        LOG("Unable to get the local socket\n");
    }


    return status;
}


LOCAL SIPpSocket* sipp_allocate_socket(int transport, int fd) {
    SIPpSocket* p = (struct SIPpSocket*)malloc(sizeof(struct SIPpSocket));

    return Initialize_SIPpSocket( p, transport, fd);
}

SIPpSocket* Initialize_SIPpSocket(SIPpSocket* p, int transport, int fd)
{
    p->ss_transport = transport;
    p->ss_fd = fd;
    p->ss_count = 1;
    p->ss_changed_dest = false;
    p->ss_congested = false;
    p->ss_invalid = false;
    p->ss_in = NULL;
    p->ss_out = NULL;
    p->ss_msglen = 0;

    /* Initialize all sockets with our destination address. */
    memcpy(&(p->ss_dest), &remote_sockaddr, sizeof(p->ss_dest));
    /* Store this socket in the tables. */
    p->ss_pollidx = pollnfds++;
    sockets[p->ss_pollidx] = p;
    epollfiles[p->ss_pollidx].data.u32 = p->ss_pollidx;
    epollfiles[p->ss_pollidx].events   = EPOLLIN;
    int rc = epoll_ctl(epollfd, EPOLL_CTL_ADD, p->ss_fd, &epollfiles[p->ss_pollidx]);
    if (rc == -1) {
        if (errno == EPERM) {
            // Attempted to use epoll on a file that does not support
            // it - this may happen legitimately when stdin/stdout is
            // redirected to /dev/null, so don't warn
        } else {
            LOG("Failed to add FD to epoll\n");
        }
    }
}

// Have we read a message from this socket?
int message_ready(SIPpSocket* sock)
{
    return sock->ss_msglen > 0;
}

SIPpSocket *new_sipp_socket(int transport) {
    SIPpSocket *ret;
    int fd = socket_fd(transport);

    ret = sipp_allocate_socket(transport, fd);
    if (!ret) {
        close(fd);
        LOG("Could not allocate new socket structure!\n");
    }
    return ret;
}

LOCAL int socket_fd(int transport)
{
    int socket_type = -1;
    int protocol = 0;
    int fd;

    switch(transport) {
        case T_UDP:
            socket_type = SOCK_DGRAM;
            protocol = IPPROTO_UDP;
            break;
        case T_TLS:
            // implement in future
        case T_TCP:
            socket_type = SOCK_STREAM;
            break;
    }
    if ((fd = socket(AF_INET, socket_type, protocol))== -1) {
        LOG("Unable to get a socket (3)\n");
    }

    return fd;
}

int buff_size = 65535;
void sipp_customize_socket(SIPpSocket *socket)
{
    unsigned int buffsize = buff_size;
    /* Allows fast TCP reuse of the socket */
    if (socket->ss_transport == T_TCP) {
        int sock_opt = 1;

        if (setsockopt(socket->ss_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&sock_opt,
                    sizeof (sock_opt)) == -1) {
            LOG("setsockopt(SO_REUSEADDR) failed");
        }


        if (setsockopt(socket->ss_fd, SOL_TCP, TCP_NODELAY, (void *)&sock_opt,
                    sizeof (sock_opt)) == -1) {
            {
                LOG("setsockopt(TCP_NODELAY) failed");
            }
        }

        {
            struct linger linger;

            linger.l_onoff = 1;
            linger.l_linger = 1;
            if (setsockopt (socket->ss_fd, SOL_SOCKET, SO_LINGER,
                        &linger, sizeof (linger)) < 0) {
                LOG("Unable to set SO_LINGER option");
            }
        }
    }

    /* Increase buffer sizes for this sockets */
    if (setsockopt(socket->ss_fd,
                SOL_SOCKET,
                SO_SNDBUF,
                &buffsize,
                sizeof(buffsize))) {
        LOG("Unable to set socket sndbuf");
    }

    buffsize = buff_size;
    if (setsockopt(socket->ss_fd,
                SOL_SOCKET,
                SO_RCVBUF,
                &buffsize,
                sizeof(buffsize))) {
        LOG("Unable to set socket rcvbuf");
    }
}

ssize_t read_message(SIPpSocket *sock, char *buf, size_t len, struct sockaddr_storage *src)
{
    size_t avail;
    int msg_len;

    if (!sock->ss_msglen)
        return 0;
    if (sock->ss_msglen > len)
        LOG("There is a message waiting in sockfd(%d) that is bigger (%zu bytes) than the read size.",
                sock->ss_fd, sock->ss_msglen);

    len = sock->ss_msglen;

    avail = sock->ss_in->len - sock->ss_in->offset;
    if (avail > len) {
        avail = len;
    }

    memcpy(buf, sock->ss_in->buf + sock->ss_in->offset, avail);
    memcpy(src, &(sock->ss_in->addr), sizeof(sock->ss_in->addr));

    /* Update our buffer and return value. */
    buf[avail] = '\0';

    sock->ss_in->offset += avail;

    /* Have we emptied the buffer? */
    if (sock->ss_in->offset == sock->ss_in->len) {
        struct socketbuf *next = sock->ss_in->next;
        free_socketbuf(sock->ss_in);
        sock->ss_in = next;
    }

    if (msg_len = check_for_message(sock)) {
        sock->ss_msglen = msg_len;
    } else {
        sock->ss_msglen = 0;
        pending_messages--;
    }
    return avail;

}
/* This socket is congested, mark it as such and add it to the poll files. */
LOCAL int enter_congestion(SIPpSocket *sock, int again)
{
    sock->ss_congested = true;

    LOG("Problem %s on socket  %d and poll_idx  is %d \n",
            again == EWOULDBLOCK ? "EWOULDBLOCK" : "EAGAIN",
            sock->ss_fd, sock->ss_pollidx);

    epollfiles[sock->ss_pollidx].events |= EPOLLOUT;
    int rc = epoll_ctl(epollfd, EPOLL_CTL_MOD, sock->ss_fd, &epollfiles[sock->ss_pollidx]);
    if (rc == -1) {
        LOG("Failed to set EPOLLOUT");

    }
    return -1;
}

int write_error(SIPpSocket *sock, int ret)
{
    const char *errstring = strerror(errno);

#ifndef EAGAIN
    int again = (errno == EWOULDBLOCK) ? errno : 0;
#else
    int again = ((errno == EAGAIN) || (errno == EWOULDBLOCK)) ? errno : 0;

    /* Scrub away EAGAIN from the rest of the code. */
    if (errno == EAGAIN) {
        errno = EWOULDBLOCK;

    }
#endif

    if (again) {
        return enter_congestion(sock, again);

    }

    if (sock->ss_transport == T_TCP ) {
        abort1(sock);
        if (reconnect_allowed()) {
            LOG("Broken pipe on TCP connection, remote peer "
                    "probably closed the socket");

        } else {
            LOG("Broken pipe on TCP connection, remote peer "
                    "probably closed the socket");

        }
        return -1;

    }
    LOG("Unable to send %s message: %s", TRANSPORT_TO_STRING(sock->ss_transport), errstring);
    return -1;

}
void abort1(SIPpSocket *sock) {
    /* Disable linger - we'll send a RST when we close. */
    struct linger flush;
    flush.l_onoff = 1;
    flush.l_linger = 0;
    setsockopt(sock->ss_fd, SOL_SOCKET, SO_LINGER, &flush, sizeof(flush));

    /* Mark the socket as non-blocking.  It's not clear whether this is required but can't hurt. */
    int flags = fcntl(sock->ss_fd, F_GETFL, 0);
    fcntl(sock->ss_fd, F_SETFL, flags | O_NONBLOCK);

    int count = --sock->ss_count;
    if (count == 0) {
        invalidate(sock);
        free(sock);
    } else {
        sock->ss_fd = -1;
    }
}

void invalidate(SIPpSocket *sock)
{
    unsigned pollidx;

    if (sock->ss_invalid) {
        return;

    }
    /* In some error conditions, the socket FD has already been closed - if it hasn't, do so now. */
    if (sock->ss_fd != -1) {
        int rc = epoll_ctl(epollfd, EPOLL_CTL_DEL, sock->ss_fd, NULL);
        if (rc == -1) {
            LOG("Failed to delete FD from epoll");

        }

        if (sock->ss_transport != T_UDP) {
            if (shutdown(sock->ss_fd, SHUT_RDWR) < 0) {
                LOG("Failed to shutdown socket %d", sock->ss_fd);

            }

        }

        if (close(sock->ss_fd) < 0) {
            LOG("Failed to close socket %d", sock->ss_fd);

        }
        else {
            sock->ss_fd = -1;

        }
        abort1(sock);

    }

    if ((pollidx = sock->ss_pollidx) >= pollnfds) {
        LOG("Pollset error: index %d is greater than number of fds %d!", pollidx, pollnfds);

    }

    sock->ss_invalid = true;
    sock->ss_pollidx = -1;

    /* Adds call sockets in the array */
    assert(pollnfds > 0);

    pollnfds--;
    if (pollidx < pollnfds) {
        epollfiles[pollidx] = epollfiles[pollnfds];
        epollfiles[pollidx].data.u32 = pollidx;
        if (sockets[pollnfds]->ss_fd != -1) {
            int rc = epoll_ctl(epollfd, EPOLL_CTL_MOD, sockets[pollnfds]->ss_fd, &epollfiles[pollidx]);
            if ((rc == -1) && (errno != EPERM)) {
                // Ignore "Operation not supported"  errors -
                // otherwise we get log spam when redirecting stdout
                // to /dev/null
                LOG("Failed to update FD within epoll");
            }
        }
    }

    sockets[pollidx] = sockets[pollnfds];
    sockets[pollidx]->ss_pollidx = pollidx;
    sockets[pollnfds] = NULL;

    if (sock->ss_msglen) {
        pending_messages--;
    }
}

bool reconnect_allowed()
{
    if(reset_number == -1){
        return true;
    }
    return (reset_number > 0);
}

void process_message(SIPpSocket *socket, char *msg, ssize_t msg_size, struct sockaddr_storage *src)
{
        // TRACE_MSG(" msg_size %d and pollset_index is %d \n", msg_size, pollset_index));
}
int check_for_message(SIPpSocket *sock)
{
    return 1;
}
int main()
{
    open_connections();
    LOG("local ip is %s\n", local_ip);
    return 1;
}
