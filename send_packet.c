#include "send_packet.h"
#include <sys/time.h>
#include "common.h"
#include "prepare_pcap.h"
#include <errno.h>
#include <netinet/udp.h>
#include <pthread.h>

#define PCAP_MAXPACKET 1500

int media_ip_is_ipv6 = 0;

/* Saft threaded version */
void do_sleep(struct timeval *, struct timeval *,
              struct timeval *, struct timeval *);
void send_packets_cleanup(void *arg)
{
    int * sock = (int *) arg;

    /* Close send socket */
    close(*sock);

}

void send_packets_pcap_cleanup(void* arg)
{
    play_args_t* play_args = arg;

    if (play_args->free_pcap_when_done) {
        free(play_args->pcap);
        play_args->pcap = NULL;

    }
}

int send_packets(play_args_t* play_args)
{
    pthread_cleanup_push(send_packets_pcap_cleanup, ((void*)play_args));

    int ret, sock, port_diff;
    pcap_pkt *pkt_index, *pkt_max;
    uint16_t *from_port, *to_port;
    struct timeval didsleep = {0, 0};
    struct timeval start = {0, 0};
    struct timeval last = {0, 0};
    pcap_pkts *pkts = play_args->pcap;
    /* to and from are pointers in case play-args (call sticky) gets modified! */
    struct sockaddr_storage *to = &(play_args->to);
    struct sockaddr_storage *from = &(play_args->from);
    struct udphdr *udp;
    struct sockaddr_in6 to6, from6;
    char buffer[PCAP_MAXPACKET];
    int temp_sum;
    socklen_t len;

#ifndef MSG_DONTWAIT
    int fd_flags;
#endif

    if(media_ip_is_ipv6){
        sock = socket(PF_INET6, SOCK_RAW, IPPROTO_UDP);
        if(sock < 0){
            printf("Can't create ras IPv6 socket (need to run as root?): %s", strerror(errno));
        }
        from_port = &(((struct sockaddr_in6 *)from)->sin6_port);
        len = sizeof(struct sockaddr_in6);
        to_port = &(((struct sockaddr_in6 *)to)->sin6_port);
    } else {
        sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
        from_port = &(((struct sockaddr_in *)from)->sin_port);
        len = sizeof(struct sockaddr_in);
        to_port = &(((struct sockaddr_in *)to)->sin_port);
        if(sock < 0){
            printf("Can't create ras IPv4 socket (need to run as root?): %s", strerror(errno));
            return ret;
        }
    }

    if(ret = bind(sock, (struct sockaddr *)from, len)){
        printf("Can't bind media ras socket");
        return ret;
    }

#ifndef MSG_DONTWAIT
    fd_flags = fcntl(sock, F_GETFL, NULL);
    fd_flags |= O_NONBLOCK;
    fcntl(sock, F_SETFL, fd_flags);
#endif
    udp = (struct udphdr *)buffer;

    pkt_index = pkts->pkt;
    pkt_max = pkts->max;

    if(media_ip_is_ipv6){
        memset(&to6, 0, sizeof(to6));
        memset(&from6, 0, sizeof(from6));
        to6.sin6_family = AF_INET6;
        from6.sin6_family = AF_INET6;
        memcpy(&(to6.sin6_addr.s6_addr), &(((struct sockaddr_in6 *)(void *) to)->sin6_addr.s6_addr), sizeof(to6.sin6_addr.s6_addr));
        memcpy(&(from6.sin6_addr.s6_addr), &(((struct sockaddr_in6 *)(void *)from)->sin6_addr.s6_addr), sizeof(from6.sin6_addr.s6_addr));
    }

    /* Ensure the sender socket is closed when the thread exits - this
     * allows the thread to be cancelled cleanly.
     */
    pthread_cleanup_push(send_packets_cleanup, ((void *) &sock));

    while(pkt_index < pkt_max){
        memcpy(udp, pkt_index->data, pkt_index->pktlen);
        port_diff = ntohs(udp->uh_dport) - pkts->base;
        /* modify UDP ports */
        udp->uh_sport = htons(port_diff + ntohs(*from_port));
        udp->uh_dport = htons(port_diff + ntohs(*to_port));

        printf("source port is %d, destination port is %d\n",port_diff + ntohs(*from_port), port_diff + ntohs(*to_port));

        if (!media_ip_is_ipv6) {
            temp_sum = checksum_carry(
                    pkt_index->partial_check +
                    check((uint16_t *) &(((struct sockaddr_in *)(void *) from)->sin_addr.s_addr), 4) +
                    check((uint16_t *) &(((struct sockaddr_in *)(void *) to)->sin_addr.s_addr), 4) +
                    check((uint16_t *) &udp->uh_sport, 4)
                    );

        } else {
            temp_sum = checksum_carry(
                    pkt_index->partial_check +
                    check((uint16_t *) &(from6.sin6_addr.s6_addr), 16) +
                    check((uint16_t *) &(to6.sin6_addr.s6_addr), 16) +
                    check((uint16_t *) &udp->uh_sport, 4)
                    );

        }
#if !defined(_HPUX_LI) && defined(__HPUX)
        udp->uh_sum = (temp_sum>>16)+((temp_sum & 0xffff)<<16);
#else
        udp->uh_sum = temp_sum;
#endif

        do_sleep ((struct timeval *) &pkt_index->ts, &last, &didsleep,
                &start);
#ifdef MSG_DONTWAIT
        if (!media_ip_is_ipv6) {
            ret = sendto(sock, buffer, pkt_index->pktlen, MSG_DONTWAIT,
                    (struct sockaddr *)to, sizeof(struct sockaddr_in));

        } else {
            ret = sendto(sock, buffer, pkt_index->pktlen, MSG_DONTWAIT,
                    (struct sockaddr *)&to6, sizeof(struct sockaddr_in6));

        }
#else
        if (!media_ip_is_ipv6) {
            ret = sendto(sock, buffer, pkt_index->pktlen, 0,
                    (struct sockaddr *)to, sizeof(struct sockaddr_in));

        } else {
            ret = sendto(sock, buffer, pkt_index->pktlen, 0,
                    (struct sockaddr *)&to6, sizeof(struct sockaddr_in6));

        }
#endif
        if (ret < 0) {
            close(sock);
            printf("send_packets.c: sendto failed with error: %s", strerror(errno));
            return( -1 );

        }

        //rtp_pckts_pcap++;
        //rtp_bytes_pcap += pkt_index->pktlen - sizeof(*udp);
        memcpy (&last, &(pkt_index->ts), sizeof(struct timeval));
        pkt_index++;
    }
    
    /* Closing the socket is handled by pthread_cleanup_push()/pthread_cleanup_pop() */
    pthread_cleanup_pop(1);
    pthread_cleanup_pop(1);
    return 0;
}


/*
 * Given the timestamp on the current packet and the last packet send,
 * calculate the appropriate amount of time to sleep and do so.
 */
void do_sleep(struct timeval* time, struct timeval* last,
        struct timeval* didsleep, struct timeval* start)
{
    struct timeval nap, now, delta;
    struct timespec sleep;

    if(gettimeofday(&now, NULL) < 0){
        printf("Error gettimeofday: %s\n", strerror(errno));
    }

    /* First time through for this file */
    if(!timerisset(last)){
        *start = now;
        timerclear(&delta);
        timerclear(didsleep);
    }else{
        timersub(&now, start, &delta);
    }

    if(timerisset(last) && timercmp(time, last, >)){
        timersub(time, last, &nap);
    }else{
        /*
         * Don't sleep if this is our first packet, or if the 
         * this packet appears to have been sent before the 
         * last packet.
         */
        timerclear(&nap);
    }

    timeradd(didsleep, &nap, didsleep);

    if(timercmp(didsleep, &delta, >)){
        timersub(didsleep, &delta, &nap);

        sleep.tv_sec = nap.tv_sec;
        sleep.tv_nsec = nap.tv_usec * 1000; /* convert ms to ns */

        while((nanosleep(&sleep, &sleep) == -1)&& (errno == -EINTR)); 
    }
}
