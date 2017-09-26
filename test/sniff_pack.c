#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()
#include <pcap.h>

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_TCP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/tcp.h>      // struct tcphdr
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <errno.h>            // errno, perror()


#include "sniff_pack.h"


char *dev = "eth0";
char *bpfFilter = "tcp port 5060 and src host 10.74.39.82"; /* filter expression */
int link_type;

typedef struct _ether_type_hdr {
    uint16_t ether_type; /* we only need the type, so we can determine, if the next header is IPv4 or IPv6 */
} ether_type_hdr;

#define ARP 0x0806
#define IP  0x0800
#define LLDP 0x88cc
#define CDP 0x2000
#define TLS 0x888e
#define IPV6 0x86dd


struct ipkeymap ipkey;
struct tcpkeymap tcpkey;


/*
 * Compile and apply the filter expression.
 */
int set_filter(pcap_t *handle,struct bpf_program *fp,const char*bpfFilter){
    if(bpfFilter != NULL) {
        printf("Packet Filter: %s\n", bpfFilter);
        if (pcap_compile(handle, fp, bpfFilter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", bpfFilter, pcap_geterr(handle));
            return(2);
        }
        if (pcap_setfilter(handle, fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", bpfFilter, pcap_geterr(handle));
            return(2);
        }
    }
    return 0;
}


pcap_t * open_and_init(const char *dev_name, const char *bpfFilter)
{
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    /* open capture device */
    if((handle= pcap_open_live(dev_name, BUFSIZ, 1, 100, errbuf))==NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev_name, errbuf);
        return NULL;
    }

    /* make sure we're capturing on an Ethernet device */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev_name);
        return NULL;
    }

    link_type = DLT_EN10MB;

    pcap_setdirection(handle,PCAP_D_IN);

    /* compile and apply the filter expression */
    if(set_filter(handle,&fp,bpfFilter)!=0){
        fprintf(stderr, "Error when setting filter to %s\n", dev_name);
        return NULL;

    }
    return handle;
}
int sniff_pack_init()
{
    pcap_t *handle_dev = NULL;
    uint16_t num_packets = 20;

    handle_dev = open_and_init(dev,bpfFilter);

    /* now we can set our callback function */
    pcap_loop(handle_dev, num_packets, got_packet, NULL);

    /* cleanup */
    pcap_close(handle_dev);
    return (EXIT_SUCCESS);

}


/*
 * dissect/print packet
 */
void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{

    static int count = 1;   /* pcaket counter */

    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */
    const struct sniff_udp *udp;            /* The UDP header */
    unsigned char *payload;                    /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_udp;
    int size_payload;

    ether_type_hdr * ethhdr;
    size_t ether_type_offset = 0;
    count++;


    /* define ethernet header */
    //ethernet = (struct sniff_ethernet*)(packet);
    ether_type_offset = get_ethertype_offset( link_type, packet);

    /* define/compute ip header offset */
    ethhdr = (ether_type_hdr *)(packet + ether_type_offset);
    switch(ntohs(ethhdr->ether_type)){
        case ARP:
        case IPV6:
        case TLS:
        case CDP:
        case LLDP:
            printf("Get the ether_type %hu packet, not support at current version\n",ntohs(ethhdr->ether_type));
            return;
        case IP:
            ip = (struct sniff_ip*)((uint8_t *)ethhdr + sizeof(*ethhdr)); 
            size_ip = IP_HL(ip)*4;
            if (size_ip < IP4_HDRLEN) {
                printf("   * Invalid IP header length: %u bytes\n", size_ip);
                return;
            }

            /* get the ip gloabl information */
            memcpy((void *)(&(ipkey.ip_id)), (const void *)(&(ip->ip_id)), sizeof(ipkey.ip_id));
            memcpy((void *)(&(ipkey.ip_src)), (const void *)(&(ip->ip_src)), sizeof(ipkey.ip_src));
            memcpy((void *)(&(ipkey.ip_dst)) , (const void *)(&(ip->ip_dst)), sizeof(ipkey.ip_dst));



            /* print source and destination IP addresses */
            // printf("From: %s\n", inet_ntoa(ip->ip_src));
            // printf("To: %s, size_ip is %d\n", inet_ntoa(ip->ip_dst),size_ip);
            /* determine protocol */
            switch(ip->ip_p) {
                case IPPROTO_TCP:
                    printf("       Protocol: TCP\n");
                    /*
                     *  OK, this packet is TCP.
                     */

                    /* define/compute tcp header offset */
                    tcp = (struct sniff_tcp*)((uint8_t *)ip + size_ip);
                    size_tcp = TH_OFF(tcp)*4;
                    if (size_tcp < TCP_HDRMIN) {
                        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                        return;
                    }
                    /*get the tcp gloable informaion */
                    memcpy((void *)(&(tcpkey.th_sport)), (const void *)(&(tcp->th_sport)), sizeof(tcpkey.th_sport));
                    memcpy((void *)(&(tcpkey.th_dport)), (const void *)(&(tcp->th_dport)), sizeof(tcpkey.th_dport));
                    memcpy((void *)(&(tcpkey.th_seq)), (const void *)(&(tcp->th_seq)), sizeof(tcpkey.th_seq));
                    memcpy((void *)(&(tcpkey.th_ack)), (const void *)(&(tcp->th_ack)), sizeof(tcpkey.th_ack));

                    //printf("Src port: %d, size_ip is %d\n", ntohs(tcp->th_sport), size_ip);
                    //printf("Dst port: %d, size_tcp is %d\n", ntohs(tcp->th_dport), size_tcp);

                    /* define/compute tcp payload (segment) offset */
                    payload = (u_char *)((uint8_t *)tcp + size_tcp);

                    /* compute tcp payload (segment) size */
                    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

                    break;
                case IPPROTO_UDP:
                    /*
                     *  OK, this packet is UDP.
                     */

                    /* define/compute udp header offset */
                    printf("   Protocol: UDP\n");
                    udp = (struct sniff_udp*)((uint8_t *)ip + size_ip);
                    size_udp = UDP_HDRLEN;
                    payload = (u_char *)((uint8_t *)udp + size_udp);


                    /* compute udp payload (segment) size */
                    size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
                    break;
                default:
                    printf("   Protocol: unknown\n");
                    return;
            } /* end switch for ip */
            /*
             * Print payload data; it might be binary, so don't just
             * treat it as a string.
             */
            if (size_payload > 0) {
                printf("   Payload (%d bytes):\n", size_payload);
                process_incoming(payload, size_payload);
                /* print to message for trouble shooting */
                //print_payload(payload, 20);
            } else {
                if(tcp->th_flags & TH_SYN) {
                    printf("get a SYN pcaket\n");
                } else if (tcp->th_flags & TH_ACK){
                    printf("get a ACK pcaket\n");
                    reply_ack();

                } else
                    printf("Got SYN or ACK packet?\n");
            }
            return;
        default:
            printf("Ignoring non IP{4,6} packet, got ether_type %hu!\n",
                    ntohs(ethhdr->ether_type));
    } /* end switch for eth */
    return;
}
