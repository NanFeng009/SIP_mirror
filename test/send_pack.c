#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <error.h>
#include <sys/ioctl.h>

#include "send_pack.h"
#include "utility.h"


#define FIN 0
#define SYN 1
#define RST 2
#define PSH 3
#define ACK 4
#define URG 5
#define ECE 6
#define CWR 7

#define TCP_HDRLEN_NOP 20

/* variable for this module */
static int sd;


char *src_ip, *dst_ip;

int send_pack_init( char * src, char * dst, char * card)
{

    int rc;
    //Source IPv4 address
    src_ip = strdup( src );
    //destination IPv4 address
    dst_ip = strdup( dst );

    rc = prepare_sock( card );
    if ( rc == EXIT_FAILURE ){
        LOG("Unable to raw socket!");
        return (EXIT_FAILURE);
    }
    return (EXIT_SUCCESS) ;
}

//int main(int argc, char **argv)
//{
//    int datalen;
//    char data[4];
//    init_send( "10.74.20.189", "10.74.39.101");
//    prepare_sock("eth0");
//
//    datalen = 0;
//    /* data[0] = 'T';
//       data[1] = 'e';
//       data[2] = 's';
//       data[3] = 't';
//       */
//    send_pack(data, datalen, IPPROTO_TCP);
//
//    deinit_send();
//}

void deinit_send()
{

    // Close socket descriptor.
    if ( sd > 0 )
        close (sd);
    else
        LOG("socket = %d is already closed!", sd);

    // free the source ip
    if (src_ip )
        free( src_ip );

    // free the dst ip
    if (dst_ip )
        free( dst_ip );

}

int  prepare_sock(char * card)
{
    const int on = 1;
    struct ifreq ifr;

    //Get card index
    get_mac_index( card, &ifr );


    // Submit request for a raw socket descriptor.
    if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror ("socket() failed ");
        exit (EXIT_FAILURE);
    }

    // Set flag so socket expects us to provide IPv4 header.
    if (setsockopt (sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on)) < 0) {
        perror ("setsockopt() failed to set IP_HDRINCL ");
        exit (EXIT_FAILURE);
    }

    // Bind socket to interface index.
    if (setsockopt (sd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof (ifr)) < 0) {
        perror ("setsockopt() failed to bind to interface ");
        exit (EXIT_FAILURE);
    }

    return (EXIT_SUCCESS) ;
}

void send_pack(uint8_t * data, int datalen, uint8_t ip_p)
{
    struct ip iphdr;        // IP header
    struct udphdr udphdr;   // UDP header
    struct tcphdr tcphdr;   // TCP header
    uint8_t *packet; //
    struct sockaddr_in sin;

    // sanity check
    if ( data == NULL || datalen < 0 ){
        LOG("data is NULL or datalen < 0"); 
    }
    // Allocate memory for various arrays.
    packet = allocate_ustrmem(IP_MAXPACKET);

    // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
    // For that, we need to specify a destination for the kernel in order for it
    // to decide where to send the raw datagram. We fill in a struct in_addr with
    // the desired destination IP address, and pass this structure to the sendto() function.
    memset (&sin, 0, sizeof (struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iphdr.ip_dst.s_addr;



    if (ip_p == IPPROTO_UDP){
        //  1st - IPv4 header 
        fabricate_iphdr(&iphdr, IPPROTO_UDP, datalen);
        // 2nd - UDP header
        fabricate_udphdr(&udphdr, &iphdr, data, datalen);
        // First part is an IPv4 header.
        memcpy (packet, &iphdr, IP4_HDRLEN * sizeof (uint8_t));
        // Next part of packet is upper layer protocol header.
        memcpy ((packet + IP4_HDRLEN), &udphdr, UDP_HDRLEN * sizeof (uint8_t));
        // Finally, add the UDP data.
        memcpy (packet + IP4_HDRLEN + UDP_HDRLEN, data, datalen * sizeof (uint8_t));

        // Send packet.
        if (sendto (sd, packet, IP4_HDRLEN + UDP_HDRLEN + datalen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0){
            perror ("tcp sendto() failed ");
            exit (EXIT_FAILURE);
        }
    } else if (ip_p == IPPROTO_TCP){
        //  1st - IPv4 header
        fabricate_iphdr(&iphdr, IPPROTO_TCP, datalen);
        // 2nd - TCP header
        fabricate_tcphdr(&tcphdr, &iphdr, data, datalen);
        // Prepare packet.
        // First part is an IPv4 header.
        memcpy (packet, &iphdr, IP4_HDRLEN * sizeof (uint8_t));
        // Next part of packet is upper layer protocol header.
        memcpy ((packet + IP4_HDRLEN), &tcphdr, TCP_HDRLEN_NOP * sizeof (uint8_t));
        // Finally, add the TCP data.
        memcpy (packet + IP4_HDRLEN + TCP_HDRLEN_NOP, data, datalen * sizeof (uint8_t));


        // Send packet.
        if (sendto (sd, packet, IP4_HDRLEN + TCP_HDRLEN_NOP + datalen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0) {
            perror ("udp sendto() failed ");
            exit (EXIT_FAILURE);
        }
    }



    // Free allocated memory.
    free (packet);
    return ;
}

int send_pack_direct(uint8_t * data, int datalen )
{
    uint8_t *packet; //
    struct sockaddr_in sin;


    // sanity check
    if ( data == NULL || datalen < 0 ){
        LOG("data is NULL or datalen < 0"); 
    }
    // Allocate memory for various arrays.
    packet = allocate_ustrmem(IP_MAXPACKET);
    memcpy((void *)packet, (const void *)data, datalen);

    // The kernel is going to prepare layer 2 information (ethernet frame header) for us.
    // For that, we need to specify a destination for the kernel in order for it
    // to decide where to send the raw datagram. We fill in a struct in_addr with
    // the desired destination IP address, and pass this structure to the sendto() function.
    memset (&sin, 0, sizeof (struct sockaddr_in));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ipkey.ip_dst.s_addr;

    // Send packet.
    if (sendto (sd, packet, datalen, 0, (struct sockaddr *) &sin, sizeof (struct sockaddr)) < 0){
        perror ("sendto() failed ");
        exit (EXIT_FAILURE);
    }
    
    // Free allocated memory.
    free (packet);
    return (EXIT_SUCCESS) ;
}

// Allocate memory for an array of chars.
char * allocate_strmem (int len)
{
    void *tmp;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (char *) malloc (len * sizeof (char));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (char));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
        exit (EXIT_FAILURE);
    }
}

// Allocate memory for an array of unsigned chars.
uint8_t * allocate_ustrmem (int len)
{
    void *tmp;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (uint8_t));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
        exit (EXIT_FAILURE);
    }
}

// Allocate memory for an array of ints.
int * allocate_intmem (int len)
{
    void *tmp;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = (int *) malloc (len * sizeof (int));
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (int));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
        exit (EXIT_FAILURE);
    }
}


void fabricate_tcphdr(struct tcphdr *tcphdr, struct ip *iphdr, uint8_t *data, int datalen)
{
    int i;
    int *tcp_flags;
    tcp_flags = allocate_intmem(8);

    //TCP header
    // Source port number (16 bits)
    tcphdr->th_sport = htons (60);
    // Destination port number (16 bits)
    tcphdr->th_dport = htons (80);
    // Sequence number (32 bits)
    tcphdr->th_seq = htonl (1);
    // Acknowledgement number (32 bits): 0 in first packet of SYN/ACK process
    tcphdr->th_ack = htonl (1);
    // Reserved (4 bits): should be 0
    tcphdr->th_x2 = 0;
    // Data offset (4 bits): size of TCP header in 32-bit words
    tcphdr->th_off = TCP_HDRLEN_NOP / 4;
    // Flags (8 bits)
    // FIN flag (1 bit)
    tcp_flags[FIN] = 0;
    // SYN flag (1 bit): set to 1
    tcp_flags[SYN] = 0;
    // RST flag (1 bit)
    tcp_flags[RST] = 0;
    // PSH flag (1 bit)
    tcp_flags[PSH] = 0;
    // ACK flag (1 bit)
    tcp_flags[ACK] = 0;
    if ( datalen == 0 ){
        LOG("datalen is 0 send an Ack to remote");
        tcp_flags[ACK] = 1;
    }
    // URG flag (1 bit)
    tcp_flags[URG] = 0;
    // ECE flag (1 bit)
    tcp_flags[ECE] = 0;
    // CWR flag (1 bit)
    tcp_flags[CWR] = 0;
    tcphdr->th_flags = 0;
    for (i=0; i<8; i++) {
        tcphdr->th_flags += (tcp_flags[i] << i);
    }
    // Window size (16 bits)
    tcphdr->th_win = htons (65535);
    // Urgent pointer (16 bits): 0 (only valid if URG flag is set)
    tcphdr->th_urp = htons (0);
    // TCP checksum (16 bits)
    tcphdr->th_sum = tcp4_checksum (iphdr, tcphdr, data, datalen);
}

void fabricate_udphdr(struct udphdr *udphdr, struct ip *iphdr, uint8_t *data, int datalen)
{

    // UDP header
    // Source port number (16 bits): pick a number
    udphdr->uh_sport = htons (4950);
    // Destination port number (16 bits): pick a number
    udphdr->uh_dport = htons (4950);
    // Length of UDP datagram (16 bits): UDP header + UDP data
    udphdr->uh_ulen = htons (UDP_HDRLEN + datalen);
    // UDP checksum (16 bits)
    udphdr->uh_sum = udp4_checksum (iphdr, udphdr, data, datalen);
}

void fabricate_iphdr(struct ip *iphdr, uint8_t ip_p, int datalen)
{

    int *ip_flags;
    int status;
    ip_flags = allocate_intmem(4);
    // IPv4 header
    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
    iphdr->ip_hl = IP4_HDRLEN / sizeof (uint32_t);
    // Internet Protocol version (4 bits): IPv4
    iphdr->ip_v = 4;
    // Type of service (8 bits)
    iphdr->ip_tos = 0;
    // Total length of datagram (16 bits): IP header + UDP header + datalen
    //iphdr->ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);
    iphdr->ip_len = htons (IP4_HDRLEN + TCP_HDRLEN_NOP + datalen);
    // ID sequence number (16 bits): unused, since single datagram
    iphdr->ip_id = htons (0);
    // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
    // Zero (1 bit)
    ip_flags[0] = 0;
    // Do not fragment flag (1 bit)
    ip_flags[1] = 0;
    // More fragments following flag (1 bit)
    ip_flags[2] = 0;
    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;
    iphdr->ip_off = htons ((ip_flags[0] << 15)
            + (ip_flags[1] << 14)
            + (ip_flags[2] << 13)
            +  ip_flags[3]);
    // Time-to-Live (8 bits): default to maximum value
    iphdr->ip_ttl = 205;
    // Transport layer protocol (8 bits): 17 for UDP
    iphdr->ip_p = ip_p;
    // Source IPv4 address (32 bits)
    if ((status = inet_pton (AF_INET, src_ip, &(iphdr->ip_src))) != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }
    // Destination IPv4 address (32 bits)
    if ((status = inet_pton (AF_INET, dst_ip, &(iphdr->ip_dst))) != 1) {
        fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
        exit (EXIT_FAILURE);
    }
    // IPv4 header checksum (16 bits): set to 0 when calculating checksum
    iphdr->ip_sum = 0;
    iphdr->ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

    free (ip_flags);
    return;
}


// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t checksum (uint16_t *addr, int len)
{
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t *) addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t tcp4_checksum (struct ip *iphdr, struct tcphdr *tcphdr, uint8_t *payload, int payloadlen)
{
    uint16_t svalue;
    char buf[IP_MAXPACKET], cvalue;
    char *ptr;
    int chksumlen = 0;

    // ptr points to beginning of buffer buf
    ptr = &buf[0];

    // Copy source IP address into buf (32 bits)
    memcpy (ptr, &(iphdr->ip_src.s_addr), sizeof (iphdr->ip_src.s_addr));
    ptr += sizeof (iphdr->ip_src.s_addr);
    chksumlen += sizeof (iphdr->ip_src.s_addr);

    // Copy destination IP address into buf (32 bits)
    memcpy (ptr, &(iphdr->ip_dst.s_addr), sizeof (iphdr->ip_dst.s_addr));
    ptr += sizeof (iphdr->ip_dst.s_addr);
    chksumlen += sizeof (iphdr->ip_dst.s_addr);

    // Copy zero field to buf (8 bits)
    *ptr = 0; ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy (ptr, &(iphdr->ip_p), sizeof (iphdr->ip_p));
    ptr += sizeof (iphdr->ip_p);
    chksumlen += sizeof (iphdr->ip_p);

    // Copy TCP header length (16 bits) + data len to buf 
    svalue = htons (sizeof(struct tcphdr) + payloadlen);
    memcpy (ptr, &svalue, sizeof (svalue));
    ptr += sizeof (svalue);
    chksumlen += sizeof (svalue);

    // Copy TCP source port to buf (16 bits)
    memcpy (ptr, &(tcphdr->th_sport), sizeof (tcphdr->th_sport));
    ptr += sizeof (tcphdr->th_sport);
    chksumlen += sizeof (tcphdr->th_sport);

    // Copy TCP destination port to buf (16 bits)
    memcpy (ptr, &(tcphdr->th_dport), sizeof (tcphdr->th_dport));
    ptr += sizeof (tcphdr->th_dport);
    chksumlen += sizeof (tcphdr->th_dport);

    // Copy sequence number to buf (32 bits)
    memcpy (ptr, &(tcphdr->th_seq), sizeof (tcphdr->th_seq));
    ptr += sizeof (tcphdr->th_seq);
    chksumlen += sizeof (tcphdr->th_seq);

    // Copy acknowledgement number to buf (32 bits)
    memcpy (ptr, &(tcphdr->th_ack), sizeof (tcphdr->th_ack));
    ptr += sizeof (tcphdr->th_ack);
    chksumlen += sizeof (tcphdr->th_ack);

    // Copy data offset to buf (4 bits) and
    // copy reserved bits to buf (4 bits)
    cvalue = (tcphdr->th_off << 4) + tcphdr->th_x2;
    memcpy (ptr, &cvalue, sizeof (cvalue));
    ptr += sizeof (cvalue);
    chksumlen += sizeof (cvalue);

    // Copy TCP flags to buf (8 bits)
    memcpy (ptr, &(tcphdr->th_flags), sizeof (tcphdr->th_flags));
    ptr += sizeof (tcphdr->th_flags);
    chksumlen += sizeof (tcphdr->th_flags);

    // Copy TCP window size to buf (16 bits)
    memcpy (ptr, &(tcphdr->th_win), sizeof (tcphdr->th_win));
    ptr += sizeof (tcphdr->th_win);
    chksumlen += sizeof (tcphdr->th_win);

    // Copy TCP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    // Copy urgent pointer to buf (16 bits)
    memcpy (ptr, &(tcphdr->th_urp), sizeof (tcphdr->th_urp));
    ptr += sizeof (tcphdr->th_urp);
    chksumlen += sizeof (tcphdr->th_urp);

    // Copy payload to buf
    if (payloadlen > 0) {
        memcpy (ptr, payload, payloadlen);
        ptr += payloadlen;
        chksumlen += payloadlen;
    }


    return checksum ((uint16_t *) buf, chksumlen);
}

// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t udp4_checksum (struct ip *iphdr, struct udphdr *udphdr, uint8_t *payload, int payloadlen)
{
    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0];  // ptr points to beginning of buffer buf

    // Copy source IP address into buf (32 bits)
    memcpy (ptr, &(iphdr->ip_src.s_addr), sizeof (iphdr->ip_src.s_addr));
    ptr += sizeof (iphdr->ip_src.s_addr);
    chksumlen += sizeof (iphdr->ip_src.s_addr);

    // Copy destination IP address into buf (32 bits)
    memcpy (ptr, &(iphdr->ip_dst.s_addr), sizeof (iphdr->ip_dst.s_addr));
    ptr += sizeof (iphdr->ip_dst.s_addr);
    chksumlen += sizeof (iphdr->ip_dst.s_addr);

    // Copy zero field to buf (8 bits)
    *ptr = 0; ptr++;
    chksumlen += 1;

    // Copy transport layer protocol to buf (8 bits)
    memcpy (ptr, &(iphdr->ip_p), sizeof (iphdr->ip_p));
    ptr += sizeof (iphdr->ip_p);
    chksumlen += sizeof (iphdr->ip_p);

    // Copy UDP length to buf (16 bits)
    memcpy (ptr, &(udphdr->uh_ulen), sizeof (udphdr->uh_ulen));
    ptr += sizeof (udphdr->uh_ulen);
    chksumlen += sizeof (udphdr->uh_ulen);

    // Copy UDP source port to buf (16 bits)
    memcpy (ptr, &(udphdr->uh_sport), sizeof (udphdr->uh_sport));
    ptr += sizeof (udphdr->uh_sport);
    chksumlen += sizeof (udphdr->uh_sport);

    // Copy UDP destination port to buf (16 bits)
    memcpy (ptr, &(udphdr->uh_dport), sizeof (udphdr->uh_dport));
    ptr += sizeof (udphdr->uh_dport);
    chksumlen += sizeof (udphdr->uh_dport);

    // Copy UDP length again to buf (16 bits)
    memcpy (ptr, &(udphdr->uh_ulen), sizeof (udphdr->uh_ulen));
    ptr += sizeof (udphdr->uh_ulen);
    chksumlen += sizeof (udphdr->uh_ulen);

    // Copy UDP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    // Copy payload to buf
    memcpy (ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i=0; i<payloadlen%2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum ((uint16_t *) buf, chksumlen);
}
