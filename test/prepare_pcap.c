#include <stdlib.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <string.h>
#include <stdio.h>
#include <pcap.h>
#include "prepare_pcap.h"
#include <stdint.h>
#include "utility.h"
#include <unistd.h>
#include "send_packet.h"

#define PCAP_MAXPACKET 1500
#define MAX_PATH                   250

typedef struct _ether_type_hdr {
    uint16_t ether_type; /* we only need the type, so we can determine, if the next header is IPv4 or IPv6 */
} ether_type_hdr;

uint16_t checksum_carry(int s)
{
    int s_c = (s >> 16) + (s & 0xffff);
    return (~(s_c + (s_c >> 16)) & 0xffff);
}

int check(uint16_t *buffer, int len)
{
    int sum;
    int i;
    sum = 0;

    for (i=0; i<(len&~1); i+= 2)
        sum += *buffer++;

    if (len & 1) {
        sum += htons((*(const uint8_t*)buffer) << 8);

    }
    return sum;

}

/* get octet offset to EtherType block in 802.11 frame
 *  */
size_t get_802_11_ethertype_offset(int link, const uint8_t* pktdata)
{
    size_t offset = 0;
    uint8_t frame_type = 0;     /* 2 bits */
    uint8_t frame_sub_type = 0; /* 4 bits */
    uint16_t frame_ctl_fld;     /* Frame Control Field */

    /* get RadioTap header length */
    if (link == DLT_IEEE802_11_RADIO) {
        uint16_t rdtap_hdr_len = 0;
        /* http://www.radiotap.org */
        /* rdtap_version[1], pad[1], rdtap_hdr_len[2], rdtap_flds[4] */
        memcpy(&rdtap_hdr_len, pktdata + 2, sizeof(rdtap_hdr_len));
        /* http://radiotap.org */
        /* all data fields in the radiotap header are to be specified
         *          * in little-endian order */
        rdtap_hdr_len = le16toh(rdtap_hdr_len);
        offset += rdtap_hdr_len;

    }

    memcpy(&frame_ctl_fld, pktdata + offset, sizeof(frame_ctl_fld));
    /* extract frame type and subtype from Frame Control Field */
    frame_type = frame_sub_type = frame_ctl_fld>>8;
    frame_type = frame_type>>2 & 0x03;
    frame_sub_type >>= 4;
    if (frame_type < 0x02) {
        /* Control or Management frame, so ignore it and try to get
         *          * EtherType from next one */
        offset = 0;

    } else if (frame_type == 0x02) {
        /* only Data frames carry the relevant payload and EtherType */
        if (frame_sub_type < 0x04
                || (frame_sub_type > 0x07 && frame_sub_type < 0x0c)) {
            /* MAC header of a Data frame is at least 24 and at most 36
             *              * octets long */
            size_t mac_hdr_len = 24;
            uint8_t llc_hdr[8] = { 0x00  };
            while (mac_hdr_len <= 36) {
                /* attempt to get Logical-Link Control header */
                /* dsap[1],ssap[1],ctrl_fld[1],org_code[3],ethertype[2] */
                memcpy(llc_hdr, pktdata + offset + mac_hdr_len, sizeof(llc_hdr));
                /* check if Logical-Link Control header */
                if (llc_hdr[0] == 0xaa && llc_hdr[1] == 0xaa && llc_hdr[2] == 0x03) {
                    /* get EtherType and convert to host byte-order.
                     *                      * (reduce by sizeof(eth_type)) */
                    offset += mac_hdr_len + (sizeof(llc_hdr) - sizeof(uint16_t));
                    break;

                }
                mac_hdr_len++;

            }

        } else {
            /* could be Null Data frame, so ignore it and try to get
             *              * EtherType from next one */
            offset = 0;

        }

    } else {
        printf("Unsupported frame type %d", frame_type);

    }
    return offset;

}

/* get octet offset to EtherType block
 *  */
size_t get_ethertype_offset(int link, const uint8_t* pktdata)
{
    int is_le_encoded = 0; /* little endian */
    uint16_t eth_type = 0;
    size_t offset = 0;

    /* http://www.tcpdump.org/linktypes.html */
    if (link == DLT_EN10MB) {
        /* srcmac[6], dstmac[6], ethertype[2] */
        offset = 12;

    } else if (link == DLT_LINUX_SLL) {
        /* http://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html */
        /* pkttype[2], arphrd_type[2], lladdrlen[2], lladdr[8], ethertype[2] */
        offset = 14;

    } else if (link == DLT_IEEE802_11
            || link == DLT_IEEE802_11_RADIO) {
        offset = get_802_11_ethertype_offset(link, pktdata);
        /* multi-octet fields in 802.11 frame are to be specified in
         *          * little-endian order */
        is_le_encoded = 1;

    } else {
        printf("Unsupported link-type %d", link);

    }

    if (offset) {
        /* get EtherType and convert to host byte order */
        memcpy(&eth_type, pktdata + offset, sizeof(eth_type));
        eth_type = (is_le_encoded) ? le16toh(eth_type) : ntohs(eth_type);
        if (eth_type != 0x0800 && eth_type != 0x86dd) {
            /* check if Ethernet 802.1Q VLAN */
            printf("eth_type 2 is %04X", eth_type);
            if (eth_type == 0x8100) {
                /* vlan_tag[4] */
                offset += 4;

            } else {
                printf("Unsupported ethernet type %d", eth_type);

            }

        }

    }
    return offset;

}


LOCAL char* find_file(const char* filename)
{
    if(access(filename, R_OK) < 0){
        printf("unable to read file %s\n", filename);
    }
    return strdup(filename);
}

void free_pcaps(pcap_pkts* pkts)
{
    pcap_pkt *it;
    for(it = pkts->pkts; it != pkts->max; ++it){
        free(it->data);
    }
    free(pkts->pkts);
    //free(pkts->file);
    free(pkts);
}


int main()
{
    pcap_pkts* pkts;
    play_args_t* play_args = 0;
    play_args_t play_args_a;
    
    struct sockaddr_in sin;
    memset(&(play_args_a.to), 0, sizeof(struct sockaddr_storage));
    memset(&(play_args_a.from), 0, sizeof(struct sockaddr_storage));
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_port = htons( 7063 );
    memcpy(&(play_args_a.to), &sin, sizeof(sin));
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_port = htons( 7064 );
    memcpy(&(play_args_a.from), &sin, sizeof(sin));
    

    pkts = (pcap_pkts *)malloc(sizeof(pcap_pkts));
    pkts->file = find_file("bootp1.pcapng");
    prepare_pkts(pkts->file, pkts);
    str2hex1((unsigned char *)(((pkts->pkts))->data), ((pkts->pkts))->pktlen);

    play_args_a.pcap = pkts;
    play_args_a.last_seq_no = 100;
    play_args = &play_args_a;

    send_packets( play_args );
    free_pcaps(pkts);
    return 1;
}



/*
 * prepare a pcap file
 */
int prepare_pkts(const char * file, pcap_pkts* pkts)
{
    pcap_t *pcap;
    struct pcap_pkthdr pkthdr_storage;
    struct pcap_pkthdr* pkthdr = &pkthdr_storage;

    const uint8_t* pktdata = NULL;
    int n_pkts = 0;
    u_long max_length = 0;
    size_t ether_type_offset = 0;
    uint16_t base = 0xffff;

    u_long pktlen;
    pcap_pkt* pkt_index;
    ether_type_hdr* ethhdr;

    struct ip* iphdr;
    struct ip6_hdr* ip6hdr;
    struct udphdr* udphdr;

    char buf[28];

    pkts->pkts = NULL;

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap = pcap_open_offline(file, errbuf);
    if (!pcap)
        printf("Can't open PCAP file bootp.pcapng\n" );

    while(pcap_next_ex(pcap, &pkthdr, &pktdata) == 1){
        if(pkthdr->len != pkthdr->caplen){
            printf("You got truncated packets.\n");
        }

        /* Determine offset from packet to ether type only once. */
        if (!ether_type_offset){
            int datalink = pcap_datalink(pcap);
            ether_type_offset = get_ethertype_offset(datalink, pktdata);

        }

        ethhdr = (ether_type_hdr *)(pktdata + ether_type_offset);
        if (ntohs(ethhdr->ether_type) != 0x0800 /* IPv4 */
                && ntohs(ethhdr->ether_type) != 0x86dd) { /* IPv6 */
            printf( "Ignoring non IP{4,6} packet, got ether_type %hu!\n",
                    ntohs(ethhdr->ether_type));
            continue;
        }

        iphdr = (struct ip*)((char*)ethhdr + sizeof(*ethhdr));
        if (iphdr && iphdr->ip_v == 6) {
            /* ipv6 */
            ip6hdr = (struct ip6_hdr*)(void*)iphdr;
            if (ip6hdr->ip6_nxt != IPPROTO_UDP) {
                fprintf(stderr, "prepare_pcap.c: Ignoring non UDP packet!\n");
                continue;

            }
            udphdr = (struct udphdr*)((char*)ip6hdr + sizeof(*ip6hdr));

        } else {
            /* ipv4 */
            if (iphdr->ip_p != IPPROTO_UDP) {
                fprintf(stderr, "prepare_pcap.c: Ignoring non UDP packet!\n");
                continue;

            }
            udphdr = (struct udphdr*)((char*)iphdr + (iphdr->ip_hl << 2));

        }

        pktlen = ntohs(udphdr->uh_ulen);
        if (pktlen > PCAP_MAXPACKET) {
            printf("Packet %d with size 0x%lx is too big! "
                    "Recompile with bigger PCAP_MAXPACKET in prepare_pcap.h",
                    n_pkts, pktlen);

        }
        /* BUG: inefficient */
        pkts->pkts = (pcap_pkt *)realloc(pkts->pkts, sizeof(*(pkts->pkts)) * (n_pkts + 1));
        if (!pkts->pkts)
            printf("Can't re-allocate memory for pcap pkt");
        pkt_index = pkts->pkts + n_pkts;
        pkt_index->pktlen = pktlen;
        pkt_index->ts = pkthdr->ts;
        if (format_timeval(&(pkt_index->ts), buf, sizeof(buf)) > 0) {
            printf("%s\n", buf);
        }
        pkt_index->data = (unsigned char *) malloc(pktlen); /* BUG: inefficient */
        if (!pkt_index->data)
            printf("Can't allocate memory for pcap pkt data");
        memcpy(pkt_index->data, udphdr, pktlen);
        printf("print udp header\n");
        str2hex1(udphdr , pktlen);

        udphdr->uh_sum = 0;

        /* compute a partial udp checksum */
        /* not including port that will be changed */
        /* when sending RTP */
        pkt_index->partial_check = check((uint16_t*)&udphdr->uh_ulen, pktlen - 4) + ntohs(IPPROTO_UDP + pktlen);
        if (max_length < pktlen)
            max_length = pktlen;
        if (base > ntohs(udphdr->uh_dport))
            base = ntohs(udphdr->uh_dport);
        n_pkts++;


    }
    pkts->max = pkts->pkts + n_pkts;
    pkts->max_length = max_length;
    pkts->base = base;
    fprintf(stderr, "In pcap bootp.pcapnp, npkts %d\nmax pkt length %lu\nbase port %d\n",  n_pkts, max_length, base);
    pcap_close(pcap);

    return (0);
}
