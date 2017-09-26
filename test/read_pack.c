#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <stdint.h>
#include <pcap.h>
#include <error.h>

#include "read_pack.h"

#if LOCAL_INTERFACE




#define ARP 0x0806
#define IP  0x0800
#define LLDP 0x88cc
#define CDP 0x2000
#define TLS 0x888e
#define IPV6 0x86dd

typedef struct _ether_type_hdr {
    uint16_t ether_type; /* we only need the type, so we can determine, if the next header is IPv4 or IPv6 */
} ether_type_hdr;



#endif /* end of LOCAL_INTERFACE */


/* gloabl variable store the payload from pcap file for sending in send_pack */
struct wireshark_entry * wireshark_data_head[ WIRESHARK_ENTRY_MAX ]; /*  Always points to the first data */
struct wireshark_entry * wireshark_data_tail[ WIRESHARK_ENTRY_MAX ]; /*  Always points to the last data */


// Allocate memory 
void * allocate_mem (int len)
{
    void *tmp;

    if (len <= 0) {
        fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_mem().\n", len);
        exit (EXIT_FAILURE);
    }

    tmp = malloc(len);
    if (tmp != NULL) {
        memset (tmp, 0, len * sizeof (char));
        return (tmp);
    } else {
        fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_mem().\n");
        exit (EXIT_FAILURE);
    }
}


LOCAL char* find_file(const char* filename)
{
    if(access(filename, R_OK) < 0){
        LOG("unable to read file %s\n", filename);
        exit(1);
    }
    return strdup(filename);
}

size_t get_ethertype_offset(int link, const uint8_t* pktdata)
{
    int is_le_encoded = 0; /* little endian */
    uint16_t eth_type = 0;
    size_t offset = 0;

    if(link == DLT_EN10MB){
        /* srcmac[6], dstmac[6], ethertype[2] */
        offset = 12;
    } else if (link == DLT_LINUX_SLL) {
        /* pkttype[2], arphrd_type[2], lladdrlen[2], lladdr[8], ethertype[2] */
        offset = 14;
    } else if (link == DLT_IEEE802_11
            || link == DLT_IEEE802_11_RADIO) {
        offset = get_802_11_ethertype_offset(link, pktdata);
        /* multi-octet fields in 802.11 frame are to be specified in
           131          *          * little-endian order */
        is_le_encoded = 1;
    } else {
        LOG("Unsupported link-type %d", link);
    }
    if(offset){
        /* get EtherType and convert to host byte order */
        memcpy(&eth_type, pktdata + offset, sizeof(eth_type));
        eth_type = (is_le_encoded) ? le16toh(eth_type) : ntohs(eth_type);
        if (eth_type != 0x0800 && eth_type != 0x86dd) {
            /* check if Ethernet 802.1Q VLAN */
            if (eth_type == 0x8100) {
                /* vlan_tag[4] */
                offset += 4;

            } else {
                LOG("Unsupported ethernet type %d", eth_type);
            }
        }
    }
    return offset;
}



/* get octet offset to EtherType block in 802.11 frame
 *  *  */
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
         *          *          * in little-endian order */
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
         *          *          * EtherType from next one */
        offset = 0;
    } else if (frame_type == 0x02) {
        /* only Data frames carry the relevant payload and EtherType */
        if (frame_sub_type < 0x04
                || (frame_sub_type > 0x07 && frame_sub_type < 0x0c)) {
            /* MAC header of a Data frame is at least 24 and at most 36
             *              *              * octets long */
            size_t mac_hdr_len = 24;
            uint8_t llc_hdr[8] = { 0x00   };
            while (mac_hdr_len <= 36) {
                /* attempt to get Logical-Link Control header */
                /* dsap[1],ssap[1],ctrl_fld[1],org_code[3],ethertype[2] */
                memcpy(llc_hdr, pktdata + offset + mac_hdr_len, sizeof(llc_hdr));
                /* check if Logical-Link Control header */
                if (llc_hdr[0] == 0xaa && llc_hdr[1] == 0xaa && llc_hdr[2] == 0x03) {
                    /* get EtherType and convert to host byte-order.
                     *                      *                      * (reduce by sizeof(eth_type)) */
                    offset += mac_hdr_len + (sizeof(llc_hdr) - sizeof(uint16_t));
                    break;
                }
                mac_hdr_len++;
            }
        } else {
            /* could be Null Data frame, so ignore it and try to get
             *              *              * EtherType from next one */
            offset = 0;
        }
    } else {
        LOG("Unsupported frame type %d", frame_type);
    }
    return offset;
}


/* Init the wireshark_entry */
void wireshark_init_entry_all()
{
    int i;
    for (i = 0; i < WIRESHARK_ENTRY_MAX; i++)
    {
        wireshark_data_tail[i] = NULL; 
        wireshark_data_head[i] = NULL;
    }
    return;
}

void* memdup(const void* mem, size_t size) { 
    if(size > 0){
        void* out = malloc(size);

        if(out != NULL)
            memcpy(out, mem, size);

        return out;
    } else {
        return NULL;
    }
}

void wireshark_add_entry(struct ip * iphdr, void * thhdr, uint8_t * payload, int payload_len, int queue_type)
{

    if( wireshark_data_tail[queue_type] == NULL ){
        wireshark_data_tail[queue_type] = malloc(sizeof (struct wireshark_entry));
        wireshark_data_head[queue_type] = wireshark_data_tail[queue_type];
    } else if(wireshark_data_tail[queue_type]!= NULL && wireshark_data_tail[queue_type]->next == NULL) {
        wireshark_data_tail[queue_type]->next = malloc(sizeof (struct wireshark_entry));
        wireshark_data_tail[queue_type] = wireshark_data_tail[queue_type]->next;
    } else {
        LOG("add data to a un-empty area!");
    }

    wireshark_data_tail[queue_type]->iphdr = memdup( iphdr, IP4_HDRLEN );
    if (queue_type == WIRESHARK_ENTRY_UDP){
        wireshark_data_tail[queue_type]->udphdr = memdup( thhdr, UDP_HDRLEN );
        wireshark_data_tail[queue_type]->payload = memdup( payload, payload_len );
    } else if (queue_type == WIRESHARK_ENTRY_TCP) {
        wireshark_data_tail[queue_type]->tcphdr = memdup( thhdr, TCP_HDRLEN(thhdr)); ///////////????????????
        wireshark_data_tail[queue_type]->payload = memdup( payload, payload_len );
    } else {
        LOG(" Unsupport packet type!");
    }


    wireshark_data_tail[queue_type]->next = NULL; /*set the next data to NULL */

}


struct wireshark_entry * wireshark_pop_entry(int queue_type)
{
    struct wireshark_entry * p;
    if(wireshark_data_head[queue_type] != wireshark_data_tail[queue_type]){
        p = wireshark_data_head[queue_type];
    }else {
        LOG("no data in queue!");
        return NULL;
    }

    wireshark_data_head[queue_type] = wireshark_data_head[queue_type]->next;

    return p;
}

void wireshark_display_entry(int queue_type)
{
    if(queue_type < 0 || queue_type >= WIRESHARK_ENTRY_MAX){
        LOG("Invalid message type");
        return;
    }
    struct wireshark_entry *p = wireshark_data_head[queue_type];
    while( p != NULL ){
        print_payload(p->payload, 20);
        p = p->next;
    }
}

void wireshark_display_entry_all()
{
    int num;
    for(num = 0; num < WIRESHARK_ENTRY_MAX; num++){
        wireshark_display_entry( num );
    }
}

int read_pack_init(char * filename)
{
    int rc;
    wireshark_init_entry_all();
    rc = read_pack( filename );
    if ( rc == EXIT_FAILURE ){
        return (EXIT_FAILURE);
    }
    //wireshark_display_entry_all();
    //wireshark_display_entry(0);
    return (EXIT_SUCCESS);
}
int read_pack ( char * filename )
{
    pcap_t *pcap; /* pcap.h */
    struct pcap_pkthdr pkthdr_storage; /* pcap.h */
    struct pcap_pkthdr* pkthdr = &pkthdr_storage;

    const uint8_t* pktdata = NULL;
    unsigned int ether_type_offset = 0;
    char errbuf[PCAP_ERRBUF_SIZE];


    struct ip* iphdr;
    struct udphdr* udphdr;
    struct tcphdr* tcphdr;
    uint8_t* phdr;


    ether_type_hdr* ethhdr;

    char *file = find_file( filename );


    pcap = pcap_open_offline(file, errbuf);
    if(!pcap){
        LOG("Can't open PCAP file bootp.pcapng\n" );
        return (EXIT_FAILURE);
    }
    while(pcap_next_ex(pcap, &pkthdr, &pktdata) == 1){
        if(pkthdr->len != pkthdr->caplen){
            LOG("This is a truncated packet, please get a new pcap!");
            return (EXIT_FAILURE);
        }

        /* Determine offset from packet to ether type first time. */
        if(!ether_type_offset){
            int datalink = pcap_datalink(pcap);
            ether_type_offset = get_ethertype_offset(datalink, pktdata);
        }

        ethhdr = (ether_type_hdr *)(pktdata + ether_type_offset);

        switch(ntohs(ethhdr->ether_type)){
            case ARP:
            case IPV6:
            case TLS:
            case CDP:
            case LLDP:
                LOG("Get the ether_type %hu packet, not support at current version\n",ntohs(ethhdr->ether_type));
                continue;
            case IP:
                iphdr = (struct ip*)((char*)ethhdr + sizeof(*ethhdr));
                int datalen = 0;

                /* udp */
                if(iphdr->ip_p == IPPROTO_UDP){
                    udphdr = (struct udphdr*)((char*)iphdr + (iphdr->ip_hl << 2));
                    datalen = ntohs(iphdr->ip_len) - IP4_HDRLEN - UDP_HDRLEN; 
                    phdr = (uint8_t *)udphdr + UDP_HDRLEN;

                    wireshark_add_entry(iphdr, (void *)udphdr, phdr, datalen, WIRESHARK_ENTRY_UDP );
                } /* end udp */
                /* tcp */
                else if(iphdr->ip_p == IPPROTO_TCP){
                    tcphdr = (struct tcphdr*)((char*)iphdr + (iphdr->ip_hl << 2));
                    datalen = ntohs(iphdr->ip_len) - IP4_HDRLEN - TCP_HDRLEN(tcphdr); 
                    phdr = (uint8_t *)tcphdr + TCP_HDRLEN(tcphdr);

                    wireshark_add_entry(iphdr, (void *)tcphdr, phdr, datalen, WIRESHARK_ENTRY_TCP );
                } /*end tcp */
                else{
                    LOG("Unsupported frame type %d",iphdr->ip_p );
                    continue;
                }

                break;
            default:
                LOG("Ignoring non IP{4,6} packet, got ether_type %hu!\n",
                        ntohs(ethhdr->ether_type));
                continue;
        } /* end switch */

    } /* end while */


    pcap_close(pcap);
    return (EXIT_SUCCESS);
}

