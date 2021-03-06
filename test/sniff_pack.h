/* This file was automatically generated.  Do not edit! */
void reply_ack();
void process_incoming(unsigned char *msg,int msg_size);
#define UDP_HDRLEN 8         // UDP header length, excludes options data
#define TCP_HDRMIN 20         // TCP header min length
#define IP4_HDRLEN 20         // IPv4 header length
#define IP_HL(ip)(((ip)->ip_vhl) & 0x0f)
size_t get_ethertype_offset(int link,const uint8_t *pktdata);
typedef struct sniff_tcp sniff_tcp;
typedef u_int tcp_seq;
struct sniff_tcp {
    u_short th_sport;/* source port */
    u_short th_dport;/* destination port */
    tcp_seq th_seq;/* sequence number           */
    tcp_seq th_ack;/* acknowledgement number */
    u_char th_offx2;/* data offset, rsvd */
#define TH_OFF(th)(((th)->th_offx2 & 0xf0) >>   4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;/* window */
    u_short th_sum;/* checksum */
    u_short th_urp;/* ur                        gent pointer */


};
typedef struct sniff_ip sniff_ip;
struct sniff_ip {
    u_char ip_vhl;/* version << 4 | header length >> 2 */
    u_char ip_tos;/* type o             f service */
    u_short ip_len;/* total length */
    u_short ip_id;/*                 identification */
    u_short ip_off;/* fragment offset field */
#define IP_RF 0x8000/* reserved fragment flag */
#define IP_DF 0x4000 /* dont fragment flag */
#define IP_MF 0x2000 /* more fragments flag */
#define IP_OFFMASK 0x1fff  /* mask for fragmenting bits */
    u_char ip_ttl;/* time to live */
    u_char ip_p;/* protocol */
    u_short ip_sum;/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest         address */


};
typedef struct sniff_ethernet sniff_ethernet;
#define ETHER_ADDR_LEN 6
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */

};
void got_packet(unsigned char *args,const struct pcap_pkthdr *header,const unsigned char *packet);
int sniff_pack_init();
extern char *bpfFilter;
pcap_t *open_and_init(const char *dev_name,const char *bpfFilter);
int set_filter(pcap_t *handle,struct bpf_program *fp,const char *bpfFilter);
typedef struct tcpkeymap tcpkeymap;
struct tcpkeymap {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
};
extern struct tcpkeymap tcpkey;
extern struct tcpkeymap tcpkey;
typedef struct ipkeymap ipkeymap;
struct ipkeymap {
    uint16_t ip_id;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};
extern struct ipkeymap ipkey;
extern struct ipkeymap ipkey;
extern int link_type;
extern char *dev;
