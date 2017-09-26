/* This file was automatically generated.  Do not edit! */
uint16_t checksum(uint16_t *addr,int len);
uint16_t udp4_checksum(struct ip *iphdr,struct udphdr *udphdr,uint8_t *payload,int payloadlen);
uint16_t tcp4_checksum(struct ip *iphdr,struct tcphdr *tcphdr,uint8_t *payload,int payloadlen);
int *allocate_intmem(int len);
char *allocate_strmem(int len);
typedef struct ipkeymap ipkeymap;
struct ipkeymap {
    uint16_t ip_id;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};
extern struct ipkeymap ipkey;
extern struct ipkeymap ipkey;
int send_pack_direct(uint8_t *data,int datalen);
void fabricate_tcphdr(struct tcphdr *tcphdr,struct ip *iphdr,uint8_t *data,int datalen);
#define UDP_HDRLEN 8         // UDP header length, excludes options data
#define IP4_HDRLEN 20         // IPv4 header length
void fabricate_udphdr(struct udphdr *udphdr,struct ip *iphdr,uint8_t *data,int datalen);
void fabricate_iphdr(struct ip *iphdr,uint8_t ip_p,int datalen);
uint8_t *allocate_ustrmem(int len);
void send_pack(uint8_t *data,int datalen,uint8_t ip_p);
void get_mac_index(char *card,struct ifreq *ifr);
void deinit_send();
#define LOG(format, args...) do {                \
    printf("%s: "format"\n", __func__, ##args);  \
} while(0)
int prepare_sock(char *card);
int send_pack_init(char *src,char *dst,char *card);
extern char *src_ip,*dst_ip;
