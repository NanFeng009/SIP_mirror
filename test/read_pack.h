/* This file was automatically generated.  Do not edit! */
int read_pack(char *filename);
int read_pack_init(char *filename);
void wireshark_display_entry_all();
void print_payload(const unsigned char *payload,int len);
void wireshark_display_entry(int queue_type);
typedef struct wireshark_entry wireshark_entry;
struct wireshark_entry *wireshark_pop_entry(int queue_type);
#define TCP_HDRLEN(thhdr) (((((struct tcphdr *)thhdr)->th_off ) & 0x0f) * 4)
#define WIRESHARK_ENTRY_TCP 1
#define UDP_HDRLEN 8         // UDP header length, excludes options data
#define WIRESHARK_ENTRY_UDP 0
#define IP4_HDRLEN 20         // IPv4 header length
void wireshark_add_entry(struct ip *iphdr,void *thhdr,uint8_t *payload,int payload_len,int queue_type);
void *memdup(const void *mem,size_t size);
void wireshark_init_entry_all();
size_t get_802_11_ethertype_offset(int link,const uint8_t *pktdata);
size_t get_ethertype_offset(int link,const uint8_t *pktdata);
#define LOG(format, args...) do {                \
    printf("%s: "format"\n", __func__, ##args);  \
} while(0)
#define LOCAL static
LOCAL char *find_file(const char *filename);
void *allocate_mem(int len);
#define WIRESHARK_ENTRY_MAX 2
extern struct wireshark_entry *wireshark_data_tail[WIRESHARK_ENTRY_MAX];
extern struct wireshark_entry *wireshark_data_head[WIRESHARK_ENTRY_MAX];
struct wireshark_entry {
    /* IP layer variables */
    struct ip *iphdr;
    /* transport layer */
    union{
        /* TCP layer variable */
        struct tcphdr *tcphdr;
        /* UDP layer variable */
        struct udphdr *udphdr;
    };
    /* application data */
    uint8_t * payload;

    struct wireshark_entry * next;
};
typedef struct _ether_type_hdr _ether_type_hdr;
struct _ether_type_hdr {
    uint16_t ether_type; /* we only need the type, so we can determine, if the next header is IPv4 or IPv6 */
};
typedef struct _ether_type_hdr ether_type_hdr;
#define IPV6 0x86dd
#define TLS 0x888e
#define CDP 0x2000
#define LLDP 0x88cc
#define IP  0x0800
#define ARP 0x0806
#define LOCAL_INTERFACE 0
