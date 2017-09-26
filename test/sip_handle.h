/* This file was automatically generated.  Do not edit! */
void *allocate_mem(int len);
#define LOCAL static
LOCAL char *find_in_sdp(const char *pattern,const char *msg);
void get_remote_media_addr(const char *msg);
#define TCP_HDRMIN 20         // TCP header min length
#define IP4_HDRLEN 20         // IPv4 header length
int send_pack_direct(uint8_t *data,int datalen);
uint16_t tcp4_checksum(struct ip *iphdr,struct tcphdr *tcphdr,uint8_t *payload,int payloadlen);
typedef struct tcpkeymap tcpkeymap;
struct tcpkeymap {
    uint16_t th_sport;
    uint16_t th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
};
extern struct tcpkeymap tcpkey;
extern struct tcpkeymap tcpkey;
uint16_t checksum(uint16_t *addr,int len);
typedef struct ipkeymap ipkeymap;
struct ipkeymap {
    uint16_t ip_id;
    struct in_addr ip_src;
    struct in_addr ip_dst;
};
extern struct ipkeymap ipkey;
extern struct ipkeymap ipkey;
void reply_ack();
char *get_call_id(unsigned char *msg);
void send_pack(uint8_t *data,int datalen,uint8_t ip_p);
void extract_transaction(char *txn,char *msg);
void extract_cseq_method(char *method,char *msg);
char *get_to_tag(unsigned char *msg);
#define LOG(format, args...) do {                \
    printf("%s: "format"\n", __func__, ##args);  \
} while(0)
unsigned long get_reply_code(char *msg);
char *get_header(const char *message,const char *name,bool content);
void print_payload(const unsigned char *payload,int len);
#define MAX_HEADER_LEN 2049
void process_incoming(unsigned char *msg,int msg_size);
typedef struct sipkeymap sipkeymap;
struct sipkeymap {
    char remote_service[40];
    char remote_ip[40];
    char remote_port[40];
    char * from_tag;//get_from_tag()

    char local_service[40];
    char local_ip[40];
    char local_port[40];

    char request[40]; 
    char * call_id;  //get_call_id()
    char cseqmethon[40];//extract_cseq_method()
    char branch[40];//extract_transaction()
    char contact[40];
    unsigned long int cseq;//get_cseq_value()

};
extern sipkeymap sipmap;
extern int hasMediaInformation;
extern bool call_established;
extern int hasMedia;
