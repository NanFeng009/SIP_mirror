/* This file was automatically generated.  Do not edit! */
void deinit_send();
int sniff_pack_init();
int send_pack_init(char *src,char *dst,char *card);
#define LOG(format, args...) do {                \
    printf("%s: "format"\n", __func__, ##args);  \
} while(0)
int read_pack_init(char *filename);
extern char *src_ip,*dst_ip;
int main(int argc,char **argv);
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
extern struct sipkeymap sipkey;
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
