/* payload data */
struct data
{
    uint8_t* payload;
    uint16_t  pktlen;
    struct data* next;

};
struct paly_payload{
    uint8_t  ip_p;
    uint16_t port;
    /* IP layer variables */
    struct ip *iphdr;
    union
    {
        /* TCP layer variable */
        struct tcphdr *tcphdr;
        /* UDP layer variable */
        struct udphdr *udphdr;

    }thdr;
    /* payload data */
    struct data data;

};

#define NUM 5

#define LOG(format, args...) do {                \
    printf("%s: "format"\n", __func__, ##args);  \
} while(0)

#define IP4_HDRLEN 20         // IPv4 header length
#define UDP_HDRLEN 8         // UDP header length, excludes options data
#define TCP_HDRLEN(tcphdr) (((tcphdr->th_off ) & 0x0f) * 4)
