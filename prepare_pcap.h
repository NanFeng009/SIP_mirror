
typedef struct {
    u_char* data;
    u_long pktlen;
    struct timeval ts;
    int partial_check;

} pcap_pkt;

typedef struct {
    char* file;
    uint16_t base;
    u_long max_length;
    pcap_pkt* max;
    pcap_pkt* pkt;

} pcap_pkts;
