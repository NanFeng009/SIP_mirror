#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>           // uint8_t
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h> // inet_addr
#include <string.h>
#include <stdbool.h> // bool, true, false

#include "sip_handle.h"


int     hasMedia = 0;
bool    call_established; // == true when the call is established
int     hasMediaInformation; 
sipkeymap sipmap;

void process_incoming(unsigned char * msg, int msg_size)
{
    int reply_code;
    unsigned char *ptr;
    static char request[65];
    char  responsecseqmethod[65];
    char  txn[MAX_HEADER_LEN];
    char *call_id = NULL;
    char *peer_tag;
    bool found = false;
    char payload[65536];
    char * tmp = payload;



    if (msg_size <= 0){
        printf("msg_size is %d!!!", msg_size);
        return;
    }

    responsecseqmethod[0] = '\0';
    txn[0] = '\0';
    /* dump message for test */
    print_payload(msg, 20);
    /* Check that we have a To:-header */
    if (!get_header(msg, "To:", false)[0]){
        return (EXIT_FAILURE);
    }

    /* Is it a response ? */
    if ((msg[0] == 'S') && 
            (msg[1] == 'I') &&
            (msg[2] == 'P') &&
            (msg[3] == '/') &&
            (msg[4] == '2') &&
            (msg[5] == '.') &&
            (msg[6] == '0') ) {

        reply_code = get_reply_code(msg);
        if (!reply_code) {
            LOG("Get unexpected message!");
            return (EXIT_FAILURE);
        }
        /* It is a response: update peer_tag */
        ptr = get_to_tag(msg);
        if (ptr) {
            if(strlen(ptr) > (MAX_HEADER_LEN - 1)) {
                LOG("Peer tag too long. Change MAX_HEADER_LEN and recompile sipp");
            }
            if(peer_tag) {
                free(peer_tag);
            }
            peer_tag = strdup(ptr);
            if (!peer_tag) {
                LOG("Out of memory allocating peer tag.");
            }
        }
        request[0]=0;
        // extract the cseq method from the response
        extract_cseq_method (responsecseqmethod, msg);
        extract_transaction (txn, msg);
        LOG("SIP reply code is %d", reply_code);
        LOG("SIP method is %s", responsecseqmethod);
        LOG("SIP txn is %s", txn);
        return;
    } 
    /* Is it a request ? */
    else if ((ptr = strchr(msg, ' '))){
        if((ptr - msg) < 64){
            memcpy(request, msg, ptr - msg);
            request[ptr - msg] = 0;
            // Check if we received an ACK => call established
            if (strcmp(request, "ACK") == 0){
                call_established = true;
            }

            /* In case of INVITE or re-INVITE, ACK or PRACK
             * get the media info if needed (= we got a pcap
             * play action) */
            if (((strncmp(request, "INVITE", 6) == 0)
                        || (strncmp(request, "ACK", 3) == 0)
                        || (strncmp(request, "PRACK", 5) == 0)))
                //get_remote_media_addr(msg);
                ;
            /* for register */
            if (strncmp(request, "REGISTER", 8) == 0){
                tmp += sprintf( tmp, "%s", "SIP/2.0 100 Trying" );
                *tmp++ = '\r'; *tmp++ = '\n';
                tmp += sprintf( tmp, "%s", get_header(msg, "Via:", false) );
                *tmp++ = '\r'; *tmp++ = '\n';
                tmp += sprintf( tmp, "%s", get_header(msg, "From:", false) );
                *tmp++ = '\r'; *tmp++ = '\n';
                tmp += sprintf( tmp, "%s", get_header(msg, "To:", false) );
                *tmp++ = '\r'; *tmp++ = '\n';
                tmp += sprintf( tmp, "%s", get_header(msg, "Max-Forwards:", false) );
                *tmp++ = '\r'; *tmp++ = '\n';
                tmp += sprintf( tmp, "%s", get_header(msg, "Date:", false) );
                *tmp++ = '\r'; *tmp++ = '\n';
                tmp += sprintf( tmp, "%s", get_header(msg, "Call-ID:", false) );
                *tmp++ = '\r'; *tmp++ = '\n';
                tmp += sprintf( tmp, "%s", get_header(msg, "Cseq:", false) );
                *tmp++ = '\r'; *tmp++ = '\n';
                tmp += sprintf( tmp, "%s", "Content-Length: 0" );
                *tmp++ = '\r'; *tmp++ = '\n';
                *tmp++ = '\r'; *tmp++ = '\n';
                LOG("tmp is %s\n",  payload);
                send_pack(payload, strlen(payload), IPPROTO_TCP );

            }
        }
        /*
        LOG("request is %s\n", request);
        extract_cseq_method (responsecseqmethod, msg);
        extract_transaction (txn, msg);
        sipmap.cseq = get_cseq_value(msg);
        LOG("SIP method is %s", responsecseqmethod);
        LOG("SIP branch is %s", txn);
        LOG("SIP cseq is %ld", sipmap.cseq);
        sipmap.call_id = get_call_id( msg );
        sipmap.from_tag = get_from_tag(msg);
        LOG("SIP call_id is %s", sipmap.call_id);
        LOG("SIP remote_tag is %s", sipmap.from_tag);
        LOG("From content is %s\n", get_header_content(msg, "Contact:"));
        LOG("supported content is %s\n", get_header_content(msg, "Supported:"));
        */


    } else {
        LOG("SIP method too long in received message '%s'", msg);
    }


    call_id = get_call_id(msg);
    if (call_id[0] == '\0') {
        printf("SIP message without Call-ID discarded!");
        return;
    }
    // printf("SIP message Call-ID = %s \n", call_id);
}

void reply_ack()
{
    struct ip ip;
    struct tcphdr tcp;
    struct sockaddr_in sin;

    uint8_t *packet;
    packet = (uint8_t *)malloc(IP_MAXPACKET);

    int rc;


    ip.ip_hl = 0x5;
    ip.ip_v = 0x4;
    ip.ip_tos = 0x0;
    ip.ip_len = sizeof(struct ip) + sizeof(struct tcphdr); 
    ipkey.ip_id = htons(ntohs(ipkey.ip_id) + 1);
    memcpy((void *)(&(ip.ip_id)), (const void *)(&(ipkey.ip_id)), sizeof(ip.ip_id));
    ip.ip_off = 0x0;
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_TCP;
    ip.ip_sum = 0x0;
    ip.ip_src.s_addr = inet_addr("172.17.14.90");
    //memcpy((void *)(&(ip.ip_src.s_addr)), (const void *)(&(ip.ip_dst)), sizeof(ip.ip_src.s_addr));
    //ip.ip_dst.s_addr = inet_addr("172.16.1.204");
    memcpy((void *)(&(ip.ip_dst.s_addr)), (const void *)(&(ip.ip_src)), sizeof(ip.ip_src.s_addr));
    ip.ip_sum = checksum((unsigned short *)&ip, sizeof(ip));
    memcpy(packet, &ip, sizeof(ip));


    //tcp.th_sport = htons(3333);
    memset((void *)&tcp, 0, sizeof(struct tcphdr));
    memcpy((void *)(&(tcp.th_sport)), (const void *)(&(tcpkey.th_dport)), sizeof(tcp.th_sport));
    //tcp.th_dport = htons(33334);
    memcpy((void *)(&(tcp.th_dport)), (const void *)(&(tcpkey.th_sport)), sizeof(tcp.th_dport));
    //tcp.th_seq = htonl(0x131123);
    //tcpkey.th_seq = htonl(ntohl(tcpkey.th_seq) + 1);
    tcpkey.th_seq = htonl(888);
    LOG("seq # is %d\n", ntohl(tcpkey.th_seq));
    memcpy((void *)(&(tcp.th_seq)), (const void *)(&(tcpkey.th_seq)), sizeof(tcp.th_seq));
    tcp.th_off = sizeof(struct tcphdr) / 4;
    tcp.th_flags = (TH_SYN|TH_ACK);
    tcp.th_win = htons(32768);
    tcp.th_sum = 0;
    tcp.th_sum = tcp4_checksum(&ip, &tcp, NULL, 0);
    memcpy((packet + sizeof(ip)), &tcp, sizeof(tcp));

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip.ip_dst.s_addr;

    rc = send_pack_direct( packet, IP4_HDRLEN + TCP_HDRMIN );
    if( rc == EXIT_SUCCESS ){
        LOG("send packet successfully!");
    }

    free( packet );

}

/* SDP */
void get_remote_media_addr(const char * msg)
{
    char * host = find_in_sdp( "c=IN IP4 ", msg);
    if (strlen(host) == 0) {
        return;
    }

    hasMediaInformation = 1;
    const int family = AF_INET;

    char * port = find_in_sdp("m=audio ", msg);
    if (strlen(port) == 0) {
    }

    port = find_in_sdp("m=image ", msg);
    if (strlen(port) == 0) {
    }

    port = find_in_sdp("m=video ", msg);
    if (strlen(port) == 0) {
    }

}
LOCAL char * find_in_sdp(const char * pattern, const char * msg)
{
    const char * ptr = msg;
    const char * ptr1;
    static char * dest;
    int patternlen = strlen(pattern);
    ptr = strcasestr(msg, pattern);
    if (!ptr){
        return "";
    }
    ptr = ptr + patternlen;

    ptr1 = strpbrk(ptr," \r\n");
    if (!ptr1){
        return "";
    }

    dest = allocate_mem( ptr1 - ptr + 1 ); // 1 store '\0'

    memcpy( dest, ptr, ptr1 - ptr );
    dest[ptr1-ptr] = '\0';

    return dest; 
}

