#include <stdlib.h> // for EXIT_FAILURE
#include <stdio.h>
#include <sys/types.h>        // uint8_t
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_IP, IPPROTO_TCP, INET_ADDRSTRLEN

#include "mirror.h"


/* variable to keep the status of protocol */
struct ipkeymap ipkey;
struct tcpkeymap tcpkey;
struct sipkeymap sipkey;


int main(int argc, char **argv)
{
    char *src_ip = "20.74.20.189";
    char *dst_ip = "20.74.39.101";
    char *card = "eth0";
    int rc;

    rc = read_pack_init( "bootp1.pcapng" );
    if ( rc == EXIT_FAILURE ){
        LOG("Error in read pack file!");
        return (EXIT_FAILURE);
    }

    rc = send_pack_init( src_ip, dst_ip, card );
    if ( rc == EXIT_FAILURE ){
        LOG("Error in send pack prepare!");
        return (EXIT_FAILURE);
    }

    sniff_pack_init();

    deinit_send();
    return 1;
}
