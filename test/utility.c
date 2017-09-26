#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>            // errno, perror()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <net/if.h>           // struct ifreq
#include <string.h>
#include <unistd.h>           // close()


void str2hex(unsigned char *str)
{
    while ( *str != '\0' ){
        printf("%02X", *str);
        str++;
    }
    printf("\n");
}
#define col_size 16
void str2hex1(unsigned char *str, int len)
{
    int col = 0;
    if(len < 0){
        printf("The packet length should large than zero\n");
        return;
    }
    while ( len-- ){
        col++;
        printf("%02X ", *(str++));
        if(col % col_size == 0){
            printf("\n");
        }
    }
    printf("\n");
}

ssize_t format_timeval(struct timeval *tv, char *buf, size_t sz)
{
    ssize_t written = -1;
    struct tm *gm = gmtime(&tv->tv_sec);

    if (gm)
    {
        written = (ssize_t)strftime(buf, sz, "%Y-%m-%dT%H:%M:%S", gm);
        if ((written > 0) && ((size_t)written < sz))
        {
            int w = snprintf(buf+written, sz-(size_t)written, ".%06ldZ", tv->tv_usec);
            written = (w > 0) ? written + w : -1;

        }

    }
    return written;

}
/*
 *print data in rows of 16 bytes: offset   hex   ascii
 *00000   4745 5420 2f20 4854   5450 2f31 2e31 0d0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const unsigned char *payload, int len, int offset) {

    int i;
    int gap;
    const unsigned char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x", *ch);
        ch++;
        /* print extra space after for visual aid */
        if (i%2 != 0)
            printf(" ");
        if (i == 7)
            printf("   ");

    }
    /* print space to handle_dev line less than 8 bytes */
    if (len < 8)
        printf("   ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("  ");
            if (i%2 == 0)
                printf(" ");

        }

    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;

    }

    printf("\n");

    return;

}
/*
 *print packet payload data (avoid printing binary data)
 */
void print_payload(const unsigned char *payload, int len) {

    int len_rem = len;
    int line_width = 16;/* number of            bytes per line */
    int line_len;
    int offset = 0;/* zero-bas                  ed offset counter */
    const unsigned char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        //fprint_ascii_line(ch, len, offset);
        return;

    }

    /* data spans multiple lines */
    for ( ;;  ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        //fprint_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            //fprint_ascii_line(ch, len_rem, offset);
            break;
        }
    }
    return;
}
/* print data to file */
void fprint_ascii_line(const unsigned char *payload, int len, int offset) {

    int i;
    const unsigned char *ch;
    FILE *file;
    file = fopen("/tmp/payload.txt", "w+");

    /* ascii */
    ch = payload;
    for(i = 0; i < len; i++) {
        fprintf(file, "%c", *ch);
        ch++;

    }
    fclose (file);

    return;

}

void get_mac_index( char * card, struct ifreq * ifr)
{
    
    int sd;
    char interface[20];

    //Interface to send packet through
    strcpy(interface, card);

    //Submit request for a socket descriptor to look up an interface
    if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
        perror ("socket() failed to get socket descriptor for using ioctl() ");
        exit(EXIT_FAILURE);
    }
    // Use ioctl() to look up interface index which we will use to
    // bind socket descriptor sd to specified interface with setsockopt() since
    // none of the other arguments of sendto() specify which interface to use.
    memset (ifr, 0, sizeof (struct ifreq));
    snprintf (ifr->ifr_name, sizeof (ifr->ifr_name), "%s", interface);
    if (ioctl (sd, SIOCGIFINDEX, ifr) < 0) {
        perror ("ioctl() failed to find interface ");
        exit(EXIT_FAILURE);
    }
    close (sd);
    
    return;
}
