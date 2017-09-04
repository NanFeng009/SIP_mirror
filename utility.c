#include <stdio.h>
#include <sys/time.h>

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
            int w = snprintf(buf+written, sz-(size_t)written, ".%06dZ", tv->tv_usec);
            written = (w > 0) ? written + w : -1;

        }

    }
    return written;

}
/*
 *print data in rows of 16 bytes: offset   hex   ascii
 *00000   4745 5420 2f20 4854   5450 2f31 2e31 0d0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {

    int i;
    int gap;
    const u_char *ch;

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
