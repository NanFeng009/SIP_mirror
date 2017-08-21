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
