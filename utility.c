#include <stdio.h>

void str2hex(char *str)
{
    while ( *str != '\0' ){
        printf("%02X", *str);
        str++;
    }
    printf("\n");
}
