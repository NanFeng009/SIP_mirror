#include "common.h"
#include <netdb.h>

int main()
{
    int sockfd, portno, n;

    struct sockaddr_in serv_addr;
    struct hostent *server;
    
    char buffer[256];
    
    portno = 1037;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if( sockfd < 0 )  error("ERROR opening socket");

    server = gethostbyname("127.0.0.1");
    if(server == NULL) error("ERROR, no such host");

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
          server->h_length);

    serv_addr.sin_port = htons( portno );

    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0 )
        error("ERROR connecting");

    printf("Please enter the message: ");
    bzero(buffer, 256);
    fgets(buffer, 255, stdin);
    n = write(sockfd, buffer, strlen(buffer));
    if( n < 0 ) error("ERROR writing to socket");
    bzero(buffer, 256);
    n = read(sockfd, buffer, 255);
    if( n < 0 ) error("ERROR reading from server");
    printf("%s\n", buffer);

    return 0;
}


