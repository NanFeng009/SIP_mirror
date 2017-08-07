#include <pthread.h>
#include "common.h"

typedef void* (*thread_func) (void*);
#define LOG(format, args...) do {                \
    printf("%s: "format"\n", __func__, ##args);  \
} while(0)


static void server_task(void * args)
{
    int sockfd, newsockfd, portno, clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int n;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if( sockfd < 0 )error("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 1037;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if( bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
        error("ERROR on binding");
    }

    LOG("bind successfully");
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if(newsockfd < 0)  error("ERROR on accept");
    LOG("accept successfully");
    bzero(buffer, 256);

    n = read(newsockfd, buffer, 256);
    if( n < 0 )  error("ERROR reading from socket");
    printf("Here is the message: %s\n", buffer);
    n = write(newsockfd, "I got your message", 18);
    if(n < 0) error("ERROR writing to socket");

    LOG("server task exit");
}
pthread_t start_server()
{
    pthread_t thread;
    int rc;

    rc = pthread_create(&thread, NULL,(thread_func)server_task, NULL);
    if(rc != 0)  error("ERROR pthread_create");

    rc = pthread_setname_np(thread, "server_task");
    if(rc != 0)  error("ERROR pthread_setname_np");
}

int main(int argc, char** argv)
{
    int rc;
    pthread_t client_thread;
    pthread_t server_thread;

    server_thread = start_server();

    sleep(20);
    rc = pthread_join(server_thread, NULL);
    if( rc != 0 ) error("server_thread join");

    LOG("sleep for some time");
    sleep(20);
    return 0;

}
