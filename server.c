#include <pthread.h>
#include "common.h"
#include <sys/select.h>

typedef void* (*thread_func) (void*);
#define LOG(format, args...) do {                \
    printf("%s: "format"\n", __func__, ##args);  \
} while(0)

static void process_msg( int socket  );

static void server_task(void * args)
{
    int sockfd, newsockfd, portno, clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int n;
    uint32_t nfds = 0;
    fd_set read_fds;
    int rc;
    struct timeval timeout;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if( sockfd < 0 )error("ERROR opening socket");
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 1037;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if( bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
        error("ERROR on binding");
        close( sockfd );
        return -1;
    }

    rc = listen( sockfd, 5 );
    if ( rc < 0 ) error("listen to server socket failed");

    clilen = sizeof(cli_addr);
    newsockfd = accept( sockfd, (struct sockaddr *) &cli_addr, &clilen );
    if ( newsockfd < 0 ){
        LOG("accept() failed");
    }

    FD_ZERO(&read_fds);
    FD_SET(newsockfd, &read_fds);
    nfds = nfds > (uint32_t)sockfd ? nfds :(uint32_t)sockfd;

    while( 1 ){
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        rc = select((nfds + 1), &read_fds, NULL, NULL, &timeout);
        if (rc == 0){
            LOG("Select timeout and wait again");
            continue;
        }else if(rc == -1){
            perror("select failed");
            break;
        }

        if(FD_ISSET(newsockfd, &read_fds)){
            process_msg(newsockfd);
        }
    }

    (void)close( sockfd );
    LOG("Exit server socket");
}

static void process_msg( int socket )
{
    int rc = 0;
    char buffer[256];
    uint8_t response = 0;
    bzero(buffer, 256);


    rc = recv(socket, &buffer, sizeof( buffer ), 0);
    if( rc <= 0 ){
        close( socket );
        error("Receive from client failed");
    }
    printf("Here is the message: %s", buffer );
    str2hex(buffer);
    rc = send(socket, "I got your message", 18, 0);
    if(rc < 0) error("ERROR writing to socket");
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
