#include <pthread.h>
#include <signal.h>
#include "common.h"
#include <sys/select.h>

typedef void* (*thread_func) (void*);
#define LOG(format, args...) do {                \
    printf("%s: "format"\n", __func__, ##args);  \
} while(0)

//-------------------------------------------;
// Internal function prototypes
//-------------------------------------------;
static void process_msg(int socket);

static void catchterm(int signo);
static void catchhup(int signo);
static void catchalarm(int signo);
static void catchint(int signo);


typedef struct {
    char mid_msg[256];
    pthread_t pid;
}mid_buffer;
mid_buffer mid_buffs[10];

pthread_mutex_t mid_lock;
pthread_cond_t mid_cond;


int mid_serv_sock, mid_cli_sock;

static int create_socket( void )
{
    struct sockaddr_in serv_addr;
    int reuse = 1;
    int portno;

    mid_serv_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(mid_serv_sock < 0) {
        perror("createSocket failed");
        return (-1);
    }else{
        LOG("createSocket successfully");
    }

    memset((char *) &serv_addr, 0x0, sizeof(serv_addr));
    portno = 2037;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if(setsockopt(mid_serv_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0){
        perror("createSocket ERROR on setsockopt");
        close( mid_serv_sock );
        return (-1) ;
    }
    if(bind(mid_serv_sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0){
        perror("ERROR on binding");
        close( mid_serv_sock );
        return (-1);
    }

    return (0);
}

static void server_task(void * args)
{
    int clilen;
    struct sockaddr_in cli_addr;
    uint32_t nfds = 0;
    fd_set read_fds;
    int rc;
    struct timeval timeout;


    rc = create_socket();
    if(rc < 0){
        perror("createSocket() failed");
    }

    rc = listen(mid_serv_sock, 5);
    if ( rc < 0 ){
        close(mid_serv_sock);
        error("listen to server socket failed");
    } 

    clilen = sizeof(cli_addr);
    mid_cli_sock = accept(mid_serv_sock, (struct sockaddr *) &cli_addr, &clilen);
    if (mid_cli_sock < 0){
        LOG("accept() failed");
    }

    FD_ZERO(&read_fds);
    FD_SET(mid_cli_sock, &read_fds);
    nfds = nfds > (uint32_t)mid_serv_sock ? nfds :(uint32_t)mid_serv_sock;

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

        if(FD_ISSET(mid_cli_sock, &read_fds)){
            process_msg(mid_cli_sock);
        }
    }

    (void)close(mid_serv_sock);
    (void)close(mid_cli_sock);
    LOG("Exit server socket");
}

static void process_msg(int socket)
{
    int rc = 0;
    uint8_t response = 0;
    char buffer[256];
    int channel = 0;

    rc = recv(socket, &buffer, sizeof( buffer ), 0);
    if( rc <= 0 ){
        close( socket );
        error("Receive from client failed");
    }
    printf("Here is the message: %s", buffer );
    pthread_mutex_lock(&mid_lock);
    for(int channel = 0; channel < 10; channel ++){
        if(mid_buffs[channel].pid == 0){
            memcpy(mid_buffs[channel].mid_msg, buffer, 256);
            mid_buffs[channel].pid = pthread_self();
            str2hex(mid_buffs[channel].mid_msg);
            pthread_cond_signal( &mid_cond );
            LOG("data is %s, channel is %d", mid_buffs[channel].mid_msg, channel);
            break;
        }
        if (channel == 9){
            pthread_cond_wait(&mid_cond, &mid_lock);
            sleep(2);
            channel = 0;
        }
    }
    pthread_mutex_unlock(&mid_lock);

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

    memset( mid_buffs, 0x0, sizeof(mid_buffs) );
    rc = pthread_mutex_init( &mid_lock, NULL );
    if( rc != 0 ) error("pthread_mutex_init failed");
    rc = pthread_cond_init( &mid_cond, NULL );
    if( rc != 0 ) error("pthread_mutex_init failed");

    /* install signal handlers */
    signal(SIGTERM, catchterm); //signal that we need to exit
    signal(SIGALRM, catchalarm); //signal that an alarm has occurred
    signal(SIGHUP, catchhup); //signal telling up to read our config file
    signal(SIGINT, catchint); //signal for ctrl+c

    server_thread = start_server();

    sleep(20);
    rc = pthread_join(server_thread, NULL);
    if( rc != 0 ) error("server_thread join");

    LOG("sleep for some time");
    sleep(20);

    pthread_mutex_destroy(&mid_lock);
    pthread_cond_destroy(&mid_cond);

    return 0;

}


static void catchterm ( int signo  )
{
    LOG("SIGTERM received...PROXY is exiting \n");
    _exit ( 0  );
}
static void catchalarm ( int signo  )
{
    LOG("SIGALRM received...\n");
}
static void catchhup ( int signo  )
{
    LOG("SIGHUP received...\n");
}

static void catchint(int signo)
{
    LOG("SIGINT received...\n");
    if(mid_serv_sock != 0)
        close(mid_serv_sock);
    if(mid_cli_sock != 0)
        close(mid_cli_sock);
}
