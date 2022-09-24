// #include "tju_tcp.h"
// #include <string.h>
// #include<signal.h>
//
// extern FILE *log_fp;
//
// int main(int argc, char **argv) {
//     // 开启仿真环境
//     startSimulation();
//
//     log_fp = NULL;
//     log_fp = fopen("/vagrant/tju_tcp/test/server.event.log", "w");
//     Assert(log_fp != NULL, "Error opening log file\n");
//
//     tju_tcp_t* my_server = tju_socket();
//     // printf("my_tcp state %d\n", my_server->state);
//
//     tju_sock_addr bind_addr;
//     bind_addr.ip = inet_network("172.17.0.3");
//     bind_addr.port = 1234;
//
//     tju_bind(my_server, bind_addr);
//
//     tju_listen(my_server);
//     // printf("my_server state %d\n", my_server->state);
//
//     tju_tcp_t* new_conn = tju_accept(my_server);
//     // printf("new_conn state %d\n", new_conn->state);
//
//     // uint32_t conn_ip;
//     // uint16_t conn_port;
//
//     // conn_ip = new_conn->established_local_addr.ip;
//     // conn_port = new_conn->established_local_addr.port;
//     // printf("new_conn established_local_addr ip %d port %d\n", conn_ip, conn_port);
//
//     // conn_ip = new_conn->established_remote_addr.ip;
//     // conn_port = new_conn->established_remote_addr.port;
//     // printf("new_conn established_remote_addr ip %d port %d\n", conn_ip, conn_port);
//
//
//     //sleep(5);
//
//     for (int i=0; i<50000; i++){
//         char buf[20];
//         tju_recv(new_conn, (void*)buf, 20);
//         // FlushPrint("[RDT TEST] server recv begin:");
//         // for(int j=0;j<16;j++)
//         // {
//         //     FlushPrint("%c",buf[j]);
//         // }
//
//         fflush(stdout);
//         TraceableInfo("recv %d\n",i);
//     }
//
//     char _c;
//     scanf("%c",&_c);
//     FlushPrint("finished\n");
//
//     fclose(log_fp);
//
//     return EXIT_SUCCESS;
// }
#include "tju_tcp.h"
#include <string.h>
#include <signal.h>
#include <stdio.h>

#define MIN_LEN 1000
#define EACHSIZE 10*MIN_LEN
#define MAXSIZE 50*MIN_LEN*MIN_LEN

int t_times = 5000;
char allbuf[MAXSIZE] = {'\0'}; //设置全局变量

void fflushbeforeexit(int signo){
    printf("意外退出server\n");

    FILE *wfile;
//    wfile = fopen("./rdt_recv_file.txt","w");
    wfile = fopen("./rdt_recv_file.cpp","w");
    if(wfile == NULL){
        printf("Error opening file\n");
        return;
    }
    size_t ret = fwrite(allbuf, sizeof(char), sizeof(allbuf), wfile);
    fclose(wfile);

    exit(0);
}

void sleep_no_wake(int sec){
    do{
        printf("Interrupted\n");
        sec =sleep(sec);
    }while(sec > 0);
}

int main(int argc, char **argv) {
    signal(SIGHUP, fflushbeforeexit);
    signal(SIGINT, fflushbeforeexit);
    signal(SIGQUIT, fflushbeforeexit);

    // 开启仿真环境
    startSimulation();

    tju_tcp_t* my_server = tju_socket();

    tju_sock_addr bind_addr;
    bind_addr.ip = inet_network("172.17.0.3");
    bind_addr.port = 1234;

    tju_bind(my_server, bind_addr);

    tju_listen(my_server);

    tju_tcp_t* new_conn = tju_accept(my_server);

    sleep_no_wake(1);

    int alllen = 0;
    int print_s = 0;

    int tmp=0;
    while(alllen < t_times*EACHSIZE){

        if(alllen / (EACHSIZE*10) > tmp){
            tmp++;
            FlushPrint(L_GREEN("recv %d\n"), alllen);
        }

        char *buf = malloc(EACHSIZE);
        memset(buf, 0, EACHSIZE);
        int len = tju_recv(new_conn, (void*)buf, EACHSIZE);
//        if(len < EACHSIZE)
//        {
//            FlushPrint(L_CYAN("recv %d instead of %d\n"), len, EACHSIZE);
//        }
        if(len<0){
            printf("tju_recv error!\n");
            break;
        }

        // strcat(allbuf, buf);
        memcpy(allbuf+alllen, buf, len);
        alllen += len;
        free(buf);

        if(print_s+EACHSIZE <= alllen){
            char tmpbuf[EACHSIZE] = {'\0'};
            memcpy(tmpbuf, allbuf+print_s, EACHSIZE);
//            printf("[RDT TEST] server recv %s\n", tmpbuf);

//            if(alllen % (EACHSIZE*100) == 0) {
//                FlushPrint("[RDT SERVER] recv begin:\n");
//                for (int i = 0; i < EACHSIZE; i++) {
//                    if(tmpbuf[i] != '0' && tmpbuf[i] != '1')
//                    {
//                        FlushPrint(L_YELLOW("what?%c"), tmpbuf[i]);
//                        if(tmpbuf[i] == '\0')
//                            FlushPrint(L_GREEN("it's null"));
//                    }
//
////                    FlushPrint("%c", tmpbuf[i]);
//                }
//                FlushPrint("[RDT SERVER] recv end\n");
//            }

            print_s += EACHSIZE;
        }
        fflush(stdout);
    }

    FILE *wfile;
    wfile = fopen("./rdt_recv_file.txt","w");
    if(wfile == NULL){
        printf("Error opening file\n");
        return -1;
    }
    size_t ret = fwrite(allbuf, sizeof(char), sizeof(allbuf), wfile);
    fclose(wfile);

    sleep_no_wake(100);

    return EXIT_SUCCESS;
}
