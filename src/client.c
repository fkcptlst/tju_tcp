// #include "tju_tcp.h"
// #include <string.h>
// #include<signal.h>
//
// extern FILE *log_fp;
//
// int main(int argc, char **argv) {
//     TraceableInfo("start client\n");
//     // 开启仿真环境
//     startSimulation();
//
//     log_fp = NULL;
//     log_fp = fopen("/vagrant/tju_tcp/test/client.event.trace", "w");
//     Assert(log_fp != NULL, "Error opening log file\n");
//
//     tju_tcp_t* my_socket = tju_socket();
//     // printf("my_tcp state %d\n", my_socket->state);
//
//     tju_sock_addr target_addr;
//     target_addr.ip = inet_network("172.17.0.3");
//     target_addr.port = 1234;
//
//     tju_connect(my_socket, target_addr);
//     // printf("my_socket state %d\n", my_socket->state);
//
//     // uint32_t conn_ip;
//     // uint16_t conn_port;
//
//     // conn_ip = my_socket->established_local_addr.ip;
//     // conn_port = my_socket->established_local_addr.port;
//     // printf("my_socket established_local_addr ip %d port %d\n", conn_ip, conn_port);
//
//     // conn_ip = my_socket->established_remote_addr.ip;
//     // conn_port = my_socket->established_remote_addr.port;
//     // printf("my_socket established_remote_addr ip %d port %d\n", conn_ip, conn_port);
//
//     //sleep(3);
//
//     for(int i=0;i<50000;i++){
//         char buf[20];
//         sprintf(buf , "test message%d\n", i);
//         tju_send(my_socket, buf, 20);
//         TraceableInfo("send %d\n",i);
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
#include <fcntl.h>
#include <sys/stat.h>

#define MIN_LEN 1000
#define EACHSIZE (10*MIN_LEN)
#define MAXSIZE 50*MIN_LEN*MIN_LEN

// 全局变量
int t_times = 1;

void sleep_no_wake(int sec){
    do{
        sec =sleep(sec);
        FlushPrint("sleep interrupted, remaining sec: %d\n",sec);
    }while(sec > 0);
    FlushPrint("sleep finished\n");
}

int main(int argc, char **argv) {

    // 开启仿真环境
    startSimulation();

    tju_tcp_t* my_socket = tju_socket();

    tju_sock_addr target_addr;
    target_addr.ip = inet_network("172.17.0.3");
    target_addr.port = 1234;

    tju_connect(my_socket, target_addr);

    sleep_no_wake(1);

    int fd =  open("./rdt_send_file.txt",O_RDWR);
    if(-1 == fd) {
        perror("open file error");
        return 1;
    }
    struct stat st;
    fstat(fd, &st);
    char* file_buf  = (char *)malloc(sizeof(char)*st.st_size);
    read(fd, (void *)file_buf, st.st_size );
    close(fd);

    for(int i=0; i<t_times; i++){
        char *buf = malloc(EACHSIZE);
        memset(buf, 0, EACHSIZE);
        if(i<10){
            sprintf(buf , "START####%d#", i);
        }
        else if(i<100){
            sprintf(buf , "START###%d#", i);
        }
        else if(i<1000){
            sprintf(buf , "START##%d#", i);
        }
        else if(i<10000){
            sprintf(buf , "START#%d#", i);
        }

        strcat(buf, file_buf);
        tju_send(my_socket, buf, EACHSIZE);

//
//        if(i%1000 == 0){
//
//        FlushPrint("[RDT CLIENT] send begin:\n");
//        for (int i = 0; i < EACHSIZE; i++) {
//            if(buf[i] != '0' && buf[i] != '1')
//            {
//                FlushPrint(L_YELLOW("what?%c"), buf[i]);
//                if(buf[i] == '\0')
//                    FlushPrint(L_GREEN("it's null"));
//            }
//
////                    FlushPrint("%c", tmpbuf[i]);
//        }
//        FlushPrint("[RDT CLIENT] send end\n");
//
//        }




        free(buf);
    }

    free(file_buf);

    sleep_no_wake(2);
    tju_close(my_socket);
    sleep_no_wake(10000);

    return EXIT_SUCCESS;
}
