#ifndef _TJU_TCP_H_
#define _TJU_TCP_H_

#include "global.h"
#include "tju_packet.h"
#include "kernel.h"

extern FILE *log_fp;

/*
创建 TCP socket 
初始化对应的结构体
设置初始状态为 CLOSED
*/
tju_tcp_t* tju_socket();

/*
绑定监听的地址 包括ip和端口
*/
int tju_bind(tju_tcp_t* sock, tju_sock_addr bind_addr);

/*
被动打开 监听bind的地址和端口
设置socket的状态为LISTEN
*/
int tju_listen(tju_tcp_t* sock);

/*
接受连接 
返回与客户端通信用的socket
这里返回的socket一定是已经完成3次握手建立了连接的socket
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
tju_tcp_t* tju_accept(tju_tcp_t* sock);


/*
连接到服务端
该函数以一个socket为参数
调用函数前, 该socket还未建立连接
函数正常返回后, 该socket一定是已经完成了3次握手, 建立了连接
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
int tju_connect(tju_tcp_t* sock, tju_sock_addr target_addr);


int tju_send (tju_tcp_t* sock, const void *buffer, int len);
int tju_recv (tju_tcp_t* sock, void *buffer, int len);

/*
关闭一个TCP连接
这里涉及到四次挥手
*/
int tju_close (tju_tcp_t* sock);


int tju_handle_packet(tju_tcp_t* sock, char* pkt);


//// socket queue related functions
void init_sock_queue(tju_sock_queue_t *q);
int queue_length(tju_sock_queue_t *q);
int is_queue_empty(tju_sock_queue_t *q);
int is_queue_full(tju_sock_queue_t *q);
int enqueue(tju_sock_queue_t *queue_object_ptr, tju_tcp_t *socket_ptr);
socket_node_t *pop_via_hashval(tju_sock_queue_t *q, int hashval);
socket_node_t* dequeue(tju_sock_queue_t *q);

//// sending and retransmitting threads
int create_sending_and_retrans_thread(int hashval, pthread_t sending_thread_id, pthread_t retrans_thread_id);
void *sending_thread(void *arg);
void *retrans_thread(void *arg);

/// connection timeout thread
void conn_startTimer();
void conn_stopTimer();
void create_conn_retrans_thread(tju_tcp_t *sock);
void terminate_conn_timer_and_thread(tju_tcp_t *sock);
void conn_retrans_handler(tju_tcp_t *in_sock);
/// util
void tcp_connection_management_message_to_layer3(uint16_t src_port, uint16_t dst_port, uint32_t seqnum,uint32_t acknum,uint8_t flags, uint8_t trans_control_flag);

void adjust_RTO(tju_tcp_t *sock,struct timeval receive_time,uint32_t ack);

void congestion_control(tju_tcp_t *sock,int status);
#endif

