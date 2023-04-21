#include "tju_tcp.h"
#include "log.h"

int TimerStopped = 1;
int ConnTimerStopped = 1;

int CloseInitiated = 0; // buffer empty, ready to close

int is_closing = 0; // marks if the socket is closing

/*
创建 TCP socket
初始化对应的结构体
设置初始状态为 CLOSED
*/
FILE *log_fp;
// void adjust_RTO(tju_tcp_t *sock, struct timeval receive_time, uint32_t ack)
// {
//     // struct timeval send_time = sock->sendtime_hash[ack % 1024];
//     uint32_t sample_rtt;
//     uint32_t estmated_rtt = sock->window.wnd_send->estmated_rtt;
//     uint32_t dev_rtt = sock->window.wnd_send->dev_rtt;

//     sample_rtt = 1000000 * (receive_time.tv_sec - send_time.tv_sec) + (receive_time.tv_sec - send_time.tv_sec);
//     sock->window.wnd_send->estmated_rtt = 0.875 * estmated_rtt + 0.125 * sample_rtt;
//     sock->window.wnd_send->dev_rtt = 0.75 * dev_rtt + (sample_rtt > estmated_rtt) ? (sample_rtt - estmated_rtt) : (estmated_rtt - sample_rtt);

//     uint32_t timeoutInterval = sock->window.wnd_send->estmated_rtt + 4 * sock->window.wnd_send->dev_rtt;

//     sock->window.wnd_send->timeout.tv_sec = timeoutInterval / 1000000;
//     sock->window.wnd_send->timeout.tv_usec = timeoutInterval % 1000000;
// }
void retrans_handler(tju_tcp_t *in_sock) {
    static tju_tcp_t *sock = NULL;
    if (in_sock != NULL) {
        sock = in_sock;
        return;
    } else {
        RETRANS = 1;
        //congestion_control(sock, TIME_OUT);
    }
}

void timeout_handler(int signo) {

    // TraceableInfo("TIME OUT\n");
    retrans_handler(NULL);

    return;
}

void startTimer(tju_tcp_t *sock) {
    if (ConnTimerStopped == 0) // signal is already registered by conn_timer
    {
        return;
    }
    TimerStopped = 0;
    struct itimerval tick;
    RETRANS = 0;
    retrans_handler(sock);
    signal(SIGALRM, timeout_handler);
    // tick.it_value.tv_sec = sock->window.wnd_send->timeout.tv_sec;
    // tick.it_value.tv_usec = sock->window.wnd_send->timeout.tv_usec;
    tick.it_value.tv_sec = 0;
    tick.it_value.tv_usec = 50000;
    tick.it_interval.tv_sec = 0;
    tick.it_interval.tv_usec = 0;

    if (setitimer(ITIMER_REAL, &tick, NULL) < 0)
        printf("Set timer failed!\n");

    // TraceableInfo("start timer\n");
    return;
}

void stopTimer(void) {
    TimerStopped = 1;
    RETRANS = 0;
    struct itimerval value;
    value.it_value.tv_sec = 0;
    value.it_value.tv_usec = 0;
    value.it_interval.tv_sec = 0;
    value.it_interval.tv_usec = 0;

    // TraceableInfo("stop timer\n");
    setitimer(ITIMER_REAL, &value, NULL);

    return;
}

void *sending_thread(void *arg) {
    int hashval = *((int *) arg);
    tju_tcp_t *sock = established_socks[hashval];
    // TraceableInfo("进入发送线程\n");
    while (1) {
        sending_thread_loop_start:

        if(CloseInitiated) // connection close initiated. don't send any more data
            return NULL;

        sock->window.wnd_send->swnd = min(sock->window.wnd_send->cwnd, sock->window.wnd_send->rwnd);
        //uint32_t size = sock->window.wnd_send->swnd * MAX_DLEN;  to debug
        uint32_t size = 28 * MAX_DLEN;
        uint32_t base = sock->window.wnd_send->base;
        uint32_t nextseq = sock->window.wnd_send->nextseq;


        //TraceableInfo("没进来\n");
        //TraceableInfo("没进来了1 sent_len=%d sending_len=%d nextseq=%d base=%d size=%d \n",sent_len,sock->sending_len,nextseq,base,size);
        if (sock->sent_len < sock->sending_len && nextseq < base + size) {
            // TraceableInfo("进来了1 allto= %d sent_len=%d sending_len=%d nextseq=%d base=%d size=%d\n",sock->allto,sock->sent_len,sock->sending_len,nextseq,base,size);
            while (pthread_mutex_lock(&(sock->send_lock)) != 0); // 给发送缓冲区加锁

            //  TraceableInfo("remain %d\n",sock->sending_len-sock->sent_len);
            /*要发送的都落在窗口内*/
            if (sock->sending_len - sock->sent_len <= size - (nextseq - base)) {

                /*一个包装不下*/
                while (sock->sending_len - sock->sent_len > MAX_DLEN) {
                    char *msg;
                    uint32_t seq = nextseq;
                    uint16_t plen = DEFAULT_HEADER_LEN + MAX_DLEN;


                    tju_packet_t *pkt = create_packet(sock->established_local_addr.port,
                                                      sock->established_remote_addr.port, seq, 1,
                                                      DEFAULT_HEADER_LEN, plen, NO_FLAG, 32, 0,
                                                      sock->sending_buf + sock->sent_len, MAX_DLEN);

                    msg = packet_to_buf(pkt);

                    // struct timeval sendtime;
                    // gettimeofday(&sendtime, NULL);
                    sendToLayer3(msg, plen);
                    //SENDLog("[seq:%d ack:%d flags:%s]\r\n",seq,1,"");
                    int index = (seq + MAX_DLEN) % 1024;
                    // sock->sendtime_hash[index] = sendtime;

                    TraceableInfo("发送 %d 字节大小的报文 seq = %d\n", MAX_DLEN, seq);
                    if (base == nextseq) {
                        startTimer(sock);
                    }

                    nextseq += MAX_DLEN;
                    sock->sent_len += MAX_DLEN;

                    free(msg);
                    free_packet(pkt);
                }
                char *msg;
                uint32_t seq = nextseq;
                uint32_t len = sock->sending_len - sock->sent_len;
                uint16_t plen = DEFAULT_HEADER_LEN + (len);

                if (len == 0 && sock->sent_len != 0) {

                    pthread_mutex_unlock(&(sock->send_lock)); // 解锁
                    sock->window.wnd_send->nextseq = nextseq;
                    sock->sent_len = 0;

                    goto sending_thread_loop_start;
                }
                if (len == 0) {

                    pthread_mutex_unlock(&(sock->send_lock)); // 解锁
                    sock->window.wnd_send->nextseq = nextseq;


                    goto sending_thread_loop_start;
                }

                tju_packet_t *pkt = create_packet(sock->established_local_addr.port, sock->established_remote_addr.port,
                                                  seq, 1,
                                                  DEFAULT_HEADER_LEN, plen, NO_FLAG, 32, 0,
                                                  sock->sending_buf + sock->sent_len, len);
                msg = packet_to_buf(pkt);
                // struct timeval sendtime;
                // gettimeofday(&sendtime, NULL);
                sendToLayer3(msg, plen);
                //SENDLog("[seq:%d ack:%d flags:%s]\r\n",seq,1,"");
                // int index = (seq + len) % 1024;
                // sock->sendtime_hash[index] = sendtime;
                // TraceableInfo("data begin:\n");
                // for (int __i = 0; __i < len; __i++)
                // {
                //     FlushPrint("%c", *(data + __i));
                // }
                // TraceableInfo("data end\n");
                TraceableInfo("发送 %d 字节大小的报文 seq = %d\n", len, seq);
                if (base == nextseq) {
                    startTimer(sock);
                }
                nextseq += sock->sending_len - sock->sent_len;
                sock->sent_len += sock->sending_len - sock->sent_len;

                sock->window.wnd_send->nextseq = nextseq;


                pthread_mutex_unlock(&(sock->send_lock)); // 解锁

                free(msg);
                free_packet(pkt);
            }
                /*有落在窗口外面的*/
            else if (sock->sending_len - sock->sent_len > size - (nextseq - base)) {
                while (size - (nextseq - base) > MAX_DLEN) {
                    char *msg;
                    uint32_t seq = nextseq;
                    uint16_t plen = DEFAULT_HEADER_LEN + MAX_DLEN;


                    tju_packet_t *pkt = create_packet(sock->established_local_addr.port,
                                                      sock->established_remote_addr.port, seq, 1,
                                                      DEFAULT_HEADER_LEN, plen, NO_FLAG, 32, 0,
                                                      sock->sending_buf + sock->sent_len, MAX_DLEN);

                    msg = packet_to_buf(pkt);
                    // struct timeval sendtime;
                    // gettimeofday(&sendtime, NULL);
                    sendToLayer3(msg, plen);
                    //SENDLog("[seq:%d ack:%d flags:%s]\r\n",seq,1,"");
                    // int index = (seq + MAX_DLEN) % 1024;
                    // sock->sendtime_hash[index] = sendtime;

                    TraceableInfo("发送 %d 字节大小的报文 seq = %d\n", MAX_DLEN, seq);
                    if (base == nextseq) {
                        startTimer(sock);
                    }
                    nextseq += MAX_DLEN;
                    sock->sent_len += MAX_DLEN;

                    free(msg);
                    free_packet(pkt);
                }
                char *msg;
                uint32_t seq = nextseq;
                uint32_t len = size - (nextseq - base);
                uint16_t plen = DEFAULT_HEADER_LEN + len;
                if (len == 0) {
                    pthread_mutex_unlock(&(sock->send_lock)); // 解锁
                    sock->window.wnd_send->nextseq = nextseq;
                    sock->sent_len = sock->sent_len;

                    goto sending_thread_loop_start;

                }

                tju_packet_t *pkt = create_packet(sock->established_local_addr.port, sock->established_remote_addr.port,
                                                  seq, 1,
                                                  DEFAULT_HEADER_LEN, plen, NO_FLAG, 32, 0,
                                                  sock->sending_buf + sock->sent_len, len);
                msg = packet_to_buf(pkt);
                // struct timeval sendtime;
                // gettimeofday(&sendtime, NULL);
                sendToLayer3(msg, plen);
                //SENDLog("[seq:%d ack:%d flags:%s]\r\n",seq,1,"");
                // int index = (seq + len) % 1024;
                // sock->sendtime_hash[index] = sendtime;
                // TraceableInfo("data begin:\n");
                // for (int __i = 0; __i < len; __i++)
                // {
                //     FlushPrint("%c", *(data + __i));
                // }
                // TraceableInfo("data end\n");

                TraceableInfo("发送 %d 字节大小的报文 seq = %d\n", len, seq);
                if (base == nextseq) {
                    startTimer(sock);
                }
                nextseq += len;
                sock->sent_len += len;

                sock->window.wnd_send->nextseq = nextseq;


                pthread_mutex_unlock(&(sock->send_lock)); // 解锁

                free(msg);
                free_packet(pkt);

            }
        }
    }
}

void *retrans_thread(void *arg) {
    int hashval = *((int *) arg);
    tju_tcp_t *sock = established_socks[hashval];
    // TraceableInfo(L_YELLOW("进入重传线程\n"));
    while (1) {
        if(CloseInitiated) // close initiated, exit
            return NULL;
        if(TimerStopped == 0)
        {
            unsigned int remain_time = ualarm(10000, 0);
            ualarm(remain_time, 0);
            if (remain_time == 0) {
                TimerStopped = 1;
                raise(SIGALRM);
            }
        }

        if (RETRANS) {
            RETRANS = 0;

            while (pthread_mutex_lock(&(sock->send_lock)) != 0); // 给发送缓冲区加锁


            uint32_t retrans_size = sock->window.wnd_send->nextseq - sock->window.wnd_send->base;
            uint32_t retransed_size = 0;

            // 需发送的数据大于MAX_DLEN
            if (retrans_size > MAX_DLEN) {  // TODO retrans

                char *msg;
                uint32_t seq = sock->window.wnd_send->base + retransed_size;
                uint16_t plen = DEFAULT_HEADER_LEN + MAX_DLEN;


                tju_packet_t *pkt = create_packet(sock->established_local_addr.port, sock->established_remote_addr.port,
                                                  seq, 1,
                                                  DEFAULT_HEADER_LEN, plen, NO_FLAG, 32, 0,
                                                  sock->sending_buf + retransed_size, MAX_DLEN);

                msg = packet_to_buf(pkt);
                // struct timeval sendtime;
                // gettimeofday(&sendtime, NULL);
                sendToLayer3(msg, plen);
//                TraceableInfo("重传 %d 字节大小的报文 seq = %d\n", MAX_DLEN, seq);
                //SENDLog("[seq:%d ack:%d flags:%s]\r\n",seq,1,"");
                // int index = (seq + MAX_DLEN) % 1024;
                // sock->sendtime_hash[index] = sendtime;

                if (retransed_size == 0) {
                    startTimer(sock);
                }

                retransed_size += MAX_DLEN;
                retrans_size -= MAX_DLEN;

                free(msg);
                free_packet(pkt);

                // TraceableInfo("重传 1375 大小的报文 seq = %d\n", seq);
            }
            else {


                char *msg;
                uint32_t seq = sock->window.wnd_send->base + retransed_size;
                uint32_t len = retrans_size;
                uint16_t plen = DEFAULT_HEADER_LEN + len;

                tju_packet_t *pkt = create_packet(sock->established_local_addr.port, sock->established_remote_addr.port,
                                                  seq, 1,
                                                  DEFAULT_HEADER_LEN, plen, NO_FLAG, 32, 0,
                                                  sock->sending_buf + retransed_size, len);

                msg = packet_to_buf(pkt);
                // struct timeval sendtime;
                // gettimeofday(&sendtime, NULL);
                sendToLayer3(msg, plen);
                TraceableInfo("重传 %d 字节大小的报文 seq = %d\n", len, seq);
                //SENDLog("[seq:%d ack:%d flags:%s]\r\n",seq,1,"");
                // int index = (seq + len) % 1024;
                // sock->sendtime_hash[index] = sendtime;
                if (retransed_size == 0) {
                    startTimer(sock);
                }

                retransed_size += len;
                retrans_size -= len;
                // TraceableInfo("重传 %d 大小的报文 seq = %d\n", len, seq);



                free(msg);
                free_packet(pkt);
            }
            pthread_mutex_unlock(&(sock->send_lock)); // 解锁   // TODO retrans
        }
    }
}

tju_tcp_t *tju_socket() {
    /// set priority to max


    tju_tcp_t *sock = (tju_tcp_t *) malloc(sizeof(tju_tcp_t));
    sock->state = CLOSED;

    pthread_mutex_init(&(sock->send_lock), NULL);
    sock->sending_buf = NULL;
    sock->sending_len = 0;
    sock->sent_len = 0;
    sock->allto = 0;

    pthread_mutex_init(&(sock->recv_lock), NULL);
    sock->received_buf = NULL;
    sock->received_len = 0;

    pthread_mutex_init(&(sock->sending_buffer_empty_lock), NULL);

    if (pthread_cond_init(&sock->wait_cond, NULL) != 0) {
        perror("ERROR condition variable not set\n");
        exit(-1);
    }

    sock->window.wnd_recv = NULL;
    sock->window.wnd_recv = NULL;

    sock->window.wnd_send = (sender_window_t *) malloc(sizeof(sender_window_t));
    sock->window.wnd_recv = (receiver_window_t *) malloc(sizeof(receiver_window_t));

    sock->window.wnd_send->base = 1;
    sock->window.wnd_send->nextseq = 1;
    sock->window.wnd_send->rwnd = TCP_RECVWN_SIZE / MAX_DLEN;
    sock->window.wnd_send->cwnd = 1;
    sock->window.wnd_send->ssthresh = 16;
    pthread_mutex_init(&(sock->window.wnd_send->ack_cnt_lock), NULL);
    sock->window.wnd_send->ack_cnt = 0;

    sock->window.wnd_send->timeout.tv_sec = 0;
    sock->window.wnd_send->timeout.tv_usec = 500000;
    sock->window.wnd_send->estmated_rtt = 500000;
    sock->window.wnd_send->dev_rtt = 0;

    // memset(sock->sendtime_hash, 0, 1024 * sizeof(struct timeval));

    sock->window.wnd_recv->expect_seq = 1;

    int buf_max_size = 1024 * 1024 * 60; //XXX
    char hostname[8];
    gethostname(hostname, 8);
    if (strcmp(hostname, "server") == 0)
        sock->received_buf = (char *) malloc(buf_max_size); //XXX
    else if (strcmp(hostname, "client") == 0)
        sock->sending_buf = (char *) malloc(buf_max_size); //XXX

    return sock;
}

/*
绑定监听的地址 包括ip和端口
*/
int tju_bind(tju_tcp_t *sock, tju_sock_addr bind_addr) {
    int hash = bind_addr.port;
    // if port is available, then bind it
    if (bhash[hash] == 0) {
        bhash[hash] = 1; // set bhash to 1
        sock->bind_addr = bind_addr;
        return 0;
    } else {
        return -1; // port is not available
    }
}

/*
被动打开 监听bind的地址和端口
设置socket的状态为LISTEN
注册该socket到内核的监听socket哈希表
*/
int tju_listen(tju_tcp_t *sock) {
    sock->state = LISTEN;
    int hashval = cal_hash(sock->bind_addr.ip, sock->bind_addr.port, 0, 0);
    // add to lhash
    listen_socks[hashval] = sock;
    init_sock_queue(&(sock->socket_queue.half_conn_socks));
    init_sock_queue(&(sock->socket_queue.fully_conn_socks));
    return 0;
}

/**
 * 接受连接
 * 返回与客户端通信用的socket
 * 这里返回的socket一定是已经完成3次握手建立了连接的socket
 * 因为只要该函数返回, 用户就可以马上使用该socket进行send和recv,
 * 也就是说，无可连接socket时阻塞等待，一旦建立一个则返回成功的socket
 * @param listen_sock The socket that is listening for connections.
 * @return The socket that is connected to the client.
 */
tju_tcp_t *tju_accept(tju_tcp_t *listen_sock) {

    while (is_queue_empty(
            &(listen_sock->socket_queue.fully_conn_socks)));                                                                                  // wait if full connected socket queue is empty
    socket_node_t *new_conn_node = dequeue(&(listen_sock->socket_queue.fully_conn_socks)); // 已连接的出队列一个
    tju_tcp_t *new_conn = new_conn_node->socket_ptr;
    //    memcpy(new_conn, listen_sock, sizeof(tju_tcp_t));

    //    tju_sock_addr local_addr, remote_addr;
    /*
     这里涉及到TCP连接的建立
     正常来说应该是收到客户端发来的SYN报文
     从中拿到对端的IP和PORT
     换句话说 下面的处理流程其实不应该放在这里 应该在tju_handle_packet中
    */
    //    remote_addr.ip = inet_network("172.17.0.2");  //具体的IP地址
    //    remote_addr.port = 5678;  //端口
    //
    //    local_addr.ip = listen_sock->bind_addr.ip;  //具体的IP地址
    //    local_addr.port = listen_sock->bind_addr.port;  //端口

    //    new_conn->established_local_addr = local_addr;
    //    new_conn->established_remote_addr = remote_addr;

    // 这里应该是经过三次握手后才能修改状态为ESTABLISHED
    //    new_conn->state = ESTABLISHED;

    // 将新的conn放到内核建立连接的socket哈希表中
    //    int hashval = cal_hash(local_addr.ip, local_addr.port, remote_addr.ip, remote_addr.port);

    // after connection established:
    established_socks[new_conn_node->sock_hashval] = new_conn; // add established sock

    // 如果new_conn的创建过程放到了tju_handle_packet中 那么accept怎么拿到这个new_conn呢
    // 在linux中 每个listen socket都维护一个已经完成连接的socket队列
    // 每次调用accept 实际上就是取出这个队列中的一个元素
    // 队列为空,则阻塞

    // create_sending_and_retrans_thread(new_conn_node->sock_hashval, 2049, 2050); // 创建发送和重传线程
    return new_conn;
}

/*
连接到服务端
该函数以一个socket为参数
调用函数前, 该socket还未建立连接
函数正常返回后, 该socket一定是已经完成了3次握手, 建立了连接
因为只要该函数返回, 用户就可以马上使用该socket进行send和recv
*/
int tju_connect(tju_tcp_t *sock, tju_sock_addr target_addr) {

    sock->established_remote_addr = target_addr;

    tju_sock_addr local_addr;
    local_addr.ip = inet_network("172.17.0.2");
    local_addr.port = 5678; // 连接方进行connect连接的时候 内核中是随机分配一个可用的端口
    sock->established_local_addr = local_addr;

    // 这里也不能直接建立连接 需要经过三次握手
    // 实际在linux中 connect调用后 会进入一个while循环
    // 循环跳出的条件是socket的状态变为ESTABLISHED 表面看上去就是 正在连接中 阻塞
    // 而状态的改变在别的地方进行 在我们这就是tju_handle_packet
    //    sock->state = ESTABLISHED;

    int hashval = cal_hash(local_addr.ip, local_addr.port, target_addr.ip, target_addr.port);
    established_socks[hashval] = sock; // note that established_socks doesn't
    // necessarily mean it's established, since the main thread is blocked by tju_connect()

    /// first send SYN
    tcp_connection_management_message_to_layer3(local_addr.port, target_addr.port,
                                                CLIENT_CONN_SEQ, 0, SYN_FLAG_MASK, CONN_MODE_SEND);

    /// create connection management retrans thread to handle loss during connection
    create_conn_retrans_thread(sock);

    TraceableInfo("client tju_connect called\n");

    /// state change to SYN_SENT
    sock->state = SYN_SENT;

    /// wait until established
    while (sock->state != ESTABLISHED);

    /// established!

    terminate_conn_timer_and_thread(sock);

    /// create send and retrans threads
    create_sending_and_retrans_thread(hashval, 1004, 1005);

    fflush(stdout);
    sleep(1);
    return 0;
}

int tju_send(tju_tcp_t *sock, const void *buffer, int len) {
    // 这里当然不能直接简单地调用sendToLayer3
    // char* data = malloc(len);
    // memcpy(data, buffer, len);

    // char* msg;
    // uint32_t seq = 464;
    // uint16_t plen = DEFAULT_HEADER_LEN + len;

    // msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port, seq, 0,
    //           DEFAULT_HEADER_LEN, plen, NO_FLAG, 1, 0, data, len);

    // sendToLayer3(msg, plen);

    // 把收到的数据放到发送缓冲区

    while (pthread_mutex_lock(&(sock->send_lock)) != 0); // 加锁
//    sock->sending_buf = realloc(sock->sending_buf, sock->sending_len + len);
    memcpy(sock->sending_buf + sock->sending_len, buffer, len);
    sock->sending_len += len;
    sock->allto += len;

    pthread_mutex_unlock(&(sock->send_lock)); // 解锁

    return 0;
}

int tju_recv(tju_tcp_t *sock, void *buffer, int len) {
    while (sock->received_len <= 0) {
        // 阻塞
    }
    // TraceableInfo("离开阻塞\n");

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0); // 加锁

    int read_len = 0;
    if (sock->received_len >= len) { // 从中读取len长度的数据
        read_len = len;
    } else {
        read_len = sock->received_len; // 读取sock->received_len长度的数据(全读出来)
    }

    memcpy(buffer, sock->received_buf, read_len);

//    if (read_len < sock->received_len)
//    { // 还剩下一些
////        char *new_buf = malloc(sock->received_len - read_len);
////        memcpy(new_buf, sock->received_buf + read_len, sock->received_len - read_len); //XXX
////        free(sock->received_buf); //XXX
//        sock->received_len -= read_len;
//        sock->received_buf += read_len;
////        sock->received_buf = new_buf;
//    }
//    else
//    {
////        free(sock->received_buf);//XXX
////        sock->received_buf = NULL;///XXX
//        sock->received_len = 0;
//    }

    sock->received_len -= read_len;
    sock->received_buf += read_len;

    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁

    return read_len;
}


void Close(tju_tcp_t *sock) // a wrapper function
{
    do {
        int _hashval = cal_hash(sock->established_local_addr.ip, sock->established_local_addr.port,
                                sock->established_remote_addr.ip, sock->established_remote_addr.port);
        established_socks[_hashval] = NULL; // TODO mem leak
    } while (0);
    Success("connection successfully closed\n");
    conn_stopTimer();
}

int TimeWaitTimeout = 0;
tju_tcp_t *time_wait_sock = NULL;
void time_wait_handler(int signo) {
    TraceableInfo("TIME_WAIT timeout, closing connection\n");
    TimeWaitTimeout = 1;

    /// state transition
    time_wait_sock->state = CLOSED;

    Close(time_wait_sock);
}



int tju_handle_packet(tju_tcp_t *sock, char * pkt) {
    static int duplicate_ack_count = 0;

    uint32_t pkt_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
    uint8_t pkt_flag = get_flags(pkt);
    uint32_t seq_num = get_seq(pkt);
    uint32_t ack_num = get_ack(pkt);
    uint16_t pkt_adv_win = get_advertised_window(pkt);
    /// FSM
    switch (sock->state) {
        /// starting connection ---------------------------------------------------------------------------------------------------
        case LISTEN:
            do {
                int _hashval = cal_hash(sock->established_local_addr.ip, sock->established_local_addr.port,
                                        sock->established_remote_addr.ip, sock->established_remote_addr.port);
                socket_node_t *_node = pop_via_hashval(&(sock->socket_queue.half_conn_socks), _hashval);
                if (_node == NULL)
                    /// no matching half-connection socket, meaning current state is handshake 2, should enqueue half_conn_socks, and transit to SYN-RECV
                {

                    if (pkt_flag & SYN_FLAG_MASK) /// received SYN from client, handshake 1
                    {
                        /// send SYNACK
                        //RECVLog("[seq:%d ack:%d flags:%s]\r\n",seq_num,ack_num,"SYN");
                        tcp_connection_management_message_to_layer3(sock->established_local_addr.port,
                                                                    sock->established_remote_addr.port,
                                                                    SERVER_CONN_SEQ, seq_num + 1,
                                                                    SYN_FLAG_MASK | ACK_FLAG_MASK, CONN_MODE_SEND);

                        /// enqueue halfconn socket
                        tju_tcp_t *new_halfconn_sock = tju_socket();
                        memcpy(new_halfconn_sock, sock, sizeof(tju_tcp_t));
                        new_halfconn_sock->established_remote_addr = sock->established_remote_addr; // soft copy, since struct has no ptr
                        new_halfconn_sock->established_local_addr = sock->established_local_addr;

                        TraceableInfo("LISTEN -> SYN_RECV\n");
                        /// create connection management retrans thread to handle loss during connection
                        create_conn_retrans_thread(sock);

                        /// state transition
                        new_halfconn_sock->state = SYN_RECV;

                        enqueue(&(sock->socket_queue.half_conn_socks), new_halfconn_sock);
                    } else {
                        // ERR
                        Error("");
                    }
                } else /// current is SYN-RECV, socket half connected, now check if incoming packet is ACK
                {
                    if (pkt_flag & ACK_FLAG_MASK) /// received SYN-ACK-ACK from client, handshake 3
                    {
                        //RECVLog("[seq:%d ack:%d flags:%s]\r\n",seq_num,ack_num,"ACK");
                        /// dequeue and enqueue
                        tju_tcp_t *new_fully_sock = _node->socket_ptr;
                        /// state transition
                        Success(" SERVER ESTABLISHED\n");
                        terminate_conn_timer_and_thread(sock);
                        new_fully_sock->state = ESTABLISHED;
                        enqueue(&(sock->socket_queue.fully_conn_socks), new_fully_sock);
                    } else if (pkt_flag & SYN_FLAG_MASK) // packet loss occurred during handshake 2, resend SYNACK
                    {
                        // RECVLog("[seq:%d ack:%d flags:%s]\r\n",seq_num,ack_num,"SYN");
                        /// put half conn sock back into queue
                        enqueue(&(sock->socket_queue.half_conn_socks), _node->socket_ptr);

                        tcp_connection_management_message_to_layer3(sock->established_local_addr.port,
                                                                    sock->established_remote_addr.port,
                                                                    0, 0,
                                                                    0, CONN_MODE_RESEND);
                        conn_stopTimer();
                        conn_startTimer(); // restart timer
                    } else {
                        // ERR
                        Error("Flag error: %d\n", pkt_flag);
                    }
                }

            } while (0);
            break;
        case SYN_SENT:
            if (pkt_flag & SYN_FLAG_MASK && pkt_flag & ACK_FLAG_MASK) /// received SYN-ACK from server, handshake 2
            {
                //RECVLog("[seq:%d ack:%d flags:%s]\r\n",seq_num,ack_num,"SYN|ACK");
                /// send ACK
                tcp_connection_management_message_to_layer3(sock->established_local_addr.port,
                                                            sock->established_remote_addr.port,

                                                            ack_num, seq_num + 1, ACK_FLAG_MASK, CONN_MODE_SEND);
                Success(" CLIENT ESTABLISHED\n");
                terminate_conn_timer_and_thread(sock);
                /// state transition
                sock->state = ESTABLISHED;
            }
                // TODO need further check
                //            else if (pkt_flag & SYN_FLAG_MASK && !(pkt_flag & ACK_FLAG_MASK))
                //            {
                //                /// send SYN-ACK
                //                tcp_connection_management_message_to_layer3(sock->established_local_addr.port,
                //                                                            sock->established_remote_addr.port,
                //                                                            ack_num, seq_num + 1, ACK_FLAG_MASK | SYN_FLAG_MASK, CONN_MODE_SEND);
                //                /// state transition
                //                sock->state = SYN_RECV;
                //            }
            else {
                // ERR
                Error("");
            }
            break;
            //        case SYN_RECV:
            //            if (pkt_flag & ACK_FLAG_MASK) /// received SYN-ACK-ACK from client, handshake 3
            //            {
            //                /// dequeue and enqueue
            //                int hashval = cal_hash(sock->established_local_addr.ip,sock->established_local_addr.port,
            //                                       sock->established_remote_addr.ip,sock->established_remote_addr.port);
            //                socket_node_t *node = pop_via_hashval(&(sock->socket_queue.half_conn_socks), hashval);
            //                tju_tcp_t * new_fully_sock = node->socket_ptr;
            //                new_fully_sock->state = ESTABLISHED;
            //                enqueue(&(sock->socket_queue.fully_conn_socks), new_fully_sock);
            //                /// state transition
            //                sock->state = ESTABLISHED;
            //            } else {
            //                // ERR
            //                  Error("");
            //            }
            //            break;
            /// established communication --------------------------------------------------------------------------------------------
            ///***************************//
        case ESTABLISHED:
            if (pkt_flag & FIN_FLAG_MASK) /// server received FIN from client, initiate closing connection
            {
                is_closing = 1;
                TraceableInfo("FIN 1 recvd, sending ACK 2\n");
                /// send ACK
                tcp_connection_management_message_to_layer3(sock->established_local_addr.port,
                                                            sock->established_remote_addr.port,
                                                            ack_num, seq_num + 1, ACK_FLAG_MASK, CONN_MODE_SEND);
                /// state transition
                sock->state = CLOSE_WAIT;
                goto CLOSE_WAIT_lbl;
            } else if (pkt_flag & SYN_FLAG_MASK && pkt_flag & ACK_FLAG_MASK) // packet loss during handshake 3
            {
                //RECVLog("[seq:%d ack:%d flags:%s]\r\n",seq_num,ack_num,"SYN|ACK");
                tcp_connection_management_message_to_layer3(sock->established_local_addr.port,
                                                            sock->established_remote_addr.port,
                                                            0, 0,
                                                            0, CONN_MODE_RESEND);
                TraceableInfo("client heard SYN-ACK\n");
            } else if (pkt_flag == NO_FLAG) {
                // TODO RDT implementation here
                while (pthread_mutex_lock(&(sock->recv_lock)) != 0); // 加锁

                //RECVLog("[seq:%d ack:%d flags:%s]\r\n",seq_num,ack_num,"");

                // 收到的报文的序列号是期待的序列号
                if (seq_num == sock->window.wnd_recv->expect_seq) {
                    uint32_t data_len = get_plen(pkt) - DEFAULT_HEADER_LEN;
                    // 把收到的数据放到接受缓冲区

                    if (sock->received_buf == NULL) {
//                    sock->received_buf = malloc(data_len); //XXX
                        Error("should not be here!\n");
                    } else {
//                    sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len); //XXX
                    }
                    memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN, data_len);
                    // TraceableInfo("datalen:%d   data begin:\n",data_len);
                    // for (int __i = 0; __i < data_len; __i++)
                    // {
                    //     FlushPrint("%c", *(sock->received_buf + sock->received_len + __i));
                    // }
                    // TraceableInfo("data end\n");

                    sock->received_len += data_len;
                    sock->window.wnd_recv->expect_seq = seq_num + data_len;

                    uint32_t seq = sock->window.wnd_send->nextseq;
                    uint32_t ack = sock->window.wnd_recv->expect_seq;

                    char *msg = create_packet_buf(sock->established_local_addr.port, sock->established_remote_addr.port,
                                                  seq, ack,
                                                  DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK,
                                                  (TCP_RECVWN_SIZE - sock->received_len) / MAX_DLEN, 0, NULL, 0);

//                TraceableInfo("收到seq = %d 的报文  发送ACK报文 ack = %d\n", seq_num, ack);

                    sendToLayer3(msg, DEFAULT_HEADER_LEN);
                    //SENDLog("[seq:%d ack:%d flags:%s]\r\n",seq,ack,"ACK");

                    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁

                    free(msg);
                    return 0;
                } else //不是期待的
                {

                    uint32_t seq = sock->window.wnd_send->nextseq;
                    uint32_t ack = sock->window.wnd_recv->expect_seq;

                    tju_packet_t *pkt = create_packet(sock->established_local_addr.port,
                                                      sock->established_remote_addr.port, seq, ack,
                                                      DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, ACK_FLAG_MASK,
                                                      (TCP_RECVWN_SIZE - sock->received_len) / MAX_DLEN, 0, NULL, 0);
                    char *msg = packet_to_buf(pkt);
                    sendToLayer3(msg, DEFAULT_HEADER_LEN);  // ACK
                    //SENDLog("[seq:%d ack:%d flags:%s]\r\n",seq,ack,"ACK");
//                 TraceableInfo("收到seq = %d 丢弃报文 发送ACK报文 ack = %d\n", seq_num, ack);
                    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁

                    free(msg);
                    free_packet(pkt);
                    return 0;
                }
            }
                // 收到的是ACK报文
            else if (pkt_flag == ACK_FLAG_MASK) {
                while (pthread_mutex_lock(&(sock->send_lock)) != 0);

                //RECVLog("[seq:%d ack:%d flags:%s]\r\n",seq_num,ack_num,"ACK");
                //  收到的ack报文在发送窗口外 直接丢弃
                if (ack_num < sock->window.wnd_send->base) {
                    // TraceableInfo("收到的ack报文在发送窗口外 丢弃报文 \n");
                }

                    // 表示开始收到重复ACK
                else if (ack_num == sock->window.wnd_send->base) {
                    duplicate_ack_count++;
                    if(duplicate_ack_count >= 3)
                    {
                        TraceableInfo("收到3个重复ACK 重传报文\n");
                        duplicate_ack_count = 0;
                        RETRANS=1;

                        //SENDLog("[seq:%d ack:%d flags:%s]\r\n",pkt->seq_num,pkt->ack_num,"");
                    }
                    // while (pthread_mutex_lock(&(sock->window.wnd_send->ack_cnt_lock)) != 0)
                    //     ;

                    // sock->window.wnd_send->ack_cnt += 1;
                    // pthread_mutex_unlock(&(sock->window.wnd_send->ack_cnt_lock));

                    // if (sock->window.wnd_send->ack_cnt == 3)
                    // {
                    //     //congestion_control(sock, FAST_RECOVERY);
                    // }
                }

                    // 收到可用于更新的ACK
                else {
                    duplicate_ack_count = 0;
                    // while (pthread_mutex_lock(&(sock->window.wnd_send->ack_cnt_lock)) != 0)
                    //     ;

                    // sock->window.wnd_send->ack_cnt = 0;
                    // pthread_mutex_unlock(&(sock->window.wnd_send->ack_cnt_lock));

                    // if (sock->window.wnd_send->cwnd < sock->window.wnd_send->ssthresh)
                    // {
                    //     congestion_control(sock, SLOW_START);
                    // }
                    // else if (sock->window.wnd_send->cwnd >= sock->window.wnd_send->ssthresh)
                    // {
                    //     congestion_control(sock, CONGESTION_AVOIDANCE);
                    // }
                    TraceableInfo("收到ACK报文 ack=%d\n", ack_num);

                    uint32_t free_len = ack_num - sock->window.wnd_send->base;
                    sock->window.wnd_send->base = ack_num;

                    if (sock->window.wnd_send->base == sock->window.wnd_send->nextseq) {
                        stopTimer();
                    } else {
                        stopTimer();
                        startTimer(sock);
                    }
                    // struct timeval receive_time;
                    // gettimeofday(&receive_time, NULL);
                    // adjust_RTO(sock, receive_time, ack_num);
//                char *new_buf = malloc(sock->sending_len - free_len); //XXX
//                memcpy(new_buf, sock->sending_buf + free_len, sock->sending_len - free_len); //XXX

//                free(sock->sending_buf); //XXX

                    // TraceableInfo("sumfree=%d freelen=%d sending_len=%d sent_len=%d\n",sum,free_len,sock->sending_len,sock->sent_len);


                    sock->sending_len -= free_len;
                    sock->sent_len -= free_len;
                    sock->sending_buf += free_len; //XXX
                    // sock->sending_buf = new_buf; //XXX


                    // TraceableInfo("sumfree=%d freelen=%d sending_len=%d sent_len=%d\n",sum,free_len,sock->sending_len,sock->sent_len);
                    // TraceableInfo("data begin:\n");
                    // for (int __i = 0; __i < len; __i++)
                    // {
                    //     FlushPrint("%c", *(data + __i));
                    // }
                    // TraceableInfo("data end\n");
                    // if(sock->sending_len==sock->sent_len){
                    // sock->sent_len=0;
                    // }
                    sock->window.wnd_send->rwnd = pkt_adv_win;
                    // RWNDLog("[size:%d]\r\n",pkt_adv_win);
                    //  printf("发送窗口 base=%d, nextseq=%d\n", sock->window.wnd_send->base, sock->window.wnd_send->nextseq);
                    //  printf("发送缓冲区 sending_len=%d, sending_buf_send_len=%d\n", sock->sending_len, sock->sending_buf_send_len);
                }

                pthread_mutex_unlock(&(sock->send_lock)); // 解锁

                return 0;
            }
            break;
            ///***************************//
            /// closing connection ---------------------------------------------------------------------------------------------------
        case FIN_WAIT_1:
            if (pkt_flag & ACK_FLAG_MASK && !(pkt_flag & FIN_FLAG_MASK)) /// client received ACK without FIN, closing 1
            {
                TraceableInfo("received ACK 2, half closed\n");

                conn_stopTimer();
                /// state transition
                sock->state = FIN_WAIT_2;
            } else if (!(pkt_flag & ACK_FLAG_MASK) &&
                       pkt_flag & FIN_FLAG_MASK) /// client received FIN without ACK, close simultaneously
            {
                TraceableInfo("client received FIN without ACK, close simultaneously\n");
                /// send ACK
                tcp_connection_management_message_to_layer3(sock->established_local_addr.port,
                                                            sock->established_remote_addr.port,
                                                            ack_num, seq_num + 1, ACK_FLAG_MASK, CONN_MODE_SEND);
                /// state transition
                sock->state = CLOSING;
            } else if (pkt_flag & ACK_FLAG_MASK &&
                       pkt_flag & FIN_FLAG_MASK) /// close client received FIN with ACK, close simultaneously
            {
                TraceableInfo("close client received FIN with ACK, close simultaneously\n");
                /// send ACK
                tcp_connection_management_message_to_layer3(sock->established_local_addr.port,
                                                            sock->established_remote_addr.port,
                                                            ack_num, seq_num + 1, ACK_FLAG_MASK, CONN_MODE_SEND);
                /// state transition
                sock->state = TIME_WAIT;
                goto TIME_WAIT_lbl;
            } else {
                // ERR
                Error("");
            }
            break;
        case FIN_WAIT_2:
            if (pkt_flag & FIN_FLAG_MASK) /// received FIN from server
            {
                TraceableInfo("received FIN from server, sending ACK 3\n");
                /// send ACK
                tcp_connection_management_message_to_layer3(sock->established_local_addr.port,
                                                            sock->established_remote_addr.port,
                                                            ack_num, seq_num + 1, ACK_FLAG_MASK, CONN_MODE_SEND);
                /// state transition
                sock->state = TIME_WAIT;
                goto TIME_WAIT_lbl;
            }
            break;

        case TIME_WAIT: // handles incoming packet(incoming FIN, send ACK)
            (sock->established_local_addr.port,
                    sock->established_remote_addr.port,
                    ack_num, seq_num + 1, ACK_FLAG_MASK, CONN_MODE_RESEND);
            return 0;
        TIME_WAIT_lbl:
            TraceableInfo("TIME_WAIT\n");
            alarm(5);// TODO, should be 2 MSL, whatever
            signal(SIGALRM, time_wait_handler);
            time_wait_sock = sock;
            return 0;
//        sleep(4);
        CLOSE_WAIT_lbl:
            TraceableInfo("arrived at CLOSE WAIT, waiting for sending buffer to clear...\n");
            // wait until buffer is empty
            while (sock->sending_len != 0) {
                ;
            }
            CloseInitiated = 1;
//            pthread_mutex_lock(&(sock->send_lock));
            TraceableInfo("sending buffer cleared, sending FIN 3...\n");
            /// send FIN
            tcp_connection_management_message_to_layer3(sock->established_local_addr.port,
                                                        sock->established_remote_addr.port,
                                                        ack_num, seq_num + 1, FIN_FLAG_MASK|ACK_FLAG_MASK, CONN_MODE_SEND);
            stopTimer();
            create_conn_retrans_thread(sock);
            conn_startTimer();
            /// state transition
            sock->state = LAST_ACK;
            break;
        case LAST_ACK:
            if (pkt_flag & ACK_FLAG_MASK) /// server received FIN-ACK , closing
            {
                /// state transition
                sock->state = CLOSED;
                goto CLOSED_lbl;
            } else {
                // ERR
                Error("flag=%d", pkt_flag);
            }
            break;
        case CLOSING:
            if (pkt_flag & ACK_FLAG_MASK) {
                /// state transition
                sock->state = TIME_WAIT;
                goto TIME_WAIT_lbl;
            }
            break;
        CLOSED_lbl:
            Close(sock);
            return 0;
        default:
            Error("\n");
            return -1;
    }

    //    // 把收到的数据放到接受缓冲区
    //    while(pthread_mutex_lock(&(sock->recv_lock)) != 0); // 加锁
    //
    //    if(sock->received_buf == NULL){
    //        sock->received_buf = malloc(data_len);
    //    }else {
    //        sock->received_buf = realloc(sock->received_buf, sock->received_len + data_len);
    //    }
    //    memcpy(sock->received_buf + sock->received_len, pkt + DEFAULT_HEADER_LEN, data_len);
    //    sock->received_len += data_len;
    //
    //    pthread_mutex_unlock(&(sock->recv_lock)); // 解锁

    return 0;
}

int tju_close(tju_tcp_t *sock) {
    TraceableInfo(L_YELLOW("tju_close() called\n"));
    is_closing = 1;
//    do {
//        while (pthread_mutex_lock(&(sock->send_lock)) != 0)
//            ; /// 加锁防止新数据写入
//            if(sock->sending_len == 0)
//            {
//                TraceableInfo(L_GREEN("sending buffer cleared, ready to close\n"));
//                break;
//            }
//            else
//            {
//                pthread_mutex_unlock(&(sock->send_lock));
//                // delay 200ms
//                usleep(200000);
//            }
//    } while (1);
    while (sock->sending_len != 0) {
        ;
    }
//        while (pthread_mutex_lock(&(sock->send_lock)) != 0)
//            ; /// 加锁防止新数据写入

    CloseInitiated = 1;
    stopTimer();
    create_conn_retrans_thread(sock);
    conn_startTimer(); // start connection management timer
    TraceableInfo("tju_close() sending FIN 1\n");
    /// send FIN
    tcp_connection_management_message_to_layer3(sock->established_local_addr.port,
                                                sock->established_remote_addr.port,
                                                0,
                                                0,
                                                FIN_FLAG_MASK, CONN_MODE_SEND);
    /// state transition
    sock->state = FIN_WAIT_1;

    while (sock->state != CLOSED); // block until CLOSED

    return 0;
}

//// connection establishment timer functions
/**
 * called when connection establishment timer expires, call conn_retrans_handler to retransmit
 *
 * @param signo the signal number
 *
 * @return empty
 */
void conn_timeout_handler(int signo) {
    if (ConnTimerStopped)
        return;
    TraceableInfo(L_YELLOW("conn time out, calling conn_retrans_handler...\n"));
    //    conn_retrans_signal = 1;
    conn_retrans_handler(NULL);
}

void conn_startTimer() {
    ConnTimerStopped = 0;
    alarm(1); // TODO
    signal(SIGALRM, conn_timeout_handler);
    TraceableInfo("start connection establishment timer\n");
}

void conn_stopTimer() {
    ConnTimerStopped = 1;
    alarm(0); //// TODO
}

/**
 * called when connection establishment timeout, by function conn_timeout_handler
 *
 * @param in_sock The socket that is being retransmitted.
 *
 * @return void
 */
void conn_retrans_handler(tju_tcp_t *in_sock) {
    static tju_tcp_t *sock = NULL;
    if (in_sock != NULL) {
        sock = in_sock;
        return;
    } else {
        TraceableInfo("conn_retrans_handler called, conn retransmitting...\n");
        tcp_connection_management_message_to_layer3(sock->established_local_addr.port,
                                                    sock->established_remote_addr.port,
                                                    0, 0, 0, CONN_MODE_RESEND);
        conn_startTimer();
    }
}

/**
 * It creates a timer to handle loss during connection establishment.
 *
 * @param sock the socket that is being used for the connection
 */
void create_conn_retrans_thread(tju_tcp_t *sock) {
    conn_startTimer();
    signal(SIGALRM, conn_timeout_handler);
    conn_retrans_handler(sock); // initialise
    TraceableInfo("CREATE CONN RETRANSMIT THREAD\n");
}

/**
 * It terminates the connection retransmit timer after connection established
 *
 * @param sock the socket that is being closed
 *
 * @return Nothing.
 */
void terminate_conn_timer_and_thread(tju_tcp_t *sock) {
    conn_stopTimer();
    TraceableInfo("TERMINATE CONN RETRANSMIT THREAD\n");
}

//// socket queue related functions

/**
 * It initializes a socket queue
 *
 * @param q the queue to initialize
 */
void init_sock_queue(tju_sock_queue_t *q) {
    q->front = NULL;
    q->rear = NULL;
    q->queue_size = 0;
}

/**
 * It returns the length of the queue.
 *
 * @param q the queue
 *
 * @return The number of elements in the queue.
 */
int queue_length(tju_sock_queue_t *q) {
    return q->queue_size;
}

/**
 * @param q the queue to be checked
 */
int is_queue_empty(tju_sock_queue_t *q) {
    return q->queue_size == 0;
}

/**
 * @param q the queue to be checked
 * @return The function is_queue_full() returns a boolean value.
 */
int is_queue_full(tju_sock_queue_t *q) {
    return q->queue_size == MAX_SOCK;
}

/**
 * > enqueue() adds a socket to the queue
 *
 * @param q the queue to be enqueued
 * @param socker_ptr the pointer to the socket
 */
int enqueue(tju_sock_queue_t *q, tju_tcp_t *socket_ptr) {
    if (is_queue_full(q)) {
        return -1;
    } else {
        socket_node_t *new_node = (socket_node_t *) malloc(sizeof(socket_node_t));
        new_node->socket_ptr = socket_ptr;
        new_node->sock_hashval = cal_hash(socket_ptr->established_local_addr.ip,
                                          socket_ptr->established_local_addr.port,
                                          socket_ptr->established_remote_addr.ip,
                                          socket_ptr->established_remote_addr.port); // TODO may need to fix
        new_node->next = NULL;
        if (is_queue_empty(q)) // queue is empty
        {
            q->front = new_node;
            q->rear = new_node;
        } else {
            q->rear->next = new_node;
        }
        q->queue_size++;
        return 0;
    }
}

/**
 * It dequeues the first element in the queue.
 *
 * @param q the queue to be operated on
 *
 * @return A pointer to a socket_node_t struct, the element that has been dequeued.
 */
socket_node_t *dequeue(tju_sock_queue_t *q) {
    if (is_queue_empty(q)) {
        return NULL;
    } else {
        socket_node_t *temp = q->front;
        q->front = q->front->next;
        q->queue_size--;
        if (q->front == NULL) {
            q->rear = NULL;
        }
        return temp;
    }
}

/**
 * > It pops the socket node whose hash value is equal to the given hash value
 *
 * @param q the queue to be operated on
 * @param hashval the hash value of the socket
 *
 * @return A pointer to a tju_tcp_t struct.
 */
socket_node_t *pop_via_hashval(tju_sock_queue_t *q, int hashval) {
    if (is_queue_empty(q)) {
        return NULL;
    } else {
        socket_node_t *i, *j; // j is the previous node of i   queue-----j----i----
        for (i = q->front, j = NULL; i != NULL; i = i->next, j = i) {
            if (i->sock_hashval == hashval) {
                if (j == NULL) {
                    q->front = i->next;
                } else {
                    j->next = i->next;
                }
                if (i->next == NULL) {
                    q->rear = j;
                }

                q->queue_size--;
                return i;
            }
        }

        return NULL;
    }
}

/// sending and retrans thread

int create_sending_and_retrans_thread(int hashval, pthread_t sending_thread_id, pthread_t retrans_thread_id) {
    void *sending_thread_arg = malloc(sizeof(int));
    memcpy(sending_thread_arg, &hashval, sizeof(int));
    int rst1 = pthread_create(&sending_thread_id, NULL, sending_thread, sending_thread_arg);
    if (rst1 < 0) {
        printf("ERROR open sending thread \n");
        exit(-1);
    }

    void *retrans_thread_arg = malloc(sizeof(int));
    memcpy(retrans_thread_arg, &hashval, sizeof(int));
    int rst2 = pthread_create(&retrans_thread_id, NULL, retrans_thread, retrans_thread_arg);
    if (rst2 < 0) {
        printf("ERROR open retrans thread \n");
        exit(-1);
    }
}

/// util
void tcp_connection_management_message_to_layer3(uint16_t src_port, uint16_t dst_port, uint32_t seqnum, uint32_t acknum,
                                                 uint8_t flag, uint8_t trans_control_flag) {
    static tju_packet_t *last_pkt = NULL;
    tju_packet_t *pkt;
    if (trans_control_flag == CONN_MODE_SEND) {

        pkt = create_packet(src_port, dst_port, seqnum, acknum,
                            DEFAULT_HEADER_LEN, DEFAULT_HEADER_LEN, flag, 1, 0, NULL, 0);
    } else // retrans
    {
        pkt = (tju_packet_t *) malloc(sizeof(tju_packet_t));
        memcpy(pkt, last_pkt, sizeof(tju_packet_t)); // copy last packet
    }
    char flags[40] = {0};
    if (pkt->header.flags & SYN_FLAG_MASK) {
        strcat(flags, "SYN");
    }
    if (pkt->header.flags & FIN_FLAG_MASK) {
        strcat(flags, "|FIN");
    }
    if (pkt->header.flags & ACK_FLAG_MASK && pkt->header.flags & SYN_FLAG_MASK) {
        strcat(flags, "|ACK");
    } else if (pkt->header.flags & ACK_FLAG_MASK) {
        strcat(flags, "ACK");
    }
    //SENDLog("[seq:%d ack:%d flags:%s]\r\n",pkt->header.seq_num,pkt->header.ack_num,flags);
    if (trans_control_flag == CONN_MODE_SEND) {
//        TraceableInfo("transmitting packet: [seq :%d], [flags:%s]\n", pkt->header.seq_num, flags);
        TraceableInfo("transmitting packet: [flags:%s]\n", flags);
    } else {
//        TraceableInfo(L_YELLOW("retransmitting packet: [seq :%d], [flags:%s]\n"), pkt->header.seq_num, flags);
        TraceableInfo(L_YELLOW("retransmitting packet: [flags:%s]\n"), flags);
    }

    char *msg = packet_to_buf(pkt);
    sendToLayer3(msg, DEFAULT_HEADER_LEN);
    if (last_pkt != NULL) {
        free(last_pkt);
    }
    last_pkt = pkt;
    free(msg);
}

void congestion_control(tju_tcp_t *sock, int status) {
    switch (status) {
        case SLOW_START:
            sock->window.wnd_send->cwnd = min(sock->window.wnd_send->cwnd * 2, sock->window.wnd_send->ssthresh);
            break;
        case CONGESTION_AVOIDANCE:
            sock->window.wnd_send->cwnd += 1;
            break;
        case FAST_RECOVERY:
            RETRANS = 1;
            sock->window.wnd_send->ssthresh = max(sock->window.wnd_send->cwnd / 2, 1);
            sock->window.wnd_send->cwnd = sock->window.wnd_send->ssthresh;
            while (pthread_mutex_lock(&(sock->window.wnd_send->ack_cnt_lock)) != 0);
            sock->window.wnd_send->ack_cnt = 0;
            pthread_mutex_unlock(&(sock->window.wnd_send->ack_cnt_lock));
            break;
        case TIME_OUT:
            sock->window.wnd_send->ssthresh = max(sock->window.wnd_send->cwnd / 2, 1);
            sock->window.wnd_send->cwnd = 1;
            break;
    }
}