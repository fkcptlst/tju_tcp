#include "tju_packet.h"


/*
 输入header所有字段 和 TCP包数据内容及其长度
 构造tju_packet_t
 返回其指针
 */
tju_packet_t* create_packet(uint16_t src, uint16_t dst, uint32_t seq, 
    uint32_t ack, uint16_t hlen, uint16_t plen, uint8_t flags, 
    uint16_t adv_window, uint8_t ext, char* data, int len){

    tju_packet_t* new = malloc(sizeof(tju_packet_t));

    new->header.source_port = src;
    new->header.destination_port = dst;
    new->header.seq_num = seq;
    new->header.ack_num = ack;
    new->header.hlen = hlen;
    new->header.plen = plen;
    new->header.flags = flags;
    new->header.advertised_window = adv_window;
    new->header.ext = ext;

    if(len > 0){
        new->data = malloc(len);
        new->data = memcpy(new->data, data, len);
    }else{
        new->data = NULL;
    }
        
    return new;
}

/*
 输入header所有字段 和 TCP包数据内容及其长度
 构造tju_packet_t 
 返回其对应的字符串
 */
char* create_packet_buf(uint16_t src, uint16_t dst, uint32_t seq, uint32_t ack,
    uint16_t hlen, uint16_t plen, uint8_t flags, uint16_t adv_window, 
    uint8_t ext, char* data, int len){

    tju_packet_t* temp;
    char* final;  

    temp = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, 
        ext, data, len);

    final = packet_to_buf(temp);

    free_packet(temp);
    return final;
}

/*
 清除一个tju_packet_t的内存占用
 */
void free_packet(tju_packet_t* packet){
    if(packet->data != NULL)
         free(packet->data);
    free(packet);
}


/*
 下面的函数全部都是从一个packet的字符串中
 根据各个字段的偏移量
 找到并返回对应的字段
*/ 

/**
 * Get source,
 * @param msg the message received from the server
 *
 * @return The source port number
 */
uint16_t get_src(char* msg){
    int offset = 0;
    uint16_t var;
    memcpy(&var, msg+offset, SIZE16);
    return ntohs(var);
}
/**
 * It takes a pointer to a message and returns the destination address of the message
 *
 * @param msg the message received from the server
 *
 * @return The destination port number
 */
uint16_t get_dst(char* msg){
    int offset = 2;
    uint16_t var;
    memcpy(&var, msg+offset, SIZE16);
    return ntohs(var);
}
/**
 * get sequence number
 *
 * @param msg the message received from the server
 *
 * @return The sequence number of the message.
 */
uint32_t get_seq(char* msg){
    int offset = 4;
    uint32_t var;
    memcpy(&var, msg+offset, SIZE32);
    return ntohl(var);
}
/**
 * get ack number
 *
 * @param msg the message received from the server
 *
 * @return The ack number
 */
uint32_t get_ack(char* msg){
    int offset = 8;
    uint32_t var;
    memcpy(&var, msg+offset, SIZE32);
    return ntohl(var);
}
/**
 * It returns the length of the header.
 *
 * @param msg the message
 *
 * @return The length of the header.
 */
uint16_t get_hlen(char* msg){
    int offset = 12;
    uint16_t var;
    memcpy(&var, msg+offset, SIZE16);
    return ntohs(var);
}
/**
 * get the payload length of the message
 *
 * @param msg the message
 *
 * @return The length of the payload.
 */
uint16_t get_plen(char* msg){
    int offset = 14;
    uint16_t var;
    memcpy(&var, msg+offset, SIZE16);
    return ntohs(var);
}
/**
 * get the flags field of the message
 *
 * @param msg the message to be parsed
 *
 * @return The flags of the message.
 */
uint8_t get_flags(char* msg){
    int offset = 16;
    uint8_t var;
    memcpy(&var, msg+offset, SIZE8);
    return var;
}
/**
 * get the advertised window size
 *
 * @param msg the message received from the server
 *
 * @return The advertised window size
 */
uint16_t get_advertised_window(char* msg){
    int offset = 17;
    uint16_t var;
    memcpy(&var, msg+offset, SIZE16);
    return ntohs(var);
}
/**
 * Get the extension from the message.
 *
 * @param msg the message received from the server
 *
 * @return The extension of the file being requested.
 */
uint8_t get_ext(char* msg){
    int offset = 19;
    uint8_t var;
    memcpy(&var, msg+offset, SIZE8);
    return var;
}



/*############################################## 下面是实现上面函数功能的辅助函数 用户没必要调用 ##############################################*/


/*
 传入header所需的各种数据
 构造并返回header的字符串
 */
char* header_in_char(uint16_t src, uint16_t dst, uint32_t seq, uint32_t ack,
    uint16_t hlen, uint16_t plen, uint8_t flags, uint16_t adv_window, 
    uint8_t ext){

	uint16_t temp16;
    uint32_t temp32;
    
    char* msg = (char*) calloc(plen, sizeof(char));
    int index = 0;
    
    temp16 = htons(src);
    memcpy(msg+index, &temp16, SIZE16);
    index += SIZE16;

    temp16 = htons(dst);
    memcpy(msg+index, &temp16, SIZE16);
    index += SIZE16;

    temp32 = htonl(seq);
    memcpy(msg+index, &temp32, SIZE32);
    index += SIZE32;

    temp32 = htonl(ack);
    memcpy(msg+index, &temp32, SIZE32);
    index += SIZE32;
    
    temp16 = htons(hlen);
    memcpy(msg+index, &temp16, SIZE16);
    index += SIZE16;

    temp16 = htons(plen);
    memcpy(msg+index, &temp16, SIZE16);
    index += SIZE16;

    memcpy(msg+index, &flags, SIZE8);
    index += SIZE8;

    temp16 = htons(adv_window);
    memcpy(msg+index, &temp16, SIZE16);
    index += SIZE16;

    memcpy(msg+index, &ext, SIZE8);
    index += SIZE8;


	return msg;
}

/*
 根据传入的tju_packet_t指针
 构造并返回对应的字符串
 */
char* packet_to_buf(tju_packet_t* p){
    char* msg = header_in_char(p->header.source_port, p->header.destination_port, 
        p->header.seq_num, p->header.ack_num, p->header.hlen, p->header.plen, 
        p->header.flags, p->header.advertised_window, 
        p->header.ext);
    
    if(p->header.plen > p->header.hlen){
        memcpy(msg+(p->header.hlen), p->data, (p->header.plen - (p->header.hlen)));
    }
        

    return msg;
}
