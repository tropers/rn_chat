#ifndef ECNDMFHP_H
#define ECNDMFHP_H

#include <stdint.h>

#include "chat.h"

// Protocol definitions
#define PROTOCOL_VERSION 2
#define MSG_ENTER_REQ 'E'
#define MSG_NEW_USERS 'N'
#define MSG_CONNECT 'C'
#define MSG_DISCONNECT 'D'
#define MSG_HEARTBEAT 'H'
#define MSG_MESSAGE 'M'
#define MSG_PRIVATE 'P'
#define MSG_FAILED 'F'

#define IP_ADDR_LEN 4                                            // 4 bytes IP length
#define PORT_LEN 2                                               // 2 bytes port length
#define NAME_LEN_LEN 2                                           // 2 bytes name length

#define PORTSTRLEN 6 // Five digits + \0 "65535\0"

#define HEARTBEAT_TIME 20

// Header
// protocol version: 1 byte
// packet type:      1 byte
// packet length:    4 bytes (integer)
#define HEADER_PROTOCOL_VERSION_LEN 1
#define HEADER_PACKET_TYPE_LEN 1
#define HEADER_PACKET_LEN_LEN 4
#define HEADER_LEN HEADER_PROTOCOL_VERSION_LEN\
        + HEADER_PACKET_TYPE_LEN + HEADER_PACKET_LEN_LEN

typedef struct
{
    peer *peer;
    size_t peer_size;
} peer_tuple;

typedef struct
{
    list_node *peer_list;
    int sock;
} peer_list_sock_tuple;

typedef struct
{
    fd_set *peer_fds;
    int *max_fd;
} peer_and_max_fds_tuple;

typedef struct
{
    char version;
    char type;
    uint32_t length;
} packet_header;

typedef struct
{
    char *data;
    size_t length;
} data_buffer;

packet_header create_packet_header(char type, uint32_t length);
data_buffer create_enter_req_data(list_node *peer_list);
void send_packet(int sock, packet_header *header);
void send_data_packet(int sock, packet_header *header, data_buffer *data_buffer);
void handle_packet(chat_application_context *ctx, int sock);

#endif
