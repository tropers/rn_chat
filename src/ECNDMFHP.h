#ifndef ECNDMFHP_H
#define ECNDMFHP_H

#include "chat.h"

/* Protocol definitions */
#define PROTOCOL_VERSION 2
#define MSG_ENTER_REQ 'E'
#define MSG_NEW_USERS 'N'
#define MSG_CONNECT 'C'
#define MSG_DISCONNECT 'D'
#define MSG_HEARTBEAT 'H'
#define MSG_MESSAGE 'M'
#define MSG_PRIVATE 'P'
#define MSG_FAILED 'F'

typedef struct
{
    char *data;
    size_t length;
} data_buffer;

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
    size_t length;
} packet;

packet create_packet(char type, short length);
data_buffer create_enter_req_data(list_node *peer_list);
void send_packet(int sock, packet *pack);
void send_data_packet(int sock, packet *pack, data_buffer *data_buffer);
void recv_packet(chat_application_context *ctx, int sock);

#endif
