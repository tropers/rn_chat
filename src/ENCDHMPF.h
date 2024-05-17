#ifndef ENCDHMPF_H
#define ENCDHMPF_H

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
    int length;
} enter_request;

// Packet datatype
typedef struct
{
    char version;
    char type;
    short length;

    char *data;
} packet;

packet create_packet(char version, char type, short length, char *data);
enter_request create_enter_req_data(chat_application_context *ctx);
void send_packet(int sock, packet *pack);
void send_data_packet(int sock, packet *pack, char *data_buffer, int data_buf_length);
void recv_packet(chat_application_context *ctx, int sock, BOOL use_sctp);

#endif
