/**
 * chat.h
 *
 */

#ifndef CHAT_H
#define CHAT_H

#include <stdint.h>
#include <sys/select.h>

#include "list.h"
#include "constants.h"

typedef struct
{
    BOOL use_sctp;
    int sctp_hbinterval;

    pthread_mutex_t *peer_mutex;
    list_node *peer_list;

    char user_name[INPUT_BUFFER_LEN];

    fd_set peer_fds;
    fd_set read_fds;
    int max_fd;
} chat_application_context;

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

void handle(BOOL use_sctp, int sctp_hbinterval);
packet create_packet(char version, char type, short length, char *data);
enter_request create_enter_req_data(chat_application_context *ctx);
void send_packet(int sock, packet *pack);
void send_data_packet(int sock, packet *pack, char *data_buffer, int data_buf_length);

#endif
