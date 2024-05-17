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

void handle(BOOL use_sctp, int sctp_hbinterval);

#endif
