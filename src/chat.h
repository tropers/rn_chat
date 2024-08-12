/**
 * chat.h
 *
 */

#ifndef CHAT_H
#define CHAT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/select.h>

#include "list.h"
#include "constants.h"

typedef struct
{
    bool use_sctp;
    int sctp_hbinterval;

    pthread_mutex_t *peer_mutex;
    list_node *peer_list;

    char *user_name;

    fd_set peer_fds;
    int max_fd;
} chat_application_context;

void handle(bool use_sctp, int sctp_hbinterval);

#endif
