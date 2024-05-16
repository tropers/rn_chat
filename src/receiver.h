#ifndef RECEIVER_H
#define RECEIVER_H

#include "chat.h"

// Thread args for SCTP
typedef struct
{
    chat_application_context *ctx;
    int sctp_hbinterval;
} receiver_thread_args;

void *receiver_thread_func(void *args);

#endif
