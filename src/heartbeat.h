#ifndef HEARTBEAT_H
#define HEARTBEAT_H

#include <pthread.h>
#include <sys/select.h>

#include "chat.h"
#include "list.h"

typedef struct {
    chat_application_context *ctx;
} heartbeat_thread_args;

void *heartbeat_thread_func(void *args);

#endif
