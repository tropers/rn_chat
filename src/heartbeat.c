#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "heartbeat.h"
#include "chat.h"
#include "list.h"

void remove_peer(chat_application_context *ctx, list_node *peer)
{
    char *ip_buffer = malloc(INET_ADDRSTRLEN);
    struct in_addr addr;
    addr.s_addr = peer->data->ip_addr;
    inet_ntop(AF_INET, &addr, ip_buffer, INET_ADDRSTRLEN);
    fprintf(stderr, "INFO: Heartbeat for %s is up! Closing connection.\n", ip_buffer);

    close(peer->data->socket);
    FD_CLR(peer->data->socket, &ctx->peer_fds);
    peer->data->socket = -1;

    list_remove(&ctx->peer_list, peer->data->ip_addr);

    free(ip_buffer);
    ip_buffer = 0;
}

void send_heartbeat(list_node *peer)
{
    // Create heartbeat packet
    packet heartbeat = create_packet(
        PROTOCOL_VERSION,
        MSG_HEARTBEAT,
        0,
        NULL);

    // TODO: Check this
    // allocate buffer for heartbeat packet
    char buffer[sizeof(packet)];
    // char *buffer = malloc(sizeof(packet));
    memcpy(&buffer, &heartbeat, HEADER_LEN);

    if (peer->data->connected)
    {
        send(peer->data->socket, &buffer, HEADER_LEN, 0);
    }
}

void *heartbeat_thread_func(void *args)
{
    time_t base_time, new_time, old_time;

    heartbeat_thread_args thread_args = *((heartbeat_thread_args *)args);
    chat_application_context *ctx = thread_args.ctx;

    base_time = time(0);
    old_time = time(0);

    while (TRUE)
    {
        sleep(0.5);

        new_time = time(0);
        double total_diff = difftime(new_time, base_time);
        double current_diff = difftime(new_time, old_time);
        old_time = new_time;

        // Send heartbeat every 10 seconds
        if (total_diff >= 10)
        {
            base_time = time(0);

            // Start at next to skip sending heartbeat to self
            for (list_node *peer = ctx->peer_list->next; peer != NULL; peer = peer->next)
            {
                // Send heartbeat to everyone
                send_heartbeat(peer);
            }
        }

        pthread_mutex_lock(ctx->peer_mutex);

        // Calculate new Timer for peers
        for (list_node *peer = ctx->peer_list->next; peer != NULL; peer = peer->next)
        {
            peer->data->heartbeatTimer -= current_diff;

            if (peer->data->heartbeatTimer <= 0)
            {
                // Time's up, remove current peer
                remove_peer(ctx, peer);
            }
        }

        pthread_mutex_unlock(ctx->peer_mutex);
    }
}