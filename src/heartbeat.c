#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>

#include "heartbeat.h"
#include "ECNDMFHP.h"
#include "chat.h"
#include "list.h"

void remove_peer(chat_application_context *ctx, list_node *peer)
{
    char ip_buffer[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = peer->data->ip_addr;
    inet_ntop(AF_INET, &addr, ip_buffer, INET_ADDRSTRLEN);
    fprintf(stderr, "INFO: Heartbeat for %s is up! Closing connection.\n", ip_buffer);

    close(peer->data->sock);
    FD_CLR(peer->data->sock, &ctx->peer_fds);
    peer->data->sock = -1;

    list_remove(&ctx->peer_list, peer->data->ip_addr);
}

void send_heartbeat(list_node *peer)
{
    // Create heartbeat packet
    packet_header heartbeat = create_packet_header(MSG_HEARTBEAT, 0);

    if (peer->data->connected)
    {
        send_packet(peer->data->sock, &heartbeat);
    }
}

void *heartbeat_thread_func(void *args)
{
    time_t base_time, new_time, old_time;

    heartbeat_thread_args thread_args = *((heartbeat_thread_args *)args);
    chat_application_context *ctx = thread_args.ctx;

    base_time = time(0);
    old_time = time(0);

    while (true)
    {
        usleep(500 * 1000); // 500 ms

        new_time = time(0);
        double total_diff = difftime(new_time, base_time);
        double current_diff = difftime(new_time, old_time);
        old_time = new_time;

        pthread_mutex_lock(ctx->peer_mutex);

        // Send heartbeat every 10 seconds
        if (total_diff >= 10)
        {
            base_time = time(0);

            // Start at next to skip sending heartbeat to self
            list_node *peer = ctx->peer_list->next;
            while (peer)
            {
                // Send heartbeat to everyone
                send_heartbeat(peer);

                peer = peer->next;
            }
        }

        // Calculate new Timer for peers
        list_node *peer = ctx->peer_list->next;
        while (peer)
        {
            peer->data->heartbeat_timer -= current_diff;

            if (peer->data->heartbeat_timer <= 0)
            {
                // Time's up, remove current peer
                remove_peer(ctx, peer);
            }

            peer = peer->next;
        }

        pthread_mutex_unlock(ctx->peer_mutex);
    }
}
