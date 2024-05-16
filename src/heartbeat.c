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

void *heartbeat_thread_func(void *args) {
    time_t baseTime, newTime, oldTime;

    heartbeat_thread_args thread_args = *((heartbeat_thread_args *)args);
    chat_application_context *ctx = thread_args.ctx;

    // Create heartbeat packet
    packet heartbeat = create_packet(
        PROTOCOL_VERSION,
        MSG_HEARTBEAT,
        0,
        NULL
    );

    // allocate buffer for heartbeat packet
    char *buffer = malloc(sizeof(packet));
    memcpy(buffer, &heartbeat, HEADER_LEN);

    baseTime = time(0);
    oldTime = time(0);
    while (1) {
        pthread_mutex_lock(ctx->peer_mutex);

        sleep(0.5);
        newTime = time(0);
        double totalDiff = difftime(newTime, baseTime);
        double currentDiff = difftime(newTime, oldTime);
        oldTime = newTime;
        if (totalDiff >= 10) { // 10 s um heartbeats senden
            baseTime = time(0);

            for (list_node *peer = ctx->peer_list->next; peer != NULL; peer = peer->next) { //bei next starten um sich selbst zu überspringen
                // Send heartbeat to everyone
                if (peer->data->connected) {
                    send(peer->data->socket, buffer, HEADER_LEN, 0);
                }
            }
        }

        // calculate new Timer for peers
        for (list_node *peer = ctx->peer_list->next; peer != NULL; peer = peer->next) {
            peer->data->heartbeatTimer -= currentDiff;

            if (peer->data->heartbeatTimer <= 0) {

                //Time's up, remove current peer
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
        }

        pthread_mutex_unlock(ctx->peer_mutex);
    }
}
