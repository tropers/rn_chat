/**
 * chat.c
 *
 * Contains function definitions of the chat application
 */

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <string.h>
#include <sys/select.h>
#include "ECNDMFHP.h"
#include "chat.h"
#include "constants.h"
#include "helper.h"
#include "list.h"
#include "heartbeat.h"
#include "receiver.h"

void send_disconnect(chat_application_context *ctx)
{
    pthread_mutex_lock(ctx->peer_mutex);

    // Create disconnect packet
    packet_header reset = create_packet_header(MSG_DISCONNECT, 0);

    list_node* peer = ctx->peer_list;
    while(peer != NULL)
    {
        // Send disconnect to everyone
        if (peer->data->connected)
        {
            send_packet(peer->data->sock, &reset);
        }

        // Close connection
        close(peer->data->sock);
        FD_CLR(peer->data->sock, &ctx->peer_fds);
        peer->data->sock = -1;

        peer = peer->next;
    }

    pthread_mutex_unlock(ctx->peer_mutex);
}

void send_message(chat_application_context *ctx, char *message,
                  BOOL private, char *user_name)
{
    pthread_mutex_lock(ctx->peer_mutex);

    int message_length = strlen(message) + 1;
    int aligned_length = message_length;

    // Don't send empty messages!
    if (!strcmp(message, "\n"))
    {
        return;
    }

    // Align message block
    if (message_length % 4 != 0)
    {
        aligned_length = message_length + (4 - (message_length % 4));
    }

    // Create message packet
    packet_header message_packet = create_packet_header(MSG_MESSAGE, aligned_length); // Length in 4 byte blocks
    data_buffer message_buffer = {
        .data = message,
        .length = aligned_length
    };

    // Skip ourselves to send package only to other clients
    list_node *peer = ctx->peer_list->next;
    while (peer)
    { 
        if (peer->data->connected)
        {
            if (private)
            {
                message_packet.type = MSG_PRIVATE;

                if (!strcmp(peer->data->name, user_name))
                {
                    send_data_packet(peer->data->sock, &message_packet, &message_buffer);
                }
            }
            else
            {
                // Send message to everyone
                send_data_packet(peer->data->sock, &message_packet, &message_buffer);
            }
        }
    
        peer = peer->next;
    }

    pthread_mutex_unlock(ctx->peer_mutex);
}

// Connects to a client / client-network
int connect_to_peer(pthread_mutex_t *peer_mutex, list_node *peer_list, uint32_t destination_ip,
                    uint16_t destination_port, fd_set *peer_fds,
                    int *max_fd, BOOL use_sctp)
{
    // socket-file destriptor
    struct sockaddr_in address;
    int sockfd = socket(AF_INET, SOCK_STREAM, use_sctp ? IPPROTO_SCTP : IPPROTO_TCP);
    if (sockfd < 0)
    {
        fprintf(stderr, "ERROR: Failed to create socket.\n");
        return 0;
    }

    bzero((char *)&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = destination_ip;
    address.sin_port = destination_port;

    if (connect(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        fprintf(stderr, "ERROR: connect failed.\n");
        close(sockfd);
        FD_CLR(sockfd, peer_fds);
        sockfd = -1;
        return 0;
    }

    // Add socket ot master set
    FD_SET(sockfd, peer_fds);

    data_buffer request_buffer = create_enter_req_data(peer_list);
    packet_header enter_req = create_packet_header(MSG_ENTER_REQ, request_buffer.length);

    send_data_packet(sockfd, &enter_req, &request_buffer);

    // Free data from enter request
    free(request_buffer.data);

    // Set maximum socket to new socket if new socket is bigger
    if (sockfd > *max_fd)
    {
        *max_fd = sockfd;
    }

    return sockfd;
}

void show_peer_list(chat_application_context *ctx)
{
    pthread_mutex_lock(ctx->peer_mutex);

    printf("current peers:\n");

    list_node *peer = ctx->peer_list;
    while (peer)
    {
        struct in_addr addr = {.s_addr = peer->data->ip_addr};
        char ip_buf[INET_ADDRSTRLEN];
        char port_buf[PORTSTRLEN + 1];
        sprintf(port_buf, "%hu", peer->data->port);

        printf("%s:\n", peer->data->name);
        printf("  address: %s:%s\n\n", inet_ntop(AF_INET, &addr, ip_buf, INET_ADDRSTRLEN), port_buf);

        peer = peer->next;
    }

    pthread_mutex_unlock(ctx->peer_mutex);
}

// Initializes the chat handler and runs in infinite loop
void handle(BOOL use_sctp, int sctp_hbinterval)
{
    char buffer[INPUT_BUFFER_LEN];

    chat_application_context ctx = {
        .use_sctp = use_sctp,
        .sctp_hbinterval = sctp_hbinterval};

    pthread_mutex_t peer_mutex;
    ctx.peer_mutex = &peer_mutex;

    pthread_t heartbeat_thread;
    pthread_t receiver_thread;

    printf("##################################################\n");
    printf("#       SUPER AWESOME CHAT CLIENT SOFTWARE       #\n");
    printf("#                       %s                     #\n", CHAT_VERSION);
    printf("##################################################\n");

    // Initialize list and mutex
    printf("Initializing peer list...\n");
    ctx.peer_list = list_new();
    if (!ctx.peer_list)
    {
        fprintf(stderr, "ERROR: Could not initialize peer-list, exiting.\n");
        exit(-1);
    }

    // Retreive username
    printf("Please enter username: ");
    fgets(ctx.user_name, INPUT_BUFFER_LEN, stdin);
    chomp(ctx.user_name);

    peer *user = malloc(sizeof(peer));
    if (!user)
    {
        fprintf(stderr, "ERROR: Could allocate memory for local user, exiting.\n");
        exit(-1);
    }

    // Retrieve IP address
    printf("Please enter your IP-address: ");
    fgets(buffer, INPUT_BUFFER_LEN, stdin);
    chomp(buffer);

    // Retrieve port
    // TODO

    inet_pton(AF_INET, buffer, &(user->ip_addr));
    user->name = ctx.user_name;
    user->port = PORT;
    user->connected = 1;
    user->is_new = 0;

    // Add self to list
    list_add(&ctx.peer_list, user);

    printf("Initializing peer list mutex...\n");
    pthread_mutex_init(ctx.peer_mutex, NULL);

    printf("Starting receiver thread...\n");

    receiver_thread_args args = {
        .ctx = &ctx,
        .sctp_hbinterval = sctp_hbinterval};

    pthread_create(&receiver_thread, NULL, receiver_thread_func, &args);

    // Start heartbeat thread if not using SCTP protocol
    if (!use_sctp)
    {
        printf("Starting heartbeat thread...\n");
        pthread_create(&heartbeat_thread, NULL, heartbeat_thread_func, &args);
    }

    // Main loop for grabbing keyboard input
    while (TRUE)
    {
        printf("> ");
        fgets(buffer, INPUT_BUFFER_LEN, stdin);

        char *splitstr = strtok(buffer, " ");

        if (!strcmp(splitstr, "/connect"))
        {
            // ip address
            splitstr = strtok(NULL, " ");
            if (splitstr == NULL)
            {
                fprintf(stderr, "usage: /connect IP_ADDRESS PORT\n");
                continue;
            }
            uint32_t ip_addr;
            inet_pton(AF_INET, splitstr, &ip_addr);

            // port
            splitstr = strtok(NULL, " ");
            if (splitstr == NULL)
            {
                fprintf(stderr, "usage: /connect IP_ADDRESS PORT\n");
                continue;
            }
            uint16_t port = htons((uint16_t)atoi(splitstr));

            if (connect_to_peer(ctx.peer_mutex, ctx.peer_list, ip_addr, port,
                                &ctx.peer_fds, &ctx.max_fd, use_sctp))
            {
                printf("Connected!\n");
            }
        }
        else if (!strcmp(splitstr, "/list") || !strcmp(splitstr, "/list\n"))
        {
            show_peer_list(&ctx);
        }
        else if (!strcmp(splitstr, "/quit") || !strcmp(splitstr, "/quit\n"))
        {
            send_disconnect(&ctx);
            list_free_safe(ctx.peer_mutex, ctx.peer_list);
            return;
        }
        else if (!strcmp(splitstr, "/msg"))
        {
            // username for private message
            splitstr = strtok(NULL, " ");
            if (splitstr == NULL)
            {
                fprintf(stderr, "usage: /msg USER_NAME MESSAGE\n");
                continue;
            }

            // Get username for private message
            char user_name[INPUT_BUFFER_LEN] = {0};
            strcpy(ctx.user_name, splitstr);

            char message[strlen(buffer)];
            bzero(message, strlen(buffer));

            splitstr = strtok(NULL, " ");
            while (splitstr != NULL)
            {
                strcat(message, splitstr);
                strcat(message, " ");

                splitstr = strtok(NULL, " ");
            }

            send_message(&ctx, message, 1, user_name);
        }
        else if (splitstr[0] == '/')
        {
            // Ignore commands (no sending messages by accident) {
        }
        else
        {
            char message[strlen(buffer)];
            memset(&message, 0, strlen(buffer));

            while (splitstr != NULL)
            {
                strcat(message, splitstr);
                strcat(message, " ");

                splitstr = strtok(NULL, " ");
            }

            // Remove newline from message
            chomp(message);

            if (strcmp(message, "") != 0) {
                printf("%s: %s\n", ctx.user_name, message);
                send_message(&ctx, message, 0, NULL);
            }
        }
    }

    pthread_join(receiver_thread, NULL);
}
