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
#include <errno.h>

#include "chat.h"
#include "constants.h"
#include "helper.h"
#include "list.h"
#include "heartbeat.h"
#include "receiver.h"

packet create_packet(char version, char type, short length, char *data)
{
    return (packet){
        .version = version,
        .type = type,
        .length = length,
        .data = data};
}

void send_packet(int sock, packet *pack)
{
    send(sock, pack, HEADER_LEN, 0);
}

void send_data_packet(int sock, packet *pack, char *data_buffer, int data_buf_length)
{
    send(sock, pack, HEADER_LEN, 0);
    send(sock, data_buffer, data_buf_length, 0);
}

// Returns the data created for the enter request package
enter_request create_enter_req_data(chat_application_context *ctx)
{
    char *data = malloc(1);

    int total_length = 0;
    int previous_total_length = 0;

    // Iterate over peers
    for (list_node *peer = ctx->peer_list; peer != NULL; peer = peer->next)
    {
        const int entry_header_length = IP_ADDR_LEN + PORT_LEN + NAME_LEN_LEN;

        char entry_header[entry_header_length];

        // Copy IP-Address to packet-data
        memcpy(entry_header, (char *)&peer->data->ip_addr, IP_ADDR_LEN);

        // Copy port
        // uint16_t port = PORT;
        uint16_t port = peer->data->port;
        memcpy(entry_header + IP_ADDR_LEN, (char *)&port, PORT_LEN);

        // Copy length of name
        uint16_t name_length = (uint16_t)strlen(peer->data->name) + 1;
        memcpy(entry_header + IP_ADDR_LEN + NAME_LEN_LEN, (char *)&name_length, NAME_LEN_LEN);

        char name[name_length];
        // Copy name
        memcpy(name, peer->data->name, (int)name_length);

        previous_total_length = total_length;
        total_length += entry_header_length + name_length;

        data = realloc(data, total_length);
        memcpy(data + previous_total_length, entry_header, entry_header_length);
        memcpy(data + previous_total_length + entry_header_length, name, name_length);
    }

    return (enter_request){
        .data = data,
        .length = total_length};
}

void send_disconnect(chat_application_context *ctx)
{
    pthread_mutex_lock(ctx->peer_mutex);

    // Create disconnect packet
    packet reset = create_packet(
        PROTOCOL_VERSION,
        MSG_DISCONNECT,
        0,
        NULL);

    for (list_node *peer = ctx->peer_list->next; peer != NULL; peer = peer->next)
    {
        // Send disconnect to everyone
        if (peer->data->connected)
        {
            send_packet(peer->data->socket, &reset);
        }

        // Close connection
        close(peer->data->socket);
        FD_CLR(peer->data->socket, &ctx->peer_fds);
        peer->data->socket = -1;
    }

    pthread_mutex_unlock(ctx->peer_mutex);
}

void send_message(chat_application_context *ctx, char *message,
                  BOOL private, char *user_name)
{
    pthread_mutex_lock(ctx->peer_mutex);

    int msg_length = strlen(message) + 1;
    int aligned_length = msg_length;

    // Don't send empty messages!
    if (strcmp(message, "\n") == 0)
    {
        return;
    }

    // Align message block
    if (msg_length % 4 != 0)
    {
        aligned_length = msg_length + (4 - (msg_length % 4));
    }

    // Create message packet
    packet message_packet = create_packet(
        PROTOCOL_VERSION,
        MSG_MESSAGE,
        aligned_length, // Length in 4 byte blocks
        NULL);

    for (list_node *peer = ctx->peer_list->next; peer != NULL; peer = peer->next)
    { // uns selbst als head überspringen und message nur an andere schicken
        // Send message to everyone
        if (peer->data->connected)
        {
            if (private)
            {
                message_packet.type = MSG_PRIVATE;

                if (strcmp(peer->data->name, user_name) == 0)
                {
                    send_data_packet(peer->data->socket, &message_packet, message, msg_length);
                }
            }
            else
            {
                send_data_packet(peer->data->socket, &message_packet, message, msg_length);
            }
        }
    }

    pthread_mutex_unlock(ctx->peer_mutex);
}

// Connects to a client / client-network
int connect_to_peer(chat_application_context *ctx, uint32_t destination_ip,
                    uint16_t destination_port, BOOL use_sctp)
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
        FD_CLR(sockfd, &ctx->peer_fds);
        sockfd = -1;
        return 0;
    }

    // Create enter request packet
    enter_request req = create_enter_req_data(ctx);

    // Add socket ot master set
    FD_SET(sockfd, &ctx->peer_fds);

    packet enter_req = create_packet(
        PROTOCOL_VERSION,
        MSG_ENTER_REQ,
        list_size_safe(ctx->peer_mutex, ctx->peer_list),
        req.data);

    send_data_packet(sockfd, &enter_req, enter_req.data, req.length);

    // Free data from enter request
    free(req.data);

    // Set maximum socket to new socket if new socket is bigger
    if (sockfd > ctx->max_fd)
    {
        ctx->max_fd = sockfd;
    }

    return sockfd;
}

void show_peer_list(chat_application_context *ctx)
{
    pthread_mutex_lock(ctx->peer_mutex);

    printf("current peers:\n");

    for (list_node *p = ctx->peer_list; p != NULL; p = p->next)
    {
        struct in_addr addr = {.s_addr = p->data->ip_addr};
        char ip_buf[INET_ADDRSTRLEN];
        char port_buf[PORTSTRLEN + 1];
        sprintf(port_buf, "%hu", p->data->port);

        printf("%s:\n", p->data->name);
        printf("  address: %s:%s\n\n", inet_ntop(AF_INET, &addr, ip_buf, INET_ADDRSTRLEN), port_buf);
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

    printf("#################################################\n");
    printf("#       SUPER AWESOME CHAT CLIENT SOFTWARE      #\n");
    printf("#                       %s                    #\n", CHAT_VERSION);
    printf("#################################################\n");

    // Initialize list and mutex
    printf("Initializing peer list...\n");
    ctx.peer_list = list_new();

    // Retreive username
    printf("Please enter username: ");
    fgets(ctx.user_name, INPUT_BUFFER_LEN, stdin);
    chomp(ctx.user_name);

    peer *user = malloc(sizeof(peer));

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

        if (strcmp(splitstr, "/connect") == 0)
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

            if (connect_to_peer(&ctx, ip_addr, port, use_sctp))
            {
                printf("Connected!\n");
            }
        }
        else if (strcmp(splitstr, "/list") == 0 || strcmp(splitstr, "/list\n") == 0)
        {
            show_peer_list(&ctx);
        }
        else if (strcmp(splitstr, "/quit") == 0 || strcmp(splitstr, "/quit\n") == 0)
        {
            send_disconnect(&ctx);
            list_free_safe(ctx.peer_mutex, ctx.peer_list);
            return;
        }
        else if (strcmp(splitstr, "/msg") == 0)
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

            if (strcmp(message, "") != 0)
                printf("%s: %s\n", ctx.user_name, message);

            send_message(&ctx, message, 0, NULL);
        }
    }

    pthread_join(receiver_thread, NULL);
}
