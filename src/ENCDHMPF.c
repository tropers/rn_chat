#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>

#include "ENCDHMPF.h"
#include "helper.h"

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

void send_failed(int sock)
{
    // Create failed packet
    packet failed = create_packet(
        PROTOCOL_VERSION,
        MSG_FAILED,
        1, // 1 single byte for the error code
        NULL);

    send_packet(sock, &failed);
}

void print_message(peer *peer, char *data_buffer, BOOL is_private)
{
    // Remove newline
    chomp(data_buffer);

    if (is_private)
        printf("[%s]: %s\n", peer->name, data_buffer);
    else
        printf("%s: %s\n", peer->name, data_buffer);

    fflush(stdout);
}

void receive_from_socket(int sock, char *buffer, int length)
{
    if (recv(sock, buffer, length, 0) <= 0)
    {
        fprintf(stderr, "ERROR: Receiving data.\n");
        exit(4);
    }
}

void receive_new_peer(chat_application_context *ctx, int sock, char type, int length)
{
    int offset = 0;
    char entry_header_buf[ENTRY_HEADER_LEN];

    for (int i = 0; i < length; i++)
    {
        offset = 0;
        peer *new_peer = malloc(sizeof(peer));

        // receive user_header
        receive_from_socket(sock, entry_header_buf, ENTRY_HEADER_LEN);

        new_peer->ip_addr = *((uint32_t *)(entry_header_buf + offset));
        offset += IP_ADDR_LEN;

        new_peer->port = *((uint16_t *)(entry_header_buf + offset));
        offset += PORT_LEN;

        int name_length = *((uint16_t *)(entry_header_buf + offset));
        offset += NAME_LEN_LEN;

        // Receive name
        new_peer->name = malloc(name_length + 1);
        bzero(new_peer->name, name_length + 1);
        receive_from_socket(sock, new_peer->name, name_length);

        // Initialize new peer
        new_peer->connected = 1;

        // We know the socket from the connecting peer
        if (i == 0 && type != MSG_NEW_USERS)
        {
            new_peer->sock = sock;
        }
        else
        {
            new_peer->sock = -1; // No socket from other participants known
        }
        new_peer->is_new = 1;
        new_peer->heartbeat_timer = HEARTBEAT_TIME;

        // Check if name of connecting client is already taken
        if (i == 0 && type == 'E')
        {
            // Search through list to see if entry already exists
            for (list_node *node = ctx->peer_list; node != NULL; node = node->next)
            {
                if (strcmp(node->data->name, new_peer->name) == 0)
                {
                    printf("INFO: Name taken!\n");
                    send_failed(sock);
                    return;
                }
            }
        }

        printf("INFO: %s joined the chat.\n", new_peer->name);
        list_add(&ctx->peer_list, new_peer);
    }
}

void propagate_new_peer(chat_application_context *ctx, int sock)
{
    enter_request req = create_enter_req_data(ctx);

    packet new_user = create_packet(
        PROTOCOL_VERSION,
        MSG_NEW_USERS,
        list_size(ctx->peer_list),
        req.data);

    // send recently added users to older users in list and set newUsers = oldusers
    for (list_node *node = ctx->peer_list->next; node != NULL; node = node->next)
    {
        if (!(node->data->is_new) && node->data->sock != sock)
        {
            send_data_packet(node->data->sock, &new_user, new_user.data, req.length);
            node->data->is_new = 0;
        }
    }

    // Free data from enter request
    free(req.data);
}

void connect_to_new_peer(chat_application_context *ctx, peer *peer, packet *connect_packet,
                         char *peer_connect_buffer, int buffer_length)
{
    // If not connected to peer yet, open connection
    if (peer->sock < 0)
    {
        // socket-file destriptor
        struct sockaddr_in address;
        int sockfd = socket(AF_INET, SOCK_STREAM, ctx->use_sctp ? IPPROTO_SCTP : IPPROTO_TCP);
        if (sockfd < 0)
        {
            fprintf(stderr, "ERROR: Failed to create socket.\n");
            return;
        }

        bzero((char *)&address, sizeof(address));
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = peer->ip_addr;
        address.sin_port = htons(peer->port); // Convert to network byteorder

        if (connect(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0)
        {
            fprintf(stderr, "ERROR: connect failed for new peer.\n");
            close(sockfd);
            FD_CLR(sockfd, &ctx->peer_fds);
            sockfd = -1;
            peer->sock = -1;
            return;
        }

        // Set socket to client
        peer->sock = sockfd;
        // Add socket to master set
        FD_SET(sockfd, &ctx->peer_fds);

        // Update max socket
        if (sockfd > ctx->max_fd)
        {
            ctx->max_fd = sockfd;
        }
    }

    send_data_packet(peer->sock, connect_packet, peer_connect_buffer, buffer_length);
    peer->is_new = 0;
}

void connect_to_new_peers(chat_application_context *ctx)
{
    packet connect_packet = create_packet(
        PROTOCOL_VERSION,
        MSG_CONNECT,
        0,
        NULL);

    char peer_connect_buffer[INPUT_BUFFER_LEN];

    int offset = 0;

    // Copy IP-Address to packet-data
    memcpy(peer_connect_buffer + offset, (char *)&ctx->peer_list->data->ip_addr, IP_ADDR_LEN);
    offset += IP_ADDR_LEN;

    // Copy port
    uint16_t port = PORT;
    memcpy(peer_connect_buffer + offset, (char *)&port, PORT_LEN);
    offset += PORT_LEN;

    // Copy length of name
    uint16_t name_len = (uint16_t)strlen(ctx->peer_list->data->name) + 1; // + 1 for null-terminator
    memcpy(peer_connect_buffer + offset, (char *)&name_len, NAME_LEN_LEN);
    offset += NAME_LEN_LEN;

    // Copy name
    memcpy(peer_connect_buffer + offset, ctx->peer_list->data->name, (int)name_len);
    offset += (int)name_len;

    // Send connect to all new peers
    // Send data
    for (list_node *node = ctx->peer_list->next; node != NULL; node = node->next)
    {
        if (node->data->is_new)
        {
            connect_to_new_peer(ctx, node->data, &connect_packet, peer_connect_buffer, offset);
        }
    }
}

void handle_enter_req(chat_application_context *ctx, int sock, int length, char type, BOOL use_sctp)
{
    receive_new_peer(ctx, sock, type, length);
    propagate_new_peer(ctx, sock);
    connect_to_new_peers(ctx);
}

void handle_connect(list_node *peer_list, int sock)
{
    char entry_header_buf[ENTRY_HEADER_LEN];

    peer *new_peer = malloc(sizeof(peer));
    int offset = 0;

    receive_from_socket(sock, entry_header_buf, ENTRY_HEADER_LEN);

    new_peer->ip_addr = *((uint32_t *)(entry_header_buf + offset));
    offset += IP_ADDR_LEN;

    new_peer->port = *((uint16_t *)(entry_header_buf + offset));
    offset += PORT_LEN;

    int name_length = *((uint16_t *)(entry_header_buf + offset));
    offset += NAME_LEN_LEN;

    // Receive name
    new_peer->name = malloc(name_length + 1);
    bzero(new_peer->name, name_length + 1);

    char name_buf[name_length + 1];
    bzero(name_buf, name_length + 1);

    receive_from_socket(sock, name_buf, name_length);

    strcpy(new_peer->name, name_buf);

    new_peer->sock = sock;
    new_peer->connected = 1;
    new_peer->is_new = 0;
    new_peer->heartbeat_timer = HEARTBEAT_TIME;

    list_add(&peer_list, new_peer);

    printf("Connect received.\n");
}

void remove_peer_by_socket(list_node *peer_list, int sock)
{
    for (list_node *node = peer_list; node != NULL; node = node->next)
    {
        if (node->data->sock == sock)
        {
            uint32_t peer_ip = node->data->ip_addr;
            list_remove(&peer_list, peer_ip);
            break;
        }
    }
}

void handle_message(list_node *peer_list, int sock, size_t packet_length, BOOL is_private)
{
    char data_buffer[packet_length];

    receive_from_socket(sock, data_buffer, packet_length);

    for (list_node *node = peer_list; node != NULL; node = node->next)
    {
        if (node->data->sock == sock)
        {
            print_message(node->data, data_buffer, is_private);
        }
    }
}

void handle_disconnect(list_node *peer_list, int sock, fd_set *peer_fds)
{
    printf("INFO: Disconnect received.\n");

    remove_peer_by_socket(peer_list, sock);

    // TODO: max_fd entsprechend anpassen
    FD_CLR(sock, peer_fds); // remove from master set
    close(sock);
    sock = -1;
}

void handle_failed(list_node *peer_list, int sock, fd_set *peer_fds)
{
    char data_buffer[sizeof(int32_t)];

    receive_from_socket(sock, data_buffer, sizeof(int32_t));
    printf("Failed received with code: %d\n", (int)*data_buffer);

    FD_CLR(sock, peer_fds); // remove from master set
    close(sock);
    remove_peer_by_socket(peer_list, sock);

    sock = -1;
}

void handle_heartbeat(list_node *peer_list, int sock, BOOL use_sctp)
{
    // If SCTP is enabled, we don't need the heartbeat
    // since SCTP has its own heartbeat
    if (use_sctp)
        return;

    // Reset heartbeat of peer
    for (list_node *peer = peer_list; peer != NULL; peer = peer->next)
    {
        if (peer->data->sock != sock)
        {
            continue;
        }
        else
        {
            // Peer found -> Reset timer
            peer->data->heartbeat_timer = HEARTBEAT_TIME;
        }
    }
}

void parse_packet(chat_application_context *ctx, int sock, char *header_buf)
{
    // Data received from client
    packet incoming_packet;
    memcpy(&incoming_packet, header_buf, HEADER_LEN);

    switch (incoming_packet.type)
    {
    case MSG_NEW_USERS:
    case MSG_ENTER_REQ:
        handle_enter_req(ctx, sock, incoming_packet.length, incoming_packet.type, ctx->use_sctp);
        break;
    case MSG_FAILED:
        handle_failed(ctx->peer_list, sock, &ctx->peer_fds);
        break;
    case MSG_CONNECT:
        handle_connect(ctx->peer_list, sock);
        break;
    case MSG_DISCONNECT:
        handle_disconnect(ctx->peer_list, sock, &ctx->peer_fds);
        break;
    case MSG_MESSAGE:
        handle_message(ctx->peer_list, sock, incoming_packet.length, FALSE);
        break;
    case MSG_PRIVATE:
        handle_message(ctx->peer_list, sock, incoming_packet.length, TRUE);
        break;
    case MSG_HEARTBEAT:
        handle_heartbeat(ctx->peer_list, sock, ctx->use_sctp);
        break;
    default:
        break;
    }
}

void recv_packet(chat_application_context *ctx, int sock, BOOL use_sctp)
{
    pthread_mutex_lock(ctx->peer_mutex);

    int nbytes;
    char header_buf[HEADER_LEN];

    // Handle data from client
    if ((nbytes = recv(sock, header_buf, HEADER_LEN, 0)) <= 0)
    {
        // If there's an error, the connection is reset
        if (nbytes == 0)
        {
            // Connection is closed
            printf("INFO: Socket %d hung up\n", sock);
        }
        else
        {
            fprintf(stderr, "ERROR: Error in recv()\n");
        }

        // Remove client from list if error in connection has occured
        for (list_node *node = ctx->peer_list->next; node != NULL; node = node->next)
        {
            if (node->data->sock == sock)
            {
                list_remove(&ctx->peer_list, node->data->ip_addr);
                break;
            }
        }

        close(sock);                  // bye!
        FD_CLR(sock, &ctx->peer_fds); // remove from master set
        sock = -1;
    }
    else
    {
        parse_packet(ctx, sock, header_buf);
    }

    pthread_mutex_unlock(ctx->peer_mutex);
}