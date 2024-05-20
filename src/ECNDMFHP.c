#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>

#include "ECNDMFHP.h"
#include "helper.h"

packet create_packet(char version, char type, short length)
{
    return (packet){
        .version = version,
        .type = type,
        .length = length};
}

void send_packet(int sock, packet *pack)
{
    send(sock, pack, HEADER_LEN, 0);
}

void send_data_packet(int sock, packet *pack, char *data_buffer, int data_buffer_length)
{
    send(sock, pack, HEADER_LEN, 0);
    send(sock, data_buffer, data_buffer_length, 0);
}

// Returns the data created for the enter request package
enter_request create_enter_req_data(list_node *peer_list)
{
    char *data = malloc(1);
    if (!data)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for request data, exiting.\n");
        exit(-1);
    }

    int total_length = 0;
    int previous_total_length = 0;

    // Iterate over peers
    list_node *peer = peer_list;
    while (peer)
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

        peer = peer->next;
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
        MSG_FAILED, 1); // 1 single byte for the error code

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

int receive_from_socket(int sock, char *buffer, size_t length)
{
    int bytes_received = 0;

    if ((bytes_received = recv(sock, buffer, length, 0)) <= 0)
    {
        // If there's an error, the connection is reset
        if (bytes_received == 0)
        {
            // Connection is closed
            printf("INFO: Socket %d hung up.\n", sock);
        }
        else
        {
            fprintf(stderr, "ERROR: Error in recv().\n");
            close(sock);
            exit(4);
        }
    }

    return bytes_received;
}

int parse_new_peer(int sock, char *packet_data_buffer, peer *new_peer)
{
    int buffer_offset = 0;

    new_peer->ip_addr = *((uint32_t *)(packet_data_buffer + buffer_offset));
    buffer_offset += IP_ADDR_LEN;

    new_peer->port = *((uint16_t *)(packet_data_buffer + buffer_offset));
    buffer_offset += PORT_LEN;

    int name_length = *((uint16_t *)(packet_data_buffer + buffer_offset));
    buffer_offset += NAME_LEN_LEN;

    // Receive name
    new_peer->name = malloc(name_length + 1);
    if (!new_peer->name)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for peer name, exiting.\n");
        exit(-1);
    }

    bzero(new_peer->name, name_length + 1);

    memcpy(new_peer->name, packet_data_buffer + buffer_offset, name_length);

    return buffer_offset;
}

void parse_new_peers(list_node *peer_list, int sock, char *packet_data_buffer, char type, size_t length)
{
    int buffer_offset = 0;
    int new_peer_index = 0;

    while (buffer_offset <= length)
    {
        peer *new_peer = malloc(sizeof(peer));
        if (!new_peer)
        {
            fprintf(stderr, "ERROR: Could not allocate memory for new peer, exiting.\n");
            exit(-1);
        }

        buffer_offset += parse_new_peer(sock, packet_data_buffer + buffer_offset, new_peer);

        // Search through list to see if entry already exists
        list_node *peer = peer_list;
        while (peer)
        {
            if (!strcmp(peer->data->name, new_peer->name))
            {
                printf("INFO: Name taken!\n");
                send_failed(sock);
                free(new_peer->name);
                free(new_peer);
                return;
            }

            peer = peer->next;
        }

        // Initialize new peer
        new_peer->connected = 1;

        // TODO: What does this do?
        // We know the socket from the connecting peer
        if (new_peer_index == 0 && type != MSG_NEW_USERS)
        {
            new_peer->sock = sock;
        }
        else
        {
            new_peer->sock = -1; // No socket from other participants known
        }
        new_peer->is_new = 1;
        new_peer->heartbeat_timer = HEARTBEAT_TIME;

        printf("INFO: %s joined the chat.\n", new_peer->name);
        list_add(&peer_list, new_peer);

        new_peer_index++;
    }
}

void propagate_new_peers(list_node *peer_list, int sock)
{
    enter_request req = create_enter_req_data(peer_list);

    packet new_user = create_packet(
        PROTOCOL_VERSION,
        MSG_NEW_USERS,
        req.length);

    // Send recently added users to older users in list and set newUsers = oldusers
    list_node *peer = peer_list->next;
    while (peer)
    {
        if (!(peer->data->is_new) && peer->data->sock != sock)
        {
            send_data_packet(peer->data->sock, &new_user, req.data, new_user.length);
            peer->data->is_new = 0;
        }

        peer = peer->next;
    }

    // Free data from enter request
    free(req.data);
}

void connect_to_new_peer(list_node *peer_list, peer *peer, packet *connect_packet,
                         char *peer_connect_buffer, int buffer_length, BOOL use_sctp,
                         fd_set *peer_fds, int *max_fd)
{
    // If not connected to peer yet, open connection
    if (peer->sock < 0)
    {
        // socket-file destriptor
        struct sockaddr_in address;
        int sockfd = socket(AF_INET, SOCK_STREAM, use_sctp ? IPPROTO_SCTP : IPPROTO_TCP);
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
            FD_CLR(sockfd, peer_fds);
            sockfd = -1;
            peer->sock = -1;
            return;
        }

        // Set socket to client
        peer->sock = sockfd;
        // Add socket to master set
        FD_SET(sockfd, peer_fds);

        // Update max socket
        if (sockfd > *max_fd)
        {
            *max_fd = sockfd;
        }
    }

    send_data_packet(peer->sock, connect_packet, peer_connect_buffer, buffer_length);
    peer->is_new = 0;
}

void connect_to_new_peers(list_node *peer_list, fd_set *peer_fds, int *max_fd, BOOL use_sctp)
{
    packet connect_packet = create_packet(
        PROTOCOL_VERSION,
        MSG_CONNECT,
        0);

    char peer_connect_buffer[INPUT_BUFFER_LEN];

    int buffer_offset = 0;

    // Copy IP-Address to packet-data
    memcpy(peer_connect_buffer + buffer_offset, (char *)&peer_list->data->ip_addr, IP_ADDR_LEN);
    buffer_offset += IP_ADDR_LEN;

    // Copy port
    uint16_t port = PORT;
    memcpy(peer_connect_buffer + buffer_offset, (char *)&port, PORT_LEN);
    buffer_offset += PORT_LEN;

    // Copy length of name
    uint16_t name_len = (uint16_t)strlen(peer_list->data->name) + 1; // + 1 for null-terminator
    memcpy(peer_connect_buffer + buffer_offset, (char *)&name_len, NAME_LEN_LEN);
    buffer_offset += NAME_LEN_LEN;

    // Copy name
    memcpy(peer_connect_buffer + buffer_offset, peer_list->data->name, (int)name_len);
    buffer_offset += (int)name_len;

    // Send connect to all new peers
    // Send data
    list_node *peer = peer_list->next;
    while (peer)
    {
        if (peer->data->is_new)
        {
            connect_to_new_peer(peer_list, peer->data, &connect_packet,
                                peer_connect_buffer, buffer_offset, use_sctp, peer_fds, max_fd);
        }

        peer = peer->next;
    }
}

void handle_enter_req(list_node *peer_list, int sock, char *packet_data_buffer, size_t length,
                      char type, BOOL use_sctp, fd_set *peer_fds, int *max_fd)
{
    parse_new_peers(peer_list, sock, packet_data_buffer, type, length);
    propagate_new_peers(peer_list, sock);
    connect_to_new_peers(peer_list, peer_fds, max_fd, use_sctp);
}

void handle_connect(list_node *peer_list, int sock, char *packet_data_buffer, size_t length)
{
    peer *new_peer = malloc(sizeof(peer));
    if (!new_peer)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for new peer, exiting.\n");
        exit(-1);
    }

    int buffer_offset = 0;

    new_peer->ip_addr = *((uint32_t *)(packet_data_buffer + buffer_offset));
    buffer_offset += IP_ADDR_LEN;

    new_peer->port = *((uint16_t *)(packet_data_buffer + buffer_offset));
    buffer_offset += PORT_LEN;

    int name_length = *((uint16_t *)(packet_data_buffer + buffer_offset));
    buffer_offset += NAME_LEN_LEN;

    // Receive name
    new_peer->name = malloc(name_length + 1);
    if (!new_peer->name)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for new peers name, exiting.\n");
        exit(-1);
    }

    memcpy (new_peer->name, packet_data_buffer + buffer_offset, name_length);

    new_peer->sock = sock;
    new_peer->connected = 1;
    new_peer->is_new = 0;
    new_peer->heartbeat_timer = HEARTBEAT_TIME;

    list_add(&peer_list, new_peer);

    printf("Connect received.\n");
}

void remove_peer_by_socket(list_node *peer_list, int sock)
{
    list_node *peer = peer_list;
    while (peer)
    {
        if (peer->data->sock == sock)
        {
            uint32_t peer_ip = peer->data->ip_addr;
            list_remove(&peer_list, peer_ip);
        }

        peer = peer->next;
    }
}

void handle_message(list_node *peer_list, int sock, char *packet_data_buffer, BOOL is_private)
{
    list_node *peer = peer_list;
    while (peer)
    {
        if (peer->data->sock == sock)
        {
            print_message(peer->data, packet_data_buffer, is_private);
        }

        peer = peer->next;
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

void handle_failed(list_node *peer_list, int sock, char *packet_data_buffer, fd_set *peer_fds)
{
    printf("Failed received with code: %d\n", *((int32_t*)packet_data_buffer));

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
    list_node *peer = peer_list;
    while (peer)
    {
        if (peer->data->sock == sock)
        {
            // Peer found -> Reset timer
            peer->data->heartbeat_timer = HEARTBEAT_TIME;
        }

        peer = peer->next;
    }
}

void parse_packet(list_node *peer_list, int sock, packet *incoming_packet, char *packet_data_buffer,
                  BOOL use_sctp, fd_set *peer_fds, int *max_fd)
{
    switch (incoming_packet->type)
    {
    case MSG_NEW_USERS:
    case MSG_ENTER_REQ:
        handle_enter_req(peer_list, sock, packet_data_buffer, incoming_packet->length,
                         incoming_packet->type, use_sctp, peer_fds, max_fd);
        break;
    case MSG_FAILED:
        handle_failed(peer_list, sock, packet_data_buffer, peer_fds);
        break;
    case MSG_CONNECT:
        handle_connect(peer_list, sock, packet_data_buffer, incoming_packet->length);
        break;
    case MSG_DISCONNECT:
        handle_disconnect(peer_list, sock, peer_fds);
        break;
    case MSG_MESSAGE:
        // TODO: Check length of message
        handle_message(peer_list, sock, packet_data_buffer, FALSE);
        break;
    case MSG_PRIVATE:
        handle_message(peer_list, sock, packet_data_buffer, TRUE);
        break;
    case MSG_HEARTBEAT:
        handle_heartbeat(peer_list, sock, use_sctp);
        break;
    default:
        break;
    }
}

void recv_packet(chat_application_context *ctx, int sock, BOOL use_sctp)
{
    pthread_mutex_lock(ctx->peer_mutex);

    char header_buffer[HEADER_LEN];

    // Read header of packet
    if (receive_from_socket(sock, header_buffer, HEADER_LEN) <= 0)
    {
        // Remove client from list if error in connection has occured
        list_node *peer = ctx->peer_list->next;
        while (peer)
        {
            if (peer->data->sock == sock)
            {
                list_remove(&ctx->peer_list, peer->data->ip_addr);
            }

            peer = peer->next;
        }

        close(sock);                  // bye!
        FD_CLR(sock, &ctx->peer_fds); // remove from master set
        sock = -1;
    }
    else
    {
        packet incoming_packet;
        memcpy(&incoming_packet, header_buffer, HEADER_LEN);

        // Read data section of packet
        char *packet_data_buffer = malloc(incoming_packet.length);
        receive_from_socket(sock, packet_data_buffer, incoming_packet.length);

        parse_packet(ctx->peer_list, sock, &incoming_packet, packet_data_buffer, ctx->use_sctp,
                     &ctx->peer_fds, &ctx->max_fd);
    }

    pthread_mutex_unlock(ctx->peer_mutex);
}
