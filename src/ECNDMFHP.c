#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>

#include "ECNDMFHP.h"
#include "helper.h"

packet_header create_packet_header(char type, uint32_t length)
{
    return (packet_header){
        .version = PROTOCOL_VERSION,
        .type = type,
        .length = length};
}

void send_packet_header(int sock, packet_header *header)
{
    // Send protocol version and packet_header type
    send(sock, header, HEADER_PROTOCOL_VERSION_LEN + HEADER_PACKET_TYPE_LEN, 0);

    uint32_t packet_length = htonl(header->length);
    send(sock, &packet_length, HEADER_PACKET_LEN_LEN, 0);
}

void send_packet(int sock, packet_header *header)
{
    send_packet_header(sock, header);
}

void send_data_packet(int sock, packet_header *header, data_buffer *data_buffer)
{
    send_packet_header(sock, header);
    send(sock, data_buffer->data, data_buffer->length, 0);
}

size_t receive_from_socket(int sock, char *buffer, size_t length)
{
    size_t bytes_received = 0;

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

void remove_peer_and_close_socket(int sock, list_node *peer_list, peer_and_max_fds_tuple *peer_and_max_fds)
{
    // Remove client from list if error in connection has occured
    list_node *peer = peer_list->next;
    while (peer)
    {
        if (peer->data->sock == sock)
        {
            list_remove(&peer_list, peer->data->ip_addr);
        }

        peer = peer->next;
    }

    close(sock);                              // bye!
    FD_CLR(sock, peer_and_max_fds->peer_fds); // remove from master set
    sock = -1;
}

packet_header *receive_packet_header(int sock, list_node *peer_list, peer_and_max_fds_tuple *peer_and_max_fds)
{
    size_t bytes_received = 0;
    packet_header *packet_header = malloc(sizeof(packet_header));
    if (!packet_header)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for header packet_header, exiting.");
        exit(-1);
    }

    // Read protocol version & packet_header type
    bytes_received = receive_from_socket(sock, &packet_header->version, HEADER_PROTOCOL_VERSION_LEN);
    if (bytes_received == 0)
    {
        remove_peer_and_close_socket(sock, peer_list, peer_and_max_fds);
        return NULL;
    }

    bytes_received = receive_from_socket(sock, &packet_header->type, HEADER_PACKET_TYPE_LEN);
    if (bytes_received == 0)
    {
        remove_peer_and_close_socket(sock, peer_list, peer_and_max_fds);
        return NULL;
    }

    // Read integer for packet_header length
    uint32_t packet_length_buffer;
    bytes_received = receive_from_socket(sock, (char *)&packet_length_buffer, HEADER_PACKET_LEN_LEN);
    if (bytes_received == 0)
    {
        remove_peer_and_close_socket(sock, peer_list, peer_and_max_fds);
        return NULL;
    }

    packet_header->length = ntohl(packet_length_buffer);

    return packet_header;
}

data_buffer serialize_peer_data(peer *peer)
{
    size_t buffer_offset = 0;
    uint16_t name_length = (uint16_t)strlen(peer->name) + 1; // + 1 for null-terminator
    char *serialized_peer = malloc(sizeof(peer) + name_length);

    // Copy IP-Address to packet_header-data
    memcpy(serialized_peer + buffer_offset, (char *)&peer->ip_addr, IP_ADDR_LEN);
    buffer_offset += IP_ADDR_LEN;

    // Copy port
    memcpy(serialized_peer + buffer_offset, (char *)&peer->port, PORT_LEN);
    buffer_offset += PORT_LEN;

    // Copy length of name
    memcpy(serialized_peer + buffer_offset, (char *)&name_length, NAME_LEN_LEN);
    buffer_offset += NAME_LEN_LEN;

    // Copy name
    memcpy(serialized_peer + buffer_offset, peer->name, (int)name_length);
    buffer_offset += name_length;

    return (data_buffer){
        .data = serialized_peer,
        .length = buffer_offset};
}

peer_tuple deserialize_peer_data(data_buffer *packet_data_buffer)
{
    size_t buffer_offset = 0;
    peer *new_peer = malloc(sizeof(peer));
    if (!new_peer)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for new peer, exiting.\n");
        exit(-1);
    }

    new_peer->ip_addr = *((uint32_t *)(packet_data_buffer->data + buffer_offset));
    buffer_offset += IP_ADDR_LEN;

    new_peer->port = *((uint16_t *)(packet_data_buffer->data + buffer_offset));
    buffer_offset += PORT_LEN;

    uint16_t name_length = *((uint16_t *)(packet_data_buffer->data + buffer_offset));
    buffer_offset += NAME_LEN_LEN;

    new_peer->name = malloc(name_length + 1);
    if (!new_peer->name)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for peer name, exiting.\n");
        exit(-1);
    }

    bzero(new_peer->name, name_length + 1);

    memcpy(new_peer->name, packet_data_buffer->data + buffer_offset, name_length);
    buffer_offset += name_length;

    return (peer_tuple){
        .peer = new_peer,
        .peer_size = buffer_offset};
}

// Returns the data created for the enter request package
data_buffer create_enter_req_data(list_node *peer_list)
{
    char *data = malloc(1);
    if (!data)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for request data, exiting.\n");
        exit(-1);
    }

    size_t total_length = 0;
    size_t previous_total_length = 0;

    // Iterate over peers
    list_node *peer = peer_list;
    while (peer)
    {
        previous_total_length = total_length;
        data_buffer buffer = serialize_peer_data(peer->data);
        total_length += buffer.length;

        // Increase size of data buffer for more peers and copy serialized peer to buffer
        data = realloc(data, total_length);
        memcpy(data + previous_total_length, buffer.data, buffer.length);

        peer = peer->next;

        free(buffer.data);
    }

    return (data_buffer){
        .data = data,
        .length = total_length};
}

void send_failed(int sock)
{
    // Create failed packet_header
    packet_header failed = create_packet_header(MSG_FAILED, 1); // 1 single byte for the error code

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

void parse_new_peers(peer_list_sock_tuple peer_list_and_socket, data_buffer *packet_data_buffer, char type)
{
    size_t peer_buffer_offset = 0;
    int new_peer_index = 0;

    while (peer_buffer_offset < packet_data_buffer->length)
    {
        peer_tuple new_peer = deserialize_peer_data(
            &(data_buffer){
                // Add calculated buffer offset to packet_header data buffer
                // to iterate through peers in received list.
                .data = packet_data_buffer->data + peer_buffer_offset,
                .length = packet_data_buffer->length});
        peer_buffer_offset += new_peer.peer_size;

        // Search through list to see if entry already exists
        list_node *peer = peer_list_and_socket.peer_list;
        while (peer)
        {
            if (!strcmp(peer->data->name, new_peer.peer->name))
            {
                printf("INFO: Name taken!\n");
                send_failed(peer_list_and_socket.sock);
                free(new_peer.peer->name);
                free(new_peer.peer);
                return;
            }

            peer = peer->next;
        }

        // Initialize new peer
        new_peer.peer->connected = 1;

        // TODO: What does this do?
        // We know the socket from the connecting peer
        if (new_peer_index == 0 && type == MSG_NEW_USERS)
        {
            new_peer.peer->sock = peer_list_and_socket.sock;
        }
        else
        {
            new_peer.peer->sock = -1; // No socket from other participants known
        }
        new_peer.peer->is_new = 1;
        new_peer.peer->heartbeat_timer = HEARTBEAT_TIME;

        printf("INFO: %s joined the chat.\n", new_peer.peer->name);
        list_add(&peer_list_and_socket.peer_list, new_peer.peer);

        new_peer_index++;
    }
}

void propagate_new_peers(peer_list_sock_tuple peer_list_and_socket)
{
    data_buffer request_buffer = create_enter_req_data(peer_list_and_socket.peer_list);

    packet_header new_user = create_packet_header(MSG_NEW_USERS, request_buffer.length);

    // Send recently added users to older users in list and set newUsers = oldusers
    list_node *peer = peer_list_and_socket.peer_list->next;
    while (peer)
    {
        if (!(peer->data->is_new) && peer->data->sock != peer_list_and_socket.sock)
        {
            send_data_packet(peer->data->sock, &new_user, &request_buffer);
            peer->data->is_new = 0;
        }

        peer = peer->next;
    }

    free(request_buffer.data);
}

void connect_to_new_peer(list_node *peer_list, peer *peer, packet_header connect_packet,
                         data_buffer *data_buffer, peer_and_max_fds_tuple peer_and_max_fds, BOOL use_sctp)
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
            FD_CLR(sockfd, peer_and_max_fds.peer_fds);
            sockfd = -1;
            peer->sock = -1;
            return;
        }

        // Set socket to client
        peer->sock = sockfd;
        // Add socket to master set
        FD_SET(sockfd, peer_and_max_fds.peer_fds);

        // Update max socket
        if (sockfd > *peer_and_max_fds.max_fd)
        {
            *peer_and_max_fds.max_fd = sockfd;
        }
    }

    send_data_packet(peer->sock, &connect_packet, data_buffer);
    peer->is_new = 0;
}

void connect_to_new_peers(list_node *peer_list, peer_and_max_fds_tuple peer_and_max_fds, BOOL use_sctp)
{
    packet_header connect_packet = create_packet_header(MSG_CONNECT, 0);

    // Create data buffer of ourselves
    peer us = *peer_list->data;
    data_buffer peer_connect_buffer = serialize_peer_data(&us);

    // Send connect to all new peers
    // Send data
    list_node *peer = peer_list->next;
    while (peer)
    {
        if (peer->data->is_new)
        {
            connect_to_new_peer(peer_list, peer->data, connect_packet,
                                &peer_connect_buffer, peer_and_max_fds, use_sctp);
        }

        peer = peer->next;
    }

    free(peer_connect_buffer.data);
}

void handle_enter_req(peer_list_sock_tuple peer_list_and_socket, data_buffer *packet_data_buffer,
                      char type, peer_and_max_fds_tuple peer_and_max_fds, BOOL use_sctp)
{
    parse_new_peers(peer_list_and_socket, packet_data_buffer, type);
    propagate_new_peers(peer_list_and_socket);
    connect_to_new_peers(peer_list_and_socket.peer_list, peer_and_max_fds, use_sctp);
}

void handle_connect(peer_list_sock_tuple peer_list_and_socket, data_buffer *packet_data_buffer)
{
    peer_tuple new_peer = deserialize_peer_data(packet_data_buffer);

    new_peer.peer->sock = peer_list_and_socket.sock;
    new_peer.peer->connected = 1;
    new_peer.peer->is_new = 0;
    new_peer.peer->heartbeat_timer = HEARTBEAT_TIME;

    list_add(&peer_list_and_socket.peer_list, new_peer.peer);
    printf("Connect received.\n");
}

void remove_peer_by_socket(peer_list_sock_tuple peer_list_and_socket)
{
    list_node *peer = peer_list_and_socket.peer_list;
    while (peer)
    {
        if (peer->data->sock == peer_list_and_socket.sock)
        {
            uint32_t peer_ip = peer->data->ip_addr;
            list_remove(&peer_list_and_socket.peer_list, peer_ip);
        }

        peer = peer->next;
    }
}

void handle_message(peer_list_sock_tuple peer_list_and_socket, data_buffer *packet_data_buffer, BOOL is_private)
{
    list_node *peer = peer_list_and_socket.peer_list;
    while (peer)
    {
        if (peer->data->sock == peer_list_and_socket.sock)
        {
            print_message(peer->data, packet_data_buffer->data, is_private);
        }

        peer = peer->next;
    }
}

void handle_disconnect(peer_list_sock_tuple peer_list_and_socket, fd_set *peer_fds)
{
    printf("INFO: Disconnect received.\n");

    // TODO: max_fd entsprechend anpassen
    FD_CLR(peer_list_and_socket.sock, peer_fds); // remove from master set
    close(peer_list_and_socket.sock);
    remove_peer_by_socket(peer_list_and_socket);

    peer_list_and_socket.sock = -1;
}

void handle_failed(peer_list_sock_tuple peer_list_and_socket, data_buffer *packet_data_buffer, fd_set *peer_fds)
{
    printf("Failed received with code: %d\n", *((int32_t *)packet_data_buffer->data));

    FD_CLR(peer_list_and_socket.sock, peer_fds); // remove from master set
    close(peer_list_and_socket.sock);
    remove_peer_by_socket(peer_list_and_socket);

    peer_list_and_socket.sock = -1;
}

void handle_heartbeat(peer_list_sock_tuple peer_list_and_socket, BOOL use_sctp)
{
    // If SCTP is enabled, we don't need the heartbeat
    // since SCTP has its own heartbeat
    if (use_sctp)
        return;

    // Reset heartbeat of peer
    list_node *peer = peer_list_and_socket.peer_list;
    while (peer)
    {
        if (peer->data->sock == peer_list_and_socket.sock)
        {
            // Peer found -> Reset timer
            peer->data->heartbeat_timer = HEARTBEAT_TIME;
        }

        peer = peer->next;
    }
}

void parse_packet(peer_list_sock_tuple peer_list_and_socket, packet_header *incoming_packet,
                  data_buffer *packet_data_buffer, peer_and_max_fds_tuple peer_and_max_fds, BOOL use_sctp)
{
    switch (incoming_packet->type)
    {
    case MSG_NEW_USERS:
    case MSG_ENTER_REQ:
        handle_enter_req(peer_list_and_socket, packet_data_buffer,
                         incoming_packet->type, peer_and_max_fds, use_sctp);
        break;
    case MSG_FAILED:
        handle_failed(peer_list_and_socket, packet_data_buffer, peer_and_max_fds.peer_fds);
        break;
    case MSG_CONNECT:
        handle_connect(peer_list_and_socket, packet_data_buffer);
        break;
    case MSG_DISCONNECT:
        handle_disconnect(peer_list_and_socket, peer_and_max_fds.peer_fds);
        break;
    case MSG_MESSAGE:
        // TODO: Check length of message
        handle_message(peer_list_and_socket, packet_data_buffer, FALSE);
        break;
    case MSG_PRIVATE:
        handle_message(peer_list_and_socket, packet_data_buffer, TRUE);
        break;
    case MSG_HEARTBEAT:
        handle_heartbeat(peer_list_and_socket, use_sctp);
        break;
    default:
        break;
    }
}

void recv_packet(chat_application_context *ctx, int sock)
{
    pthread_mutex_lock(ctx->peer_mutex);

    peer_and_max_fds_tuple peer_and_max_fds = {
        .peer_fds = &ctx->peer_fds,
        .max_fd = &ctx->max_fd};

    // Read header of packet_header
    packet_header *incoming_packet = receive_packet_header(sock, ctx->peer_list, &peer_and_max_fds);

    if (incoming_packet)
    {
        // Read data section of packet_header
        data_buffer packet_data_buffer = {
            .data = malloc(incoming_packet->length),
            .length = incoming_packet->length};
        if (!packet_data_buffer.data)
        {
            fprintf(stderr, "ERROR: Could allocate memory for packet_header data buffer, exiting.\n");
            exit(-1);
        }
        receive_from_socket(sock, packet_data_buffer.data, incoming_packet->length);

        parse_packet((peer_list_sock_tuple){
                         .peer_list = ctx->peer_list,
                         .sock = sock},
                     incoming_packet, &packet_data_buffer, peer_and_max_fds, ctx->use_sctp);

        free(packet_data_buffer.data);
        free(incoming_packet);
    }

    pthread_mutex_unlock(ctx->peer_mutex);
}
