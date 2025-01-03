#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>

#include "ECNDMFHP.h"
#include "helper.h"
#include "debug.h"

packet_header create_packet_header(char type, uint32_t length)
{
    return (packet_header){
        .version = PROTOCOL_VERSION,
        .type = type,
        .length = htonl(length)};
}

/**
 * send_packet is used to send "dataless" packets which are self contained in the packet header.
 */
void send_packet(int sock, packet_header *header)
{
    DEBUG("Sending header with (0x%02x, %c, 0x%08x)\n", header->version, header->type, header->length);
    send(sock, header, sizeof(packet_header), 0);
}

/**
 * send_data_packet sends a packet consisting of the header and a variable data buffer.
 */
void send_data_packet(int sock, packet_header *header, data_buffer *data_buffer)
{
    size_t packet_length = sizeof(packet_header) + data_buffer->length;
    char packet_buffer[packet_length];

    memcpy(packet_buffer, header, sizeof(packet_header));
    memcpy(packet_buffer + sizeof(packet_header), data_buffer->data, data_buffer->length);

    send(sock, packet_buffer, packet_length, 0);
}

size_t receive_from_socket(int sock, void *buffer, size_t length)
{
    size_t bytes_received = 0;

    if ((bytes_received = recv(sock, buffer, length, 0)) <= 0)
    {
        // If there's an error, the connection is reset
        if (bytes_received == 0)
        {
            // Connection is closed
            printf("INFO: Socket %d hung up.\n", sock);
            close(sock);
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

list_node *find_peer_by_socket(peer_list_sock_tuple peer_and_sock)
{
    list_node *peer = peer_and_sock.peer_list;
    while (peer)
    {
        if (peer->data->sock == peer_and_sock.sock)
            return peer;

        peer = peer->next;
    }

    return NULL;
}

list_node *find_peer_by_name(list_node *peer_list, peer *search_peer)
{
    list_node *peer = peer_list;
    while (peer)
    {
        DEBUG("Comparing peer %s with %s.\n", peer->data->name, search_peer->name);

        if (strcmp(peer->data->name, search_peer->name) == 0)
        {
            DEBUG("Peer with name %s found. Returning %s.\n",
                search_peer->name,
                search_peer->name);
            return peer;
        }

        peer = peer->next;
    }

    DEBUG("No peer with name %s found. Returning NULL.\n", search_peer->name);
    return NULL;
}

void remove_peer_and_close_socket(peer_list_sock_tuple peer_and_sock, peer_and_max_fds_tuple *peer_and_max_fds)
{
    // Remove client from list if error in connection has occured
    list_node *peer = find_peer_by_socket(peer_and_sock);
    if (peer)
    {
        list_remove(&peer_and_sock.peer_list, peer->data->ip_addr);
        FD_CLR(peer_and_sock.sock, peer_and_max_fds->peer_fds); // remove from master set
        peer_and_sock.sock = -1;
    }
}

packet_header *receive_packet_header(peer_list_sock_tuple peer_and_sock, peer_and_max_fds_tuple *peer_and_max_fds)
{
    size_t bytes_received = 0;
    packet_header *header = malloc(sizeof(packet_header));
    if (!header)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for header packet_header, exiting.");
        exit(1);
    }

    bytes_received = receive_from_socket(peer_and_sock.sock, header, sizeof(packet_header));
    if (bytes_received == 0)
    {
        remove_peer_and_close_socket(peer_and_sock, peer_and_max_fds);
        return NULL;
    }

    header->length = ntohl(header->length);
    DEBUG("0x%02x, %c, 0x%08x\n", header->version, header->type, header->length);

    return header;
}

data_buffer serialize_peer_data(peer *p)
{
    size_t buffer_offset = 0;
    uint16_t name_length = (uint16_t)strlen(p->name) + 1; // + 1 for null-terminator
    char *serialized_peer = malloc(sizeof(peer) + name_length);

    // Copy IP-Address to packet_header-data
    memcpy(serialized_peer + buffer_offset, (char *)&p->ip_addr, IP_ADDR_LEN);
    buffer_offset += IP_ADDR_LEN;

    // Copy port
    memcpy(serialized_peer + buffer_offset, (char *)&p->port, PORT_LEN);
    buffer_offset += PORT_LEN;

    // Copy length of name
    memcpy(serialized_peer + buffer_offset, (char *)&name_length, NAME_LEN_LEN);
    buffer_offset += NAME_LEN_LEN;

    // Copy name
    memcpy(serialized_peer + buffer_offset, p->name, (int)name_length);
    buffer_offset += name_length;

    return (data_buffer){
        .data = serialized_peer,
        .length = buffer_offset};
}

peer_tuple deserialize_peer_data(data_buffer *packet_data_buffer)
{
    size_t buffer_offset = 0;
    peer *new_peer = malloc(sizeof(peer));
    DEBUG("Allocated new peer at %p.\n", new_peer);
    if (!new_peer)
    {
        fprintf(stderr, "ERROR: Could not allocate memory for new peer, exiting.\n");
        exit(1);
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
        exit(1);
    }

    bzero(new_peer->name, name_length + 1);

    memcpy(new_peer->name, packet_data_buffer->data + buffer_offset, name_length);
    buffer_offset += name_length;

    // Default values
    new_peer->connected = false;
    new_peer->heartbeat_timer = HEARTBEAT_TIME;
    DEBUG("Setting new_peer %s at %p is_new.\n", new_peer->name, new_peer);
    new_peer->is_new = true;
    new_peer->sock = -1;

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
        exit(1);
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

void send_failed(int sock, uint32_t code)
{
    // Create failed packet_header with a single uint32 to encode error code.
    packet_header failed = create_packet_header(MSG_FAILED, sizeof(uint32_t));

    data_buffer code_buffer = {
        .data = malloc(sizeof(uint32_t)),
        .length = sizeof(uint32_t)
    };

    if (!code_buffer.data)
    {
        printf("ERROR: Couldn't allocate memory for failed message. Exiting.\n");
        exit(1);
    }

    // Set error code
    memcpy(code_buffer.data, (char *)&code, sizeof(code));

    DEBUG("Sending failed packet to socket %d with code %d.\n", sock, code);

    send_data_packet(sock, &failed, &code_buffer);
}

void print_message(peer *peer, char *data_buffer, bool is_private)
{
    // Remove newline
    chomp(data_buffer);

    if (is_private)
        printf("[%s]: %s\n", peer->name, data_buffer);
    else
        printf("%s: %s\n", peer->name, data_buffer);

    fflush(stdout);
}

void parse_enter_req(peer_list_sock_tuple peer_and_sock, data_buffer *packet_data_buffer)
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
        // for client who sent entry request
        if (new_peer_index == 0
            && find_peer_by_name(peer_and_sock.peer_list, new_peer.peer))
        {
            printf("INFO: Name \"%s\" taken!\n", new_peer.peer->name);
            // TODO: Write defines for error codes sent
            send_failed(peer_and_sock.sock, 1);
            free(new_peer.peer->name);
            free(new_peer.peer);
            return;
        }

        // Check if peer already exists, only add non-existing peers
        if (!find_peer_by_name(peer_and_sock.peer_list, new_peer.peer))
        {
            // We know the socket from the first peer
            if (new_peer_index == 0)
            {
                new_peer.peer->sock = peer_and_sock.sock;
                new_peer.peer->connected = true;
            }

            printf("INFO: %s joined the chat.\n", new_peer.peer->name);
            list_add(&peer_and_sock.peer_list, new_peer.peer);

            new_peer_index++;
        }
        else
        {
            free(new_peer.peer);
        }

#ifdef DEBUGGING
        list_node *peer_print = peer_and_sock.peer_list;
        while (peer_print)
        {
            DEBUG("\nname:      %s\n"
                  "connected: %d\n"
                  "is_new:    %d\n",
                  peer_print->data->name,
                  peer_print->data->connected,
                  peer_print->data->is_new);

            peer_print = peer_print->next;
        }
        DEBUG("Peer list size: %d.\n", list_size(peer_and_sock.peer_list));
#endif
    }
}

void parse_new_users(peer_list_sock_tuple peer_and_sock, data_buffer *packet_data_buffer)
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

        // Check if peer already exists, only add non-existing peers
        if (!find_peer_by_name(peer_and_sock.peer_list, new_peer.peer))
        {
            printf("INFO: %s joined the chat.\n", new_peer.peer->name);
            list_add(&peer_and_sock.peer_list, new_peer.peer);

            new_peer_index++;
        }
        else
        {
            free(new_peer.peer);
        }

#ifdef DEBUGGING
        list_node *peer_print = peer_and_sock.peer_list;
        while (peer_print)
        {
            DEBUG("\nname:      %s\n"
                  "connected: %d\n"
                  "is_new:    %d\n",
                  peer_print->data->name,
                  peer_print->data->connected,
                  peer_print->data->is_new);

            peer_print = peer_print->next;
        }
        DEBUG("Peer list size: %d.\n", list_size(peer_and_sock.peer_list));
#endif
    }
}

void propagate_new_peers(peer_list_sock_tuple peer_and_sock)
{
    data_buffer request_buffer = create_enter_req_data(peer_and_sock.peer_list);

    packet_header new_user = create_packet_header(MSG_NEW_USERS, request_buffer.length);

    // Send recently added users to older users in list and set newUsers = oldusers
    list_node *peer = peer_and_sock.peer_list->next;
    while (peer)
    {
        if (!peer->data->is_new && peer->data->sock != peer_and_sock.sock)
        {
            DEBUG("Propagating peers to %s.\n", peer->data->name);
            send_data_packet(peer->data->sock, &new_user, &request_buffer);
        }

        peer = peer->next;
    }

    free(request_buffer.data);
}

void connect_to_new_peer(list_node *peer_list, peer *peer, packet_header connect_packet,
                         data_buffer *data_buffer, peer_and_max_fds_tuple peer_and_max_fds, bool use_sctp)
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
        peer->connected = true;
        // Add socket to master set
        FD_SET(sockfd, peer_and_max_fds.peer_fds);

        // Update max socket
        if (sockfd > *peer_and_max_fds.max_fd)
        {
            DEBUG("New socket fd larger than previous,\n"
                  "changing max_fd from %d to %d.\n", *peer_and_max_fds.max_fd, sockfd);
            *peer_and_max_fds.max_fd = sockfd;
        }
    }

    send_data_packet(peer->sock, &connect_packet, data_buffer);
    peer->is_new = false;
}

void connect_to_new_peers(list_node *peer_list, peer_and_max_fds_tuple peer_and_max_fds, bool use_sctp)
{
    // Create data buffer of ourselves
    peer us = *peer_list->data;
    data_buffer peer_connect_buffer = serialize_peer_data(&us);
    packet_header connect_packet = create_packet_header(MSG_CONNECT, peer_connect_buffer.length);

    // Send connect to all new peers
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

/**
 * handle_enter_req handles an enter request.
 * TODO: Write documentation on how the protocol works.
 */
void handle_enter_req(peer_list_sock_tuple peer_and_sock, data_buffer *packet_data_buffer,
                      peer_and_max_fds_tuple peer_and_max_fds, bool use_sctp)
{
    DEBUG("Handling enter request.\n");
    parse_enter_req(peer_and_sock, packet_data_buffer);
    propagate_new_peers(peer_and_sock);
    connect_to_new_peers(peer_and_sock.peer_list, peer_and_max_fds, use_sctp);
}

void handle_new_users(peer_list_sock_tuple peer_and_sock, data_buffer *packet_data_buffer,
                      peer_and_max_fds_tuple peer_and_max_fds, bool use_sctp)
{
    DEBUG("Handling new users.\n");
    parse_new_users(peer_and_sock, packet_data_buffer);
    connect_to_new_peers(peer_and_sock.peer_list, peer_and_max_fds, use_sctp);
}

void handle_connect(peer_list_sock_tuple peer_and_sock, data_buffer *packet_data_buffer)
{
    peer_tuple new_peer = deserialize_peer_data(packet_data_buffer);

    new_peer.peer->sock = peer_and_sock.sock;
    new_peer.peer->connected = true;
    new_peer.peer->is_new = false;
    new_peer.peer->heartbeat_timer = HEARTBEAT_TIME;

    if (!find_peer_by_name(peer_and_sock.peer_list, new_peer.peer))
    {
        list_add(&peer_and_sock.peer_list, new_peer.peer);
        printf("INFO: %s joined the chat.\n", new_peer.peer->name);
    }
}

void remove_peer_by_socket(peer_list_sock_tuple peer_and_sock)
{
    list_node *peer = peer_and_sock.peer_list;
    while (peer)
    {
        if (peer->data->sock == peer_and_sock.sock)
        {
            uint32_t peer_ip = peer->data->ip_addr;
            list_remove(&peer_and_sock.peer_list, peer_ip);
            break;
        }

        peer = peer->next;
    }
}

void handle_message(peer_list_sock_tuple peer_and_sock, data_buffer *packet_data_buffer, bool is_private)
{
    list_node *peer = peer_and_sock.peer_list;
    while (peer)
    {
        if (peer->data->sock == peer_and_sock.sock)
        {
            print_message(peer->data, packet_data_buffer->data, is_private);
        }

        peer = peer->next;
    }
}

void handle_disconnect(peer_list_sock_tuple peer_and_sock, fd_set *peer_fds)
{
    list_node *peer = find_peer_by_socket(peer_and_sock);
    if (peer)
    {
        printf("INFO: Disconnect received from \"%s\".\n", peer->data->name);

        // TODO: max_fd entsprechend anpassen
        FD_CLR(peer_and_sock.sock, peer_fds); // remove from master set
        remove_peer_by_socket(peer_and_sock);

        peer_and_sock.sock = -1;
    }
    else
    {
        printf("ERROR: No peer found for socket %d.\n", peer_and_sock.sock);
    }
}

void handle_failed(peer_list_sock_tuple peer_and_sock, data_buffer *packet_data_buffer, fd_set *peer_fds)
{
    printf("INFO: Failed received with code: %d\n", *((uint32_t *)packet_data_buffer->data));

    FD_CLR(peer_and_sock.sock, peer_fds); // remove from master set
    remove_peer_by_socket(peer_and_sock);

    peer_and_sock.sock = -1;
}

void handle_heartbeat(peer_list_sock_tuple peer_and_sock, bool use_sctp)
{
    // If SCTP is enabled, we don't need the heartbeat
    // since SCTP has its own heartbeat
    if (use_sctp)
        return;

    // Reset heartbeat of peer
    list_node *peer = peer_and_sock.peer_list;
    while (peer)
    {
        if (peer->data->sock == peer_and_sock.sock)
        {
            // Peer found -> Reset timer
            peer->data->heartbeat_timer = HEARTBEAT_TIME;
        }

        peer = peer->next;
    }
}

void parse_packet(peer_list_sock_tuple peer_and_sock, packet_header *incoming_packet,
                  data_buffer *packet_data_buffer, peer_and_max_fds_tuple peer_and_max_fds, bool use_sctp)
{
    switch (incoming_packet->type)
    {
    case MSG_NEW_USERS:
        handle_new_users(peer_and_sock, packet_data_buffer,
                         peer_and_max_fds, use_sctp);
        break;
    case MSG_ENTER_REQ:
        handle_enter_req(peer_and_sock, packet_data_buffer,
                         peer_and_max_fds, use_sctp);
        break;
    case MSG_FAILED:
        handle_failed(peer_and_sock, packet_data_buffer, peer_and_max_fds.peer_fds);
        break;
    case MSG_CONNECT:
        handle_connect(peer_and_sock, packet_data_buffer);
        break;
    case MSG_DISCONNECT:
        handle_disconnect(peer_and_sock, peer_and_max_fds.peer_fds);
        break;
    case MSG_MESSAGE:
        // TODO: Check length of message
        handle_message(peer_and_sock, packet_data_buffer, false);
        break;
    case MSG_PRIVATE:
        handle_message(peer_and_sock, packet_data_buffer, true);
        break;
    case MSG_HEARTBEAT:
        handle_heartbeat(peer_and_sock, use_sctp);
        break;
    default:
        break;
    }
}

void handle_packet(chat_application_context *ctx, int sock)
{
    pthread_mutex_lock(ctx->peer_mutex);

    peer_and_max_fds_tuple peer_and_max_fds = {
        .peer_fds = &ctx->peer_fds,
        .max_fd = &ctx->max_fd};

    peer_list_sock_tuple peer_and_sock = {
        .peer_list = ctx->peer_list,
        .sock = sock};

    // Read header of packet_header
    packet_header *incoming_packet = receive_packet_header(peer_and_sock, &peer_and_max_fds);

    DEBUG("Packet header with type %c, length %d bytes and version 0x%02x received.\n", 
        incoming_packet->type,
        incoming_packet->length,
        incoming_packet->version);

    if (incoming_packet)
    {
        // Read data section of packet_header
        data_buffer packet_data_buffer = {
            .data = malloc(incoming_packet->length),
            .length = incoming_packet->length};

        if (!packet_data_buffer.data)
        {
            fprintf(stderr, "ERROR: Could allocate memory for packet_header data buffer, exiting.\n");
            exit(1);
        }

        if (incoming_packet->length > 0)
        {
            DEBUG("Receiving %d bytes packet data from socket %d.\n", incoming_packet->length, sock);
            receive_from_socket(sock, packet_data_buffer.data, incoming_packet->length);
        }

        DEBUG("Parsing packet with type %c and version 0x%02x.\n",
            incoming_packet->type, incoming_packet->version);

        parse_packet((peer_list_sock_tuple){
                         .peer_list = ctx->peer_list,
                         .sock = sock},
                     incoming_packet, &packet_data_buffer, peer_and_max_fds, ctx->use_sctp);

        free(packet_data_buffer.data);
        free(incoming_packet);
    }

    pthread_mutex_unlock(ctx->peer_mutex);
}
