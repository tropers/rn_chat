#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <errno.h>

#include "receiver.h"
#include "helper.h"
#include "chat.h"

void send_failed(int socket)
{
    // Create failed packet
    packet failed = create_packet(
        PROTOCOL_VERSION,
        MSG_FAILED,
        1, // 1 single byte for the error code
        NULL);

    send_packet(socket, &failed);
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
            new_peer->socket = sock;
        }
        else
        {
            new_peer->socket = -1; // No socket from other participants known
        }
        new_peer->is_new = 1;
        new_peer->heartbeat_timer = HEARTBEAT_TIME;

        // Check if name of connecting client is already taken
        if (i == 0 && type == 'E')
        {
            // Search through list to see if entry already exists
            for (list_node *i = ctx->peer_list; i != NULL; i = i->next)
            {
                if (strcmp(i->data->name, new_peer->name) == 0)
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
    for (list_node *i = ctx->peer_list->next; i != NULL; i = i->next)
    {
        if (!(i->data->is_new) && i->data->socket != sock)
        {
            send_data_packet(i->data->socket, &new_user, new_user.data, req.length);
            i->data->is_new = 0;
        }
    }

    // Free data from enter request
    free(req.data);
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
    for (list_node *i = ctx->peer_list->next; i != NULL; i = i->next)
    {
        if (i->data->is_new)
        {
            // If not connected to peer yet, open connection
            if (i->data->socket < 0)
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
                address.sin_addr.s_addr = i->data->ip_addr;
                address.sin_port = htons(i->data->port); // Convert to network byteorder

                if (connect(sockfd, (struct sockaddr *)&address, sizeof(address)) < 0)
                {
                    fprintf(stderr, "ERROR: connect failed for new peer.\n");
                    close(sockfd);
                    FD_CLR(sockfd, &ctx->peer_fds);
                    sockfd = -1;
                    i->data->socket = -1;
                    return;
                }

                // Set socket to client
                i->data->socket = sockfd;
                // Add socket to master set
                FD_SET(sockfd, &ctx->peer_fds);

                // Update max socket
                if (sockfd > ctx->max_fd)
                {
                    ctx->max_fd = sockfd;
                }
            }

            send_data_packet(i->data->socket, &connect_packet, peer_connect_buffer, offset);
            i->data->is_new = 0;
        }
    }
}

void parse_enter_req(chat_application_context *ctx, int sock, int length, char type, BOOL use_sctp)
{
    receive_new_peer(ctx, sock, type, length);
    propagate_new_peer(ctx, sock);
    connect_to_new_peers(ctx);
}

void parse_connect(chat_application_context *ctx, int socket)
{
    char entry_header_buf[ENTRY_HEADER_LEN];

    peer *new_peer = malloc(sizeof(peer));
    int offset = 0;

    receive_from_socket(socket, entry_header_buf, ENTRY_HEADER_LEN);

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

    receive_from_socket(socket, name_buf, name_length);

    strcpy(new_peer->name, name_buf);

    new_peer->socket = socket;
    new_peer->connected = 1;
    new_peer->is_new = 0;
    new_peer->heartbeat_timer = HEARTBEAT_TIME;

    list_add(&ctx->peer_list, new_peer);

    printf("Connect received.\n");
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void remove_peer_by_socket(chat_application_context *ctx, int socket)
{
    for (list_node *peer = ctx->peer_list; peer != NULL; peer = peer->next)
    {
        if (peer->data->socket == socket)
        {
            uint32_t peer_ip = peer->data->ip_addr;
            list_remove(&ctx->peer_list, peer_ip);
        }
    }
}

void recv_packet(chat_application_context *ctx, int socket, BOOL use_sctp)
{
    pthread_mutex_lock(ctx->peer_mutex);

    int nbytes;
    char header_buf[HEADER_LEN];
    // char *data_buf;

    // Handle data from client
    if ((nbytes = recv(socket, header_buf, HEADER_LEN, 0)) <= 0)
    {
        // If there's an error, the connection is reset
        if (nbytes == 0)
        {
            // Connection is closed
            printf("INFO: Socket %d hung up\n", socket);
        }
        else
        {
            fprintf(stderr, "ERROR: Error in recv()\n");
        }

        // Remove client from list if error in connection has occured
        for (list_node *i = ctx->peer_list->next; i != NULL; i = i->next)
        {
            if (i->data->socket == socket)
            {
                list_remove(&ctx->peer_list, i->data->ip_addr);
            }
        }

        close(socket);                  // bye!
        FD_CLR(socket, &ctx->peer_fds); // remove from master set
        socket = -1;
    }
    else
    {
        // Data received from client
        packet incoming_packet;
        memcpy(&incoming_packet, header_buf, HEADER_LEN);

        char data_buf[incoming_packet.length];

        switch (incoming_packet.type)
        {
        case MSG_NEW_USERS:
        case MSG_ENTER_REQ:
            parse_enter_req(ctx, socket, incoming_packet.length, incoming_packet.type, use_sctp);
            break;
        case MSG_FAILED:
            receive_from_socket(socket, data_buf, sizeof(int32_t));
            printf("Failed received with code: %d\n", (int)*data_buf);

            remove_peer_by_socket(ctx, socket);

            close(socket);
            socket = -1;
            FD_CLR(socket, &ctx->peer_fds); // remove from master set
            // free(data_buf);
            break;
        case MSG_CONNECT:
            parse_connect(ctx, socket);
            break;
        case MSG_DISCONNECT:
            receive_from_socket(socket, data_buf, incoming_packet.length);
            printf("Disconnect received.\n");

            remove_peer_by_socket(ctx, socket);

            // TODO: max_fd entsprechend anpassen
            close(socket);
            socket = -1;
            FD_CLR(socket, &ctx->peer_fds); // remove from master set
            break;
        case MSG_MESSAGE:
            receive_from_socket(socket, data_buf, incoming_packet.length);

            for (list_node *peer = ctx->peer_list; peer != NULL; peer = peer->next)
            {
                if (peer->data->socket == socket)
                {
                    // Remove newline
                    chomp(data_buf);
                    printf("%s: %s\n", peer->data->name, data_buf);
                    fflush(stdout);
                }
            }
            break;
        case MSG_PRIVATE:
            receive_from_socket(socket, data_buf, incoming_packet.length);

            for (list_node *peer = ctx->peer_list; peer != NULL; peer = peer->next)
            {
                if (peer->data->socket == socket)
                {
                    // Remove newline at the end of message text
                    chomp(data_buf);
                    printf("[%s]: %s\n", peer->data->name, data_buf);
                    fflush(stdout);
                }
            }
            break;
        case MSG_HEARTBEAT:
            // If SCTP is enabled, we don't need the heartbeat
            // since SCTP has its own heartbeat
            if (use_sctp)
                return;

            // Reset heartbeat of peer
            for (list_node *peer = ctx->peer_list; peer != NULL; peer = peer->next)
            {
                if (peer->data->socket != socket)
                {
                    continue;
                }
                else
                {
                    // Peer found -> Reset timer
                    peer->data->heartbeat_timer = HEARTBEAT_TIME;
                }
            }
            break;
        default:
            break;
        }
    }

    pthread_mutex_unlock(ctx->peer_mutex);
}

void handle_new_connection(chat_application_context *ctx, int listener_fd)
{
    struct sockaddr_storage remoteaddr; // Client Address
    socklen_t addrlen;
    char remoteIP[INET6_ADDRSTRLEN];

    // Handle connections
    addrlen = sizeof(remoteaddr);
    int new_sock = accept(listener_fd, (struct sockaddr *)&remoteaddr, &addrlen);

    if (new_sock == -1)
    {
        fprintf(stderr, "ERROR: Error in accept()\n");
        exit(4);
    }
    else
    {
        FD_SET(new_sock, &ctx->peer_fds); // Add to master set

        if (new_sock > ctx->max_fd)
        { // Check if new socket is bigger than maximum socket
            ctx->max_fd = new_sock;
        }

        printf("INFO: New connection from %s on socket %d\n",
               inet_ntop(remoteaddr.ss_family,
                         get_in_addr((struct sockaddr *)&remoteaddr),
                         remoteIP, INET6_ADDRSTRLEN),
               new_sock);
    }
}

int setup_listener(chat_application_context *ctx, BOOL use_sctp, int sctp_hbinterval)
{
    struct sockaddr_in serv_addr;

    // Create new socket
    int listener_fd = socket(AF_INET, SOCK_STREAM, use_sctp ? IPPROTO_SCTP : IPPROTO_TCP);
    if (listener_fd < 0)
    {
        fprintf(stderr, "ERROR: Coulnd't create socket.\n");
        return -1;
    }

    // Set socket options to reuse socket
    int yes = 1;
    setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    // Handling SCTP
    if (use_sctp)
    {
        // Configure heartbeat
        struct sctp_paddrparams paddrparams;
        paddrparams.spp_flags = SPP_HB_ENABLE;
        paddrparams.spp_hbinterval = sctp_hbinterval * MSECS_IN_1SEC;
        paddrparams.spp_pathmaxrxt = 2;

        // Set socket options to use the heartbeat feature
        setsockopt(listener_fd, SOL_SCTP, SCTP_PEER_ADDR_PARAMS, &paddrparams, sizeof(paddrparams));
    }

    // Setup listener
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(PORT); // Convert from host to network byteorder

    if (bind(listener_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        fprintf(stderr, "ERROR: Couldn't bind socket.\n");
        return -1;
    }

    printf("Listening on port %d...\n", PORT);
    fflush(stdout);

    listen(listener_fd, 5);
    FD_SET(listener_fd, &ctx->peer_fds);

    ctx->max_fd = listener_fd; // Set max fd to listener fd

    return listener_fd;
}

void *receiver_thread_func(void *args)
{
    receiver_thread_args thread_args = *((receiver_thread_args *)args);
    chat_application_context *ctx = thread_args.ctx;

    FD_ZERO(&ctx->peer_fds);
    FD_ZERO(&ctx->read_fds);

    int listener_fd = setup_listener(ctx, ctx->use_sctp, thread_args.sctp_hbinterval);

    struct timeval timeout = {0, 50000};

    while (TRUE)
    {
        ctx->read_fds = ctx->peer_fds; // Copy
        int rv_select = select(ctx->max_fd + 1, &ctx->read_fds, NULL, NULL, &timeout);
        if (rv_select == 0)
        {
            // Timeout, continue
            timeout.tv_sec = 0;
            timeout.tv_usec = 50000;
            continue;
        }
        else if (rv_select == -1)
        {
            fprintf(stderr, "ERROR: select() failed with errno: %d!\n", errno);
            continue;
        }

        // Check current connections for data to be read
        for (int i = 0; i <= ctx->max_fd; i++)
        {
            if (FD_ISSET(i, &ctx->read_fds))
            {
                if (i == listener_fd)
                {
                    handle_new_connection(ctx, listener_fd);
                }
                else
                {
                    // Receive and handle message
                    recv_packet(ctx, i, ctx->use_sctp);
                }
            }
        }
    }
}
