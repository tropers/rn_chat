/**
 * chat_handler.c
 * 
 * Contains function definitions of the chat application
 */

#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h> 
#include <netinet/in.h> 
#include <netinet/sctp.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>
#include <strings.h>
#include <errno.h>

#include "chat_handler.h"
#include "list.h"

//================================================
// CHAT HANDLER VARS
//================================================

pthread_t heartbeat_thread;
pthread_t receiver_thread;
pthread_mutex_t peer_mutex;
list_node *peer_list = NULL;

char user_name[INPUT_BUFFER_LEN];

fd_set peer_fds;
fd_set read_fds;
int max_fd;

//================================================
// HELPER FUNCTIONS
//================================================

void chomp(char *s)
{
    while (*s && *s != '\n' && *s != '\r')
        s++;

    *s = 0;
}

//================================================
// CHAT HANDLER FUNCTIONS
//================================================

void parse_enter_req(int sock, int length, char type, BOOL use_sctp)
{
    int offset = 0;
    char *entry_header_buf;

    for (int i = 0; i < length; i++)
    {
        offset = 0;
        peer *new_peer = malloc(sizeof(peer));
        entry_header_buf = malloc(ENTRY_HEADER_LEN);
        //receive user_header
        if (recv(sock, entry_header_buf, ENTRY_HEADER_LEN, 0) <= 0)
        {
            fprintf(stderr, "ERROR: Receiving data.\n");
            exit(4);
        }

        new_peer->ip_addr = *((uint32_t *)(entry_header_buf + offset));
        offset += IP_ADDR_LEN;

        new_peer->port = *((uint16_t *)(entry_header_buf + offset));
        offset += PORT_LEN;

        int name_length = *((uint16_t *)(entry_header_buf + offset));
        offset += NAME_LEN_LEN;

        // Receive name
        new_peer->name = malloc(name_length + 1);
        bzero(new_peer->name, name_length + 1);
        if (recv(sock, new_peer->name, name_length, 0) <= 0)
        {
            fprintf(stderr, "ERROR: Receiving data.\n");
            exit(4);
        }

        //initialize new peer
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
        new_peer->isNew = 1;
        new_peer->heartbeatTimer = HEARTBEAT_TIME;

        // Check if name of connecting client is already taken
        if (i == 0 && type == 'E')
        {
            // Search through list to see if entry already exists
            pthread_mutex_lock(&peer_mutex);
            for (list_node *i = peer_list; i != NULL; i = i->next)
            {
                printf("listname:\t\t%s\npeername:\t\t%s\n", i->data->name, new_peer->name);

                if (strcmp(i->data->name, new_peer->name) == 0)
                {
                    printf("INFO: Name taken!\n");
                    pthread_mutex_unlock(&peer_mutex);
                    send_failed(sock);
                    return;
                }
            }

            pthread_mutex_unlock(&peer_mutex);
        }

        pthread_mutex_lock(&peer_mutex);
        list_add(&peer_list, new_peer);
        pthread_mutex_unlock(&peer_mutex);
    }

    char *buffer = NULL;
    int packet_len = 0;
    create_enter_req_data(&buffer, &packet_len);

    packet newUser;
    newUser.data = buffer;
    pthread_mutex_lock(&peer_mutex);
    newUser.length = list_size(peer_list);
    pthread_mutex_unlock(&peer_mutex);
    newUser.type = MSG_NEW_USERS;
    newUser.version = PROTOCOL_VERSION;

    //send recently added users to older users in list and set newUsers = oldusers
    pthread_mutex_lock(&peer_mutex);
    for (list_node *i = peer_list->next; i != NULL; i = i->next)
    {
        if (!(i->data->isNew) && i->data->socket != sock)
        {
            send(i->data->socket, &newUser, HEADER_LEN, 0);
            send(i->data->socket, newUser.data, packet_len, 0);
            i->data->isNew = 0;
        }
    }
    pthread_mutex_unlock(&peer_mutex);

    // Send connect to new peer
    packet connect_packet;
    connect_packet.type = MSG_CONNECT;
    connect_packet.version = PROTOCOL_VERSION;
    connect_packet.length = 0;

    char *peer_connect_buffer = malloc(INPUT_BUFFER_LEN * 4);

    offset = 0;

    // Copy IP-Address to packet-data
    memcpy(peer_connect_buffer + offset, (char *)&peer_list->data->ip_addr, IP_ADDR_LEN);
    offset += IP_ADDR_LEN;

    // Copy port
    uint16_t port = PORT;
    memcpy(peer_connect_buffer + offset, (char *)&port, PORT_LEN);
    offset += PORT_LEN;

    // Copy length of name
    uint16_t name_len = (uint16_t)strlen(peer_list->data->name) + 1; // + 1 for null-terminator
    memcpy(peer_connect_buffer + offset, (char *)&name_len, NAME_LEN_LEN);
    offset += NAME_LEN_LEN;

    // Copy name
    memcpy(peer_connect_buffer + offset, peer_list->data->name, (int)name_len);
    offset += (int)name_len;

    // Send connect to all new peers
    // Send data
    for (list_node *i = peer_list->next; i != NULL; i = i->next)
    {
        if (i->data->isNew)
        {
            // If not connected to peer yet, open connection
            if (i->data->socket < 0)
            {
                //socket-file destriptor
                struct sockaddr_in address;
                int sockfd = socket(AF_INET, SOCK_STREAM, use_sctp ? IPPROTO_SCTP : IPPROTO_TCP);
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
                    FD_CLR(sockfd, &peer_fds);
                    sockfd = -1;
                    i->data->socket = -1;
                    return;
                }

                // Set socket to client
                i->data->socket = sockfd;
                // Add socket to master set
                FD_SET(sockfd, &peer_fds);

                // Update max socket
                if (sockfd > max_fd)
                {
                    max_fd = sockfd;
                }
            }

            send(i->data->socket, (char *)&connect_packet, HEADER_LEN, 0);
            send(i->data->socket, peer_connect_buffer, offset, 0);

            i->data->isNew = 0;
        }
    }

    // Delete packet buffers
    free(buffer);
    free(peer_connect_buffer);
}

// Returns the data created for the enter request package
void create_enter_req_data(char **packet_data, int *packet_len)
{
    int offset = 0;

    // DEBUGGING
    // printf("%d \t %d\n", list_size(peer_list), list_size(peer_list) * sizeof(list_node) * 2);

    pthread_mutex_lock(&peer_mutex);
    char *data = malloc(list_size(peer_list) * sizeof(list_node) * 1024); // * 256 to compensate for string names
    pthread_mutex_unlock(&peer_mutex);

    if (data == NULL)
    {
        fprintf(stderr, "ERROR: Counldn't allocate packet data.\n");
    }

    // Iterate over peers
    pthread_mutex_lock(&peer_mutex);
    for (list_node *peer = peer_list; peer != NULL; peer = peer->next)
    {
        // Copy IP-Address to packet-data
        memcpy(data + offset, (char *)&peer->data->ip_addr, IP_ADDR_LEN);
        offset += IP_ADDR_LEN;

        // Copy port
        // uint16_t port = PORT;
        uint16_t port = peer->data->port;
        memcpy(data + offset, (char *)&port, PORT_LEN);
        offset += PORT_LEN;

        // Copy length of name
        uint16_t name_len = (uint16_t)strlen(peer->data->name) + 1;
        memcpy(data + offset, (char *)&name_len, NAME_LEN_LEN);
        offset += NAME_LEN_LEN;

        // Copy name
        memcpy(data + offset, peer->data->name, (int)name_len);
        offset += (int)name_len;
    }
    pthread_mutex_unlock(&peer_mutex);

    // HEX VIEW OF PACKET FOR DEBUGGING
    // for (int i = 0; i < offset; ++i) {
    //     if (i % 16 == 0) {
    //         printf("\n");
    //     }

    //     printf("%02X ", data[i]);
    //     fflush(stdout);
    // }

    // Return pointer to buffer
    *packet_data = data;
    // Return length of data
    *packet_len = offset;
}

void parse_connect(int socket)
{
    char *entry_header_buf = malloc(ENTRY_HEADER_LEN);
    peer *new_peer = malloc(sizeof(peer));
    int offset = 0;

    if (recv(socket, entry_header_buf, ENTRY_HEADER_LEN, 0) <= 0)
    {
        fprintf(stderr, "ERROR: Receiving data.\n");
        exit(4);
    }

    new_peer->ip_addr = *((uint32_t *)(entry_header_buf + offset));
    offset += IP_ADDR_LEN;

    new_peer->port = *((uint16_t *)(entry_header_buf + offset));
    offset += PORT_LEN;

    int name_length = *((uint16_t *)(entry_header_buf + offset));
    offset += NAME_LEN_LEN;

    // DEBUGGING
    printf("name_len: %d\n", name_length);

    // Receive name
    new_peer->name = malloc(name_length + 1);
    bzero(new_peer->name, name_length + 1);

    char name_buf[name_length + 1];
    bzero(name_buf, name_length + 1);

    if (recv(socket, name_buf, name_length + 1, 0) <= 0)
    {
        fprintf(stderr, "ERROR: Receiving data.\n");
        exit(4);
    }

    strcpy(new_peer->name, name_buf);

    // DEBUGGING
    char *i = new_peer->name;
    while (*i != 0)
    {
        printf("%c", *i);
        ++i;
    }
    printf("\n");

    new_peer->socket = socket;
    new_peer->connected = 1;
    new_peer->isNew = 0;
    new_peer->heartbeatTimer = HEARTBEAT_TIME;

    // DEBUGGING
    printf("peer_name: %ld\t%s\n", (long int)new_peer->name, new_peer->name);

    pthread_mutex_lock(&peer_mutex);
    list_add(&peer_list, new_peer);
    pthread_mutex_unlock(&peer_mutex);
    free(entry_header_buf);

    // DEBUGGING
    printf("Printing list: \n");
    struct in_addr addr;
    pthread_mutex_lock(&peer_mutex);
    for (list_node *i = peer_list; i != NULL; i = i->next)
    {
        char ip_buf[INET_ADDRSTRLEN];
        addr.s_addr = i->data->ip_addr;
        printf("name:\t%s\nip:\t%s\n", i->data->name, inet_ntop(AF_INET, &addr, ip_buf, INET_ADDRSTRLEN));
    }
    pthread_mutex_unlock(&peer_mutex);

    printf("Connect received.\n");
}

void send_disconnect()
{
    // Create disconnect packet
    packet reset;
    reset.length = 0;
    reset.type = MSG_DISCONNECT;
    reset.version = PROTOCOL_VERSION;

    // Create buffer for packet
    char *buffer = malloc(sizeof(packet));
    memcpy(buffer, &reset, HEADER_LEN);

    pthread_mutex_lock(&peer_mutex);
    for (list_node *peer = peer_list->next; peer != NULL; peer = peer->next)
    {
        // Send disconnect to everyone
        if (peer->data->connected)
        {
            send(peer->data->socket, buffer, HEADER_LEN, 0);
        }

        // Close connection
        close(peer->data->socket);
        FD_CLR(peer->data->socket, &peer_fds);
        peer->data->socket = -1;
    }
    pthread_mutex_unlock(&peer_mutex);
}

void send_message(char *message, BOOL private, char *user_name)
{
    int msg_length = strlen(message) + 1;
    int aligned_length = msg_length;

    // Remove newline from message
    chomp(message);

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
    packet message_packet;
    message_packet.length = aligned_length; // Length in 4 byte blocks
    message_packet.type = MSG_MESSAGE;
    message_packet.version = PROTOCOL_VERSION;

    // Create buffer for packet
    char *buffer = malloc(sizeof(packet) + aligned_length);
    memcpy(buffer, &message_packet, HEADER_LEN);

    // Fill message blocks with zeros
    bzero(buffer + HEADER_LEN, aligned_length);

    // Copy actual message
    memcpy(buffer + HEADER_LEN, message, msg_length);

    pthread_mutex_lock(&peer_mutex);
    for (list_node *peer = peer_list->next; peer != NULL; peer = peer->next) //uns selbst als head überspringen und message nur an andere schicken
    {
        // Send message to everyone
        if (peer->data->connected)
        {
            if (private)
            {
                message_packet.type = MSG_PRIVATE;
                memcpy(buffer, &message_packet, HEADER_LEN);

                if (strcmp(peer->data->name, user_name) == 0)
                {
                    // Send header
                    send(peer->data->socket, buffer, HEADER_LEN, 0);

                    // Send message blocks
                    send(peer->data->socket, buffer + HEADER_LEN, aligned_length, 0);
                }
            }
            else
            {
                // Send header
                send(peer->data->socket, buffer, HEADER_LEN, 0);

                // Send message blocks
                send(peer->data->socket, buffer + HEADER_LEN, aligned_length, 0);
            }
        }
    }
    pthread_mutex_unlock(&peer_mutex);

    // Free the message buffer
    free(buffer);
}

void send_failed(int socket)
{
    // Create failed packet
    packet failed;
    failed.length = 1; // 1 single byte for the error code
    failed.type = MSG_FAILED;
    failed.version = PROTOCOL_VERSION;

    // Create buffer for packet
    char *buffer = malloc(sizeof(packet));
    memcpy(buffer, &failed, HEADER_LEN);

    // send failed package to specified socket
    send(socket, buffer, HEADER_LEN, 0);
    // free allocated memory
    free(buffer);
}

// Connects to a client / client-network
int connect_to_peer(uint32_t destination_ip, uint16_t destination_port, BOOL use_sctp)
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
        FD_CLR(sockfd, &peer_fds);
        sockfd = -1;
        return 0;
    }

    // Create enter request packet
    char *data = NULL;
    int packet_len = 0;
    create_enter_req_data(&data, &packet_len);

    // Add socket ot master set
    FD_SET(sockfd, &peer_fds);

    packet enter_req;

    enter_req.data = data;
    pthread_mutex_lock(&peer_mutex);
    enter_req.length = list_size(peer_list);
    pthread_mutex_unlock(&peer_mutex);
    enter_req.type = MSG_ENTER_REQ;
    enter_req.version = PROTOCOL_VERSION;

    send(sockfd, &enter_req, HEADER_LEN, 0);
    send(sockfd, enter_req.data, packet_len, 0);

    // Delete packet buffer
    free(data);

    // Set maximum socket to new socket if new socket is bigger
    if (sockfd > max_fd)
    {
        max_fd = sockfd;
    }

    return sockfd;
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

void recv_packet(int socket, BOOL use_sctp)
{
    int nbytes;
    char header_buf[HEADER_LEN];
    char *data_buf;

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
        pthread_mutex_lock(&peer_mutex);
        for (list_node *i = peer_list->next; i != NULL; i = i->next)
        {
            if (i->data->socket == socket)
            {
                list_remove(&peer_list, i->data->ip_addr);
            }
        }
        pthread_mutex_unlock(&peer_mutex);

        close(socket);             // bye!
        FD_CLR(socket, &peer_fds); // remove from master set
        socket = -1;
    }
    else
    {
        // Data received from client
        packet incoming_packet;
        memcpy(&incoming_packet, header_buf, HEADER_LEN);

        data_buf = malloc(incoming_packet.length);

        switch (incoming_packet.type)
        {
        case MSG_NEW_USERS:
        case MSG_ENTER_REQ:
            parse_enter_req(socket, incoming_packet.length, incoming_packet.type, use_sctp);
            break;
        case MSG_FAILED:
            if (recv(socket, data_buf, sizeof(int32_t), 0) < 0)
            {
                fprintf(stderr, "ERROR: Receiving data.\n");
                exit(4);
            }
            printf("Failed received with code: %d\n", (int)*data_buf);

            //remove from list
            pthread_mutex_lock(&peer_mutex);
            for (list_node *peer = peer_list; peer != NULL; peer = peer->next)
            {
                if (peer->data->socket == socket)
                {
                    uint32_t peer_ip = peer->data->ip_addr;
                    list_remove(&peer_list, peer_ip);
                }
            }
            pthread_mutex_unlock(&peer_mutex);

            close(socket);
            socket = -1;
            FD_CLR(socket, &peer_fds); // remove from master set
            free(data_buf);
            break;
        case MSG_CONNECT:
            parse_connect(socket);
            break;
        case MSG_DISCONNECT:
            if (recv(socket, data_buf, incoming_packet.length, 0) < 0)
            {
                fprintf(stderr, "ERROR: Receiving data.\n");
                exit(4);
            }
            printf("Disconnect received.\n");

            pthread_mutex_lock(&peer_mutex);
            for (list_node *peer = peer_list; peer != NULL; peer = peer->next)
            {
                if (peer->data->socket == socket)
                {
                    uint32_t peer_ip = peer->data->ip_addr;
                    list_remove(&peer_list, peer_ip);
                }
            }
            pthread_mutex_unlock(&peer_mutex);

            //max_fd entsprechend anpassen ;
            close(socket);
            socket = -1;
            FD_CLR(socket, &peer_fds); // remove from master set
            break;
        case MSG_MESSAGE:
            if (recv(socket, data_buf, incoming_packet.length, 0) < 0)
            {
                fprintf(stderr, "ERROR: Receiving data.\n");
                exit(4);
            }

            pthread_mutex_lock(&peer_mutex);
            for (list_node *peer = peer_list; peer != NULL; peer = peer->next)
            {
                if (peer->data->socket == socket)
                {
                    // Remove newline
                    chomp(data_buf);
                    printf("%s: %s\n", peer->data->name, data_buf);
                    fflush(stdout);
                }
            }
            pthread_mutex_unlock(&peer_mutex);
            break;
        case MSG_PRIVATE:
            if (recv(socket, data_buf, incoming_packet.length, 0) < 0)
            {
                fprintf(stderr, "ERROR: Receiving data.\n");
                exit(4);
            }

            pthread_mutex_lock(&peer_mutex);
            for (list_node *peer = peer_list; peer != NULL; peer = peer->next)
            {
                if (peer->data->socket == socket)
                {
                    // Remove newline
                    chomp(data_buf);
                    printf("[%s]: %s\n", peer->data->name, data_buf);
                    fflush(stdout);
                }
            }
            pthread_mutex_unlock(&peer_mutex);
            break;
        case MSG_HEARTBEAT:
            // If SCTP is enabled, we don't need the heartbeat
            // since SCTP has its own heartbeat
            if (use_sctp) return;

            // Reset heartbeat of peer
            pthread_mutex_lock(&peer_mutex);
            for (list_node *peer = peer_list; peer != NULL; peer = peer->next)
            {
                if (peer->data->socket != socket)
                {
                    continue;
                }
                else
                {
                    //peer gefunden timer reset
                    peer->data->heartbeatTimer = HEARTBEAT_TIME;
                    printf("Heartbeat updated for %d\n", socket);
                }
            }
            pthread_mutex_unlock(&peer_mutex);
            break;
        default:
            break;
        }
    }
}

void *receiver_thread_func(void *args)
{
    FD_ZERO(&peer_fds);
    FD_ZERO(&read_fds);

    receiver_thread_args sctp_args = *((receiver_thread_args *)args);

    int listener_fd, new_sock;
    struct sockaddr_in serv_addr;

    struct sockaddr_storage remoteaddr; // Client Address

    socklen_t addrlen;
    char remoteIP[INET6_ADDRSTRLEN];

    // Create new socket
    listener_fd = socket(AF_INET, SOCK_STREAM, sctp_args.use_sctp ? IPPROTO_SCTP : IPPROTO_TCP);
    if (listener_fd < 0)
    {
        fprintf(stderr, "ERROR: Coulnd't create socket.\n");
        return NULL;
    }

    // Set socket options to reuse socket
    int yes = 1;
    setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    // Handling SCTP
    if (sctp_args.use_sctp)
    {
        // Configure heartbeat
        struct sctp_paddrparams paddrparams;
        paddrparams.spp_flags = SPP_HB_ENABLE;
        paddrparams.spp_hbinterval = sctp_args.sctp_hbinterval * MSECS_IN_1SEC;
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
        return NULL;
    }

    printf("Listening on port %d...\n", PORT);
    fflush(stdout);

    listen(listener_fd, 5);
    FD_SET(listener_fd, &peer_fds);

    max_fd = listener_fd; // Set max fd to listener fd

    struct timeval timeout = {0, 50000};

    while (1)
    {
        read_fds = peer_fds; // Copy
        int rv_select = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
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
        for (int i = 0; i <= max_fd; i++)
        {
            if (FD_ISSET(i, &read_fds))
            {
                if (i == listener_fd)
                {
                    // Handle connections
                    addrlen = sizeof(remoteaddr);
                    new_sock = accept(listener_fd, (struct sockaddr *)&remoteaddr, &addrlen);

                    if (new_sock == -1)
                    {
                        fprintf(stderr, "ERROR: Error in accept()\n");
                        exit(4);
                    }
                    else
                    {
                        FD_SET(new_sock, &peer_fds); // Add to master set
                        if (new_sock > max_fd)
                        { // Check if new socket is bigger than maximum socket
                            max_fd = new_sock;
                        }

                        printf("INFO: New connection from %s on socket %d\n",
                               inet_ntop(remoteaddr.ss_family,
                                         get_in_addr((struct sockaddr *)&remoteaddr),
                                         remoteIP, INET6_ADDRSTRLEN),
                               new_sock);
                    }
                }
                else
                {
                    // Receive and handle message
                    recv_packet(i, sctp_args.use_sctp);
                }
            }
        }
    }
}

void *heartbeat_thread_func()
{
    time_t baseTime, newTime, oldTime;

    // Create heartbeat packet
    packet heartbeat;
    heartbeat.length = 0;
    heartbeat.type = MSG_HEARTBEAT;
    heartbeat.version = PROTOCOL_VERSION;

    // allocate buffer for heartbeat packet
    char *buffer = malloc(sizeof(packet));
    memcpy(buffer, &heartbeat, HEADER_LEN);

    baseTime = time(0);
    oldTime = time(0);
    while (1)
    {
        sleep(0.5);
        newTime = time(0);
        double totalDiff = difftime(newTime, baseTime);
        double currentDiff = difftime(newTime, oldTime);
        oldTime = newTime;
        if (totalDiff >= 10)
        { // 10 s um heartbeats senden
            baseTime = time(0);

            pthread_mutex_lock(&peer_mutex);
            for (list_node *peer = peer_list->next; peer != NULL; peer = peer->next) //bei next starten um sich selbst zu überspringen
            {
                // Send heartbeat to everyone
                if (peer->data->connected)
                {
                    send(peer->data->socket, buffer, HEADER_LEN, 0);
                }
            }
            pthread_mutex_unlock(&peer_mutex);
        }

        // calculate new Timer for peers
        pthread_mutex_lock(&peer_mutex);
        for (list_node *peer = peer_list->next; peer != NULL; peer = peer->next)
        {
            peer->data->heartbeatTimer -= currentDiff;
            if (peer->data->heartbeatTimer <= 0)
            {
                //Time's up, remove current peer
                char *ip_buffer = malloc(INET_ADDRSTRLEN);
                struct in_addr addr;
                addr.s_addr = peer->data->ip_addr;
                inet_ntop(AF_INET, &addr, ip_buffer, INET_ADDRSTRLEN);
                fprintf(stderr, "INFO: Heartbeat for %s is up! Closing connection.\n", ip_buffer);

                close(peer->data->socket);
                FD_CLR(peer->data->socket, &peer_fds);
                peer->data->socket = -1;
                
                list_remove(&peer_list, peer->data->ip_addr);
                
                free(ip_buffer);
                ip_buffer = 0;
            }
        }
        pthread_mutex_unlock(&peer_mutex);
    }
}

/* Initializes the chat handler and runs in infinite loop */
void handle(BOOL use_sctp, int sctp_hbinterval)
{
    char buffer[INPUT_BUFFER_LEN];

    printf("################################################\n");
    printf("#       SUPER AWESOME CHAT CLIENT SOFTWARE     #\n");
    printf("#                       %s                   #\n", CHAT_VERSION);
    printf("################################################\n");

    // Initialize list and mutex
    printf("Initializing peer list...\n");
    peer_list = list_new();

    // Retreive username
    printf("Please enter username: ");
    fgets(user_name, INPUT_BUFFER_LEN, stdin);
    chomp(user_name);

    peer *user = malloc(sizeof(peer));

    // Retrieve IP address
    printf("Please enter your IP-address: ");
    fgets(buffer, INPUT_BUFFER_LEN, stdin);
    chomp(buffer);

    // Retrieve port
    // TODO

    inet_pton(AF_INET, buffer, &(user->ip_addr));
    user->name = user_name;
    user->port = PORT;
    user->connected = 1;
    user->isNew = 0;

    // Add self to list
    list_add(&peer_list, user);

    printf("Initializing peer list mutex...\n");
    pthread_mutex_init(&peer_mutex, NULL);

    // Start receiver thread
    printf("Starting receiver thread...\n");
    // Pass arguments to thread
    receiver_thread_args args = {use_sctp, sctp_hbinterval};
    pthread_create(&receiver_thread, NULL, receiver_thread_func, &args);

    // Start heartbeat thread
    if (!use_sctp)
    {
        printf("Starting heartbeat thread...\n");
        pthread_create(&heartbeat_thread, NULL, heartbeat_thread_func, NULL);
    }

    // Main loop for grabbing keyboard input
    while (1)
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

            if (connect_to_peer(ip_addr, port, use_sctp))
            {
                printf("Connected!\n");
            }
        }
        else if (strcmp(splitstr, "/list") == 0 || strcmp(splitstr, "/list\n") == 0)
        {
            // Show list
            printf("current peers:\n");
            pthread_mutex_lock(&peer_mutex);
            for (list_node *p = peer_list; p != NULL; p = p->next)
            {
                struct in_addr addr = {.s_addr = p->data->ip_addr};
                char ip_buf[INET_ADDRSTRLEN];
                char port_buf[PORT_LEN + 1];
                sprintf(port_buf, "%d", p->data->port);

                printf("%s:\n", p->data->name);
                printf("  address: %s:%s\n\n", inet_ntop(AF_INET, &addr, ip_buf, INET_ADDRSTRLEN), port_buf);
            }
            pthread_mutex_unlock(&peer_mutex);
        }
        else if (strcmp(splitstr, "/quit") == 0 || strcmp(splitstr, "/quit\n") == 0)
        {
            send_disconnect();
            list_free(peer_list);
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
            // char *user_name = malloc(INPUT_BUFFER_LEN);
            char user_name[INPUT_BUFFER_LEN] = {0};
            strcpy(user_name, splitstr);

            // char *message = malloc(strlen(buffer));
            char message[strlen(buffer)];
            bzero(message, strlen(buffer));

            splitstr = strtok(NULL, " ");
            while (splitstr != NULL)
            {
                strcat(message, splitstr);
                strcat(message, " ");

                splitstr = strtok(NULL, " ");
            }

            send_message(message, 1, user_name);
        }
        else if (splitstr[0] == '/')
        {
            // Ignore commands (no sending messages by accident)
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

            send_message(message, 0, NULL);
        }
    }

    pthread_join(receiver_thread, NULL);
}
