#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <errno.h>

#include "receiver.h"
#include "ECNDMFHP.h"
#include "helper.h"
#include "chat.h"
#include "debug.h"

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void handle_new_connection(chat_application_context *ctx, int listener_fd)
{
    struct sockaddr_storage remote_address; // Client Address
    socklen_t address_length;
    char remote_ip[INET6_ADDRSTRLEN];

    // Handle connections
    address_length = sizeof(remote_address);
    int new_sock = accept(listener_fd, (struct sockaddr *)&remote_address, &address_length);

    if (new_sock == -1)
    {
        fprintf(stderr, "ERROR: accept returned with %d.\n", new_sock);
        exit(4);
    }
    else
    {
        FD_SET(new_sock, &ctx->peer_fds); // Add to master set

        if (new_sock > ctx->max_fd)
        {
            // Check if new socket is bigger than maximum socket
            DEBUG("New socket fd larger than previous,\n"
                  "changing max_fd from %d to %d.\n", ctx->max_fd, new_sock);
            ctx->max_fd = new_sock;
        }

        printf("INFO: New connection from %s on socket %d.\n",
               inet_ntop(remote_address.ss_family,
                         get_in_addr((struct sockaddr *)&remote_address),
                         remote_ip, INET6_ADDRSTRLEN),
               new_sock);
    }
}

int setup_listener(chat_application_context *ctx, bool use_sctp, int sctp_hbinterval)
{
    struct sockaddr_in serv_addr;

    // Create new socket
    int listener_fd = socket(AF_INET, SOCK_STREAM, use_sctp ? IPPROTO_SCTP : IPPROTO_TCP);
    if (listener_fd < 0)
    {
        fprintf(stderr, "ERROR: Couldn't create socket.\n");
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
    fd_set read_fds;

    FD_ZERO(&ctx->peer_fds);
    FD_ZERO(&read_fds);

    int listener_fd = setup_listener(ctx, ctx->use_sctp, thread_args.sctp_hbinterval);
    if (listener_fd <= 0)
    {
        fprintf(stderr, "ERROR: Listener could not be initialized, exiting.\n");
        exit(-1);
    }

    struct timeval timeout = {0, 50000};

    while (true)
    {
        read_fds = ctx->peer_fds;

        DEBUG("Checking for new data on sockets.\n");

        int rv_select = select(ctx->max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (rv_select == 0)
        {
            DEBUG("Select timed out.\n");

            // Timeout, continue
            timeout.tv_sec = 0;
            timeout.tv_usec = 50000;
            continue;
        }
        else if (rv_select == -1)
        {
            fprintf(stderr, "ERROR: select failed with errno: %d!\n", errno);
            continue;
        }

        // Check current connections for data to be read
        for (int fd = 0; fd <= ctx->max_fd; fd++)
        {
            if (FD_ISSET(fd, &read_fds))
            {
                DEBUG("New data detected on socket %d.\n", fd);

                if (fd == listener_fd)
                {
                    DEBUG("New connection detected on socket %d.\n", fd);
                    handle_new_connection(ctx, listener_fd);
                }
                else
                {
                    DEBUG("New packet detected on socket %d. Receiving packet...\n", fd);
                    // Receive and handle message
                    handle_packet(ctx, fd);
                }
            }
        }
    }
}
