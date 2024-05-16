#ifndef LIST_H
#define LIST_H

#include <stdint.h>

#include "chat_handler.h"

// Peer datatype
typedef struct {
    uint32_t ip_addr;
    BOOL connected;
    int socket;
    uint16_t port;
    double heartbeatTimer;
    BOOL isNew;
    
    char *name;
} peer;

// Peer list node datatype
typedef struct list_node {
    peer *data;
    
    struct list_node *next;
} list_node;

list_node *list_new();
void list_add(list_node **head, peer *data);
void list_remove(list_node **head, uint32_t ip_addr);
int list_size(list_node *head);
void list_free(list_node *head);

void *receiver_thread_func();
void handle(BOOL use_sctp, int sctp_hbinterval);
int connect_to_peer(uint32_t destinationIP, uint16_t destinationPort, BOOL use_sctp);
void send_disconnect();
void send_failed(int socket);
void create_enter_req_data(char **packet_data, int *packet_len);
void recv_packet(int socket, BOOL use_sctp);

#endif
