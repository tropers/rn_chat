/**
 * chat_handler.h
 * 
 * Contains all the datastructures and function headers for
 * the chat application
 */

#ifndef CHAT_HANDLER_H
#define CHAT_HANDLER_H

#include <pthread.h>
#include <stdint.h>
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

#define PORT                6969

#define CHAT_VERSION        "v0.1"
#define INPUT_BUFFER_LEN    256
#define PORT                6969
#define HEADER_LEN          4

#define IP_ADDR_LEN         4   // 4 bytes IP length
#define PORT_LEN            2   // 2 bytes port length
#define NAME_LEN_LEN        2   // 2 bytes name length
#define ENTRY_HEADER_LEN    (IP_ADDR_LEN + PORT_LEN + NAME_LEN_LEN)   // 8 bytes total length of entry header

/* Protocol definitions */
#define PROTOCOL_VERSION    2
#define MSG_ENTER_REQ       'E'
#define MSG_NEW_USERS       'N' 
#define MSG_CONNECT         'C'
#define MSG_DISCONNECT      'D'
#define MSG_HEARTBEAT       'H'
#define MSG_MESSAGE         'M'
#define MSG_PRIVATE         'P'
#define MSG_FAILED          'F'

#define HEARTBEAT_TIME      20

/* SCTP */
#define MSECS_IN_1SEC       1000

#define BOOL char

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

// Packet datatype
typedef struct {
    char version;
    char type;
    short length;

    char *data;
} packet;

// Thread args for SCTP
typedef struct {
    BOOL use_sctp;
    int sctp_hbinterval;
} receiver_thread_args;

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
