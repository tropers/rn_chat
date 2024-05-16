/**
 * chat_handler.h
 * 
 * Contains all the datastructures and function headers for
 * the chat application
 */

#ifndef CHAT_HANDLER_H
#define CHAT_HANDLER_H

#include <stdint.h>

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

void handle(BOOL use_sctp, int sctp_hbinterval);

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

#endif
