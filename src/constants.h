#define PORT 6969

#define CHAT_VERSION "v0.1"
#define INPUT_BUFFER_LEN 256
#define PORT 6969
// protocol version: 1 byte
// packet type:      1 byte
// packet length:    8 bytes
#define HEADER_LEN 10

#define IP_ADDR_LEN 4                                            // 4 bytes IP length
#define PORT_LEN 2                                               // 2 bytes port length
#define NAME_LEN_LEN 2                                           // 2 bytes name length
#define ENTRY_HEADER_LEN (IP_ADDR_LEN + PORT_LEN + NAME_LEN_LEN) // 8 bytes total length of entry header

#define PORTSTRLEN 6 // Five digits + \0 "65535\0"

#define HEARTBEAT_TIME 20

/* SCTP */
#define MSECS_IN_1SEC 1000

#define BOOL char
#define TRUE 1
#define FALSE 0
