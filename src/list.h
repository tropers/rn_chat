#ifndef LIST_H
#define LIST_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#include "constants.h"

// Peer datatype
typedef struct
{
    double heartbeat_timer;
    uint32_t ip_addr;
    int sock;
    uint16_t port;
    bool is_new;
    bool connected;

    char *name;
} peer;

// Peer list node datatype
typedef struct list_node
{
    peer *data;
    struct list_node *next;
} list_node;

list_node *list_new();
void list_add(list_node **head, peer *data);
void list_add_safe(pthread_mutex_t *mutex, list_node **head, peer *data);
void list_remove(list_node **head, uint32_t ip_addr);
void list_remove_safe(pthread_mutex_t *mutex, list_node **head, uint32_t ip_addr);
int list_size(list_node *head);
int list_size_safe(pthread_mutex_t *mutex, list_node *head);
void list_free(list_node *head);
void list_free_safe(pthread_mutex_t *mutex, list_node *head);

#endif
