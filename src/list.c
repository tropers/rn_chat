#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include "list.h"

/* Creates a new list */
list_node *list_new()
{
    list_node *head = malloc(sizeof(list_node));

    head->next = NULL;
    head->data = NULL;

    if (head == NULL)
    {
        fprintf(stderr, "ERROR: Couldn't initialize list, not enough memory.\n");
        return NULL;
    }

    return head;
}

/* Adds a new item at the end of the list */
void list_add(list_node **head, peer *data)
{
    // If head is NULL (after full deletion of list), create new one
    if (*head == NULL)
    {
        *head = malloc(sizeof(list_node));

        if (*head == NULL)
        {
            fprintf(stderr, "ERROR: Couldn't allocate memory for list, not enough memory.\n");
            return;
        }

        (*head)->next = NULL;
        (*head)->data = data;
        return;
    }

    // If the head doesn't contain data yet, fill it first
    if ((*head)->data == NULL)
    {
        (*head)->next = NULL;
        (*head)->data = data;
        return;
    }

    for (list_node *node = *head; node != NULL; node = node->next)
    {
        if (node->data->ip_addr == data->ip_addr)
        {

            fprintf(stderr, "ERROR: Couldn't add to list, user already exists.\n");
            return;
        }
        if (node->next == NULL)
        {
            node->next = malloc(sizeof(list_node)); // Try to allocate a new element

            if (node->next == NULL)
            {
                fprintf(stderr, "ERROR: Couldn't allocate memory for list, not enough memory.\n");
                return;
            }

            node->next->next = NULL;
            node->next->data = data; // Add data
            return;
        }
    }
}

void list_add_safe(pthread_mutex_t *mutex, list_node **head, peer *data)
{
    pthread_mutex_lock(mutex);
    list_add(head, data);
    pthread_mutex_unlock(mutex);
}

/* Removes an item from the list */
void list_remove(list_node **head, uint32_t ip_addr)
{
    list_node *prev = *head;

    for (list_node *node = *head; node != NULL; node = node->next)
    {
        if (node->data->ip_addr == ip_addr)
        {
            // If head is deleted
            if (node == *head)
            {
                list_node *next = (*head)->next;
                free(*head);
                *head = next;
                break;
            }

            prev->next = node->next;
            free(node->data);
            free(node);
            node = NULL;
            break;
        }

        prev = node;
    }
}

void list_remove_safe(pthread_mutex_t *mutex, list_node **head, uint32_t ip_addr)
{
    pthread_mutex_lock(mutex);
    list_remove(head, ip_addr);
    pthread_mutex_unlock(mutex);
}

int list_size(list_node *head)
{

    int size = 0;

    for (list_node *node = head; node != NULL; node = node->next)
    {
        ++size;
    }

    return size;
}

int list_size_safe(pthread_mutex_t *mutex, list_node *head)
{
    pthread_mutex_lock(mutex);
    int size = list_size(head);
    pthread_mutex_unlock(mutex);

    return size;
}

void list_free(list_node *head)
{

    list_node *current = head;
    list_node *next;

    while (current != NULL)
    {
        next = current->next;
        free(current->data);
        free(current);
        current = next;
    }
}

void list_free_safe(pthread_mutex_t *mutex, list_node *head)
{
    pthread_mutex_lock(mutex);
    list_free(head);
    pthread_mutex_unlock(mutex);
}
