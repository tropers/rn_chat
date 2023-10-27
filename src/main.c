/**
 * main.c
 * 
 * Main entrypoint to the application
 */

#include "chat_handler.h"

// Usage string
static char *usage = "Usage: chat -sctp INTERVAL_TIME\n\n\
INTERVAL_TIME: interval time for the sctp heartbeat\n";

int main(int argc, char **argv) {
    if (argc > 1)
    {
        if (strcmp(argv[1], "--sctp") == 0)
        {
            if (argc > 2)
            {
                printf("Using SCTP with interval: %s\n", argv[2]);
                handle(1, atoi(argv[2]));
            }
            else
            {
                // If argument isn't passed correctly, print usage
                printf(usage);
                return 0;
            }
        }
        else
        {
            printf("Invalid argument \"%s\", skipping...\nUsing TCP.\n", argv[1]);
            handle(0, 0);
        }
    }
    else
    {
        printf("Using TCP.\n");
        handle(0, 0);
    }
    return 0;
}