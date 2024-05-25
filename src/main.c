/**
 * main.c
 *
 * Main entrypoint to the application
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chat.h"
#include "helper.h"

// Usage string
static char *usage = "Usage: chat --sctp INTERVAL_TIME\n\n\
INTERVAL_TIME: interval time for the sctp heartbeat.\n";

void args_sctp(int argc, char **argv)
{
    if (argc > 2)
    {
        chomp(argv[2]);
        if (isnumber(argv[2]))
        {
            printf("Using SCTP with interval: %s.\n", argv[2]);
            handle(1, atoi(argv[2]));
        }
        else
        {
            printf("ERROR: Wrong format supplied for heartbeat SCTP heartbeat interval!\n");
            exit(-1);
        }
    }
    else
    {
        // If argument isn't passed correctly, print usage
        printf(usage);
        exit(0);
    }
}

void args_usage(int return_code)
{
    printf(usage);
    exit(return_code);
}

int main(int argc, char **argv)
{
    if (argc <= 1)
    {
        printf("Using TCP.\n");
        handle(0, 0);
        return 0;
    }
    
    if (!strcmp(argv[1], "--sctp"))
    {
        args_sctp(argc, argv);
    }
    else if (!strcmp(argv[1], "--help") ||
             !strcmp(argv[1], "-h"))
    {
        args_usage(0);
    }
    else
    {
        printf("Invalid argument \"%s\"\n", argv[1]);
        args_usage(-1);
    }

    return 0;
}
