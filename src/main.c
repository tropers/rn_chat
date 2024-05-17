/**
 * main.c
 *
 * Main entrypoint to the application
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "chat.h"
#include "helper.h"

// Usage string
static char *usage = "Usage: chat --sctp INTERVAL_TIME\n\n\
INTERVAL_TIME: interval time for the sctp heartbeat.\n";

BOOL isnumber(char *string)
{
    BOOL is_number = TRUE;

    for (char *c = string; *c != '\0'; c++)
    {
        if (!isdigit(*c))
        {
            is_number = FALSE;
            break;
        }
    }

    return is_number;
}

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        if (strcmp(argv[1], "--sctp") == 0)
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
                    return -1;
                }
            }
            else
            {
                // If argument isn't passed correctly, print usage
                printf(usage);
                return 0;
            }
        }
        else if (strcmp(argv[1], "--help") == 0 ||
                 strcmp(argv[1], "-h") == 0)
        {
            printf(usage);
            return 0;
        }
        else
        {
            printf("Invalid argument \"%s\"\n", argv[1]);
            printf(usage);
            return -1;
        }
    }
    else
    {
        printf("Using TCP.\n");
        handle(0, 0);
    }

    return 0;
}
