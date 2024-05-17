#include <ctype.h>

#include "constants.h"
#include "helper.h"

void chomp(char *s)
{
    while (*s && *s != '\n' && *s != '\r')
    {
        s++;
    }

    *s = 0;
}

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
