#include <ctype.h>
#include <stdbool.h>

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

bool isnumber(char *string)
{
    bool is_number = true;

    for (char *c = string; *c != '\0'; c++)
    {
        if (!isdigit(*c))
        {
            is_number = false;
            break;
        }
    }

    return is_number;
}
