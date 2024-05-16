#include "helper.h"

void chomp(char *s)
{
    while (*s && *s != '\n' && *s != '\r')
    {
        s++;
    }

    *s = 0;
}
