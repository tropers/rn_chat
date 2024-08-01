#ifndef DEBUG_H
#define DEBUG_H

#if 0
    #define DEBUG(fmt, args...) fprintf(stderr, "DEBUG: %s:%d:%s(): " fmt, \
    __FILE__, __LINE__, __func__, ##args)
    #define DEBUGGING
#else
    #define DEBUG(fmt, args...) /* Don't do anything in release builds */
#endif

#endif
