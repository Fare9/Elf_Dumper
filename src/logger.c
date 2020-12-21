#include "logger.h"
#include <stdarg.h>

int error_flag = 0;
int debug_flag = 0;

void 
log_format(const char *tag, const char *message, va_list args)
{
    time_t now;
    time(&now);
    char *date = ctime(&now);
    date[strlen(date) - 1] = '\0';
    printf("%s [%s] ", date, tag);
    vprintf(message, args);
}

void 
log_error(const char *message, ...)
{
    va_list args;
    if (error_flag)
    {
        va_start(args, message);
        log_format("ERROR", message, args);
        printf("\n");
        va_end(args);
    }
}

void 
log_info(const char *message, ...)
{
    va_list args;
    va_start(args, message);
    log_format("INFO", message, args);
    printf("\n");
    va_end(args);
}

void 
log_debug(const char *message, ...)
{
    va_list args;
    if (debug_flag)
    {
        va_start(args, message);
        log_format("DEBUG", message, args);
        va_end(args);
    }
}

void 
set_error_flag()
{
    error_flag = 1;
}

void 
set_debug_flag()
{
    debug_flag = 1;
}