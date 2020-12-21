#ifndef LOGGER_H
#define LOGGER_H

#include "headers.h"

void log_error(const char* message, ...);
void log_info(const char* message, ...);
void log_debug(const char* message, ...);

void set_error_flag();
void set_debug_flag();

#endif