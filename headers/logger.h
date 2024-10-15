#ifndef LOGGER_H
#define LOGGER_H

#include "headers.h"

/**
 * Method to print error messages.
 */
void log_error(const char* message, ...);

/**
 * Method to print info messages.
 */
void log_info(const char* message, ...);

/**
 * Method to print debug messages.
 */
void log_debug(const char* message, ...);

/**
 * Set a global error flag to show error messages.
 */
void set_error_flag();

/**
 * Set a global debug flag to show debug messages.
 */
void set_debug_flag();

#endif