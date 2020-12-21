#ifndef PTRACE_UTILS_H
#define PTRACE_UTILS_H

#include "headers.h"

int ptrace_attach(pid_t pid);
int ptrace_write_buffer(pid_t pid, void *dst, const void *src, size_t len);
int ptrace_read_buffer(pid_t pid, void *dst, const void *src, size_t len);
int ptrace_detach(pid_t pid);

#endif