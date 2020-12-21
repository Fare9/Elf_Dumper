#include "ptrace_utils.h"

int 
ptrace_attach(pid_t pid)
{
    int wstatus;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0)
        return -1;

    waitpid(pid, &wstatus, 0);

    return 0;
}

int 
ptrace_write_buffer(pid_t pid, void *dst, const void *src, size_t len)
{
    int sz = len / sizeof(void *);
    int remainder = len % sizeof(void *);
    unsigned char *s = (unsigned char *)src;
    unsigned char *d = (unsigned char *)dst;
    long last_value = 0;
    long mask_byte = 0;

    while (sz-- != 0)
    {
        if (ptrace(PTRACE_POKETEXT, pid, d, *(void **)s) < 0)
        {
            return -1;
        }

        s += sizeof(void *);
        d += sizeof(void *);
    }

    switch (remainder)
    {
    case 0x1:
        mask_byte = 0xff;
        break;
    case 0x2:
        mask_byte = 0xffff;
        break;
    case 0x3:
        mask_byte = 0xffffff;
        break;
    case 0x4:
        mask_byte = 0xffffffff;
        break;
    case 0x5:
        mask_byte = 0xffffffffff;
        break;
    case 0x6:
        mask_byte = 0xffffffffffff;
        break;
    case 0x7:
        mask_byte = 0xffffffffffffff;
        break;
    default:
        break;
    }

    if (remainder != 0)
    {
        // need to check errno as -1 is a valid value
        // when reading
        if ((last_value = ptrace(PTRACE_PEEKDATA, pid, d, NULL)) < 0 && errno)
            return -1;
        *(long *)s = (*(long *)s & mask_byte) | (~mask_byte & last_value);
        if (ptrace(PTRACE_POKETEXT, pid, d, *(void **)s) < 0)
            return -1;
    }

    return 0;
}

int 
ptrace_read_buffer(pid_t pid, void *dst, const void *src, size_t len)
{
    int sz = len / sizeof(void *);
    int remainder = len % sizeof(void *);
    unsigned char *s = (unsigned char *)src;
    unsigned char *d = (unsigned char *)dst;
    long word;
    long mask_byte = 0;

    while (sz-- != 0)
    {
        word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
        // need to check errno as -1 is a valid value
        // when reading
        if (word == -1 && errno)
        {
            return -1;
        }

        *(long *)d = word;
        s += sizeof(long);
        d += sizeof(long);
    }

    switch (remainder)
    {
    case 0x1:
        mask_byte = 0xff;
        break;
    case 0x2:
        mask_byte = 0xffff;
        break;
    case 0x3:
        mask_byte = 0xffffff;
        break;
    case 0x4:
        mask_byte = 0xffffffff;
        break;
    case 0x5:
        mask_byte = 0xffffffffff;
        break;
    case 0x6:
        mask_byte = 0xffffffffffff;
        break;
    case 0x7:
        mask_byte = 0xffffffffffffff;
        break;
    default:
        break;
    }
    if (remainder != 0)
    {
        word = ptrace(PTRACE_PEEKTEXT, pid, s, 0x0);
        // need to check errno as -1 is a valid value
        // when reading
        if (word == -1 && errno)
        {
            return -1;
        }

        *(long *)d = (*d & ~mask_byte) | (word & mask_byte);
        s += remainder;
        d += remainder;
    }

    return 0;
}

int
ptrace_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0)
        return -1;
    return 0;
}