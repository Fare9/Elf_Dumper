#include "memory_management.h"

void* 
allocate_memory(size_t size)
{
    void* ret_address;

    if (size == 0)
    {
        return ((void*)-2);
    }

    if ((ret_address = malloc(size)) == NULL)
    {
        return ((void*)-1);
    }

    return (ret_address);
}

void*
realloc_memory(void* ptr, size_t size)
{
    void* ret_address;

    if (size == 0)
    {
        return ((void*)-2);
    }

    if (ptr == NULL)
    {
        return ((void*)-2);
    }

    if ((ret_address = realloc(ptr, size)) == NULL)
    {
        return ((void*)-1);
    }

    return (ret_address);
}

void*
mmap_file_read(size_t length, int fd)
{
    void* file_memory;

    if (length == 0)
    {
        return ((void*)-2);
    }

    if (fd < 0)
    {
        return ((void*)-2);
    }

    if ((file_memory = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        return ((void*)-1);
    }

    return (file_memory);
}

void*
mmap_file_write(size_t length, int fd)
{
    void* file_memory;

    if (length == 0)
    {
        return ((void*)-2);
    }

    if (fd < 0)
    {
        return ((void*)-2);
    }

    if ((file_memory = mmap(NULL, length, PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        return ((void*)-1);
    }

    return (file_memory);
}

void*
mmap_file_read_write(size_t length, int fd)
{
    void* file_memory;

    if (length == 0)
    {
        return ((void*)-2);
    }

    if (fd < 0)
    {
        return ((void*)-2);
    }

    if ((file_memory = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
    {
        return ((void*)-1);
    }

    return (file_memory);
}

int
free_memory(void *ptr)
{
    if (ptr == NULL)
    {
        return (-1);
    }

    free(ptr);

    ptr = NULL;

    return (0);
}

int
munmap_memory(void* ptr, size_t size)
{
    if (size == 0)
    {
        return (-2);
    }

    if (ptr == NULL)
    {
        return (-2);
    }

    if (munmap(ptr, size) < 0)
    {
        return (-1);
    }

    return (0);
}