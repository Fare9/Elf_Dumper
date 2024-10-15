#ifndef MEMORY_MANAGEMENT_H
#define MEMORY_MANAGEMENT_H

#include "headers.h"

/**
 * Allocate memory using malloc with a specific size.
 * @param size bytes to allocate
 * @return pointer to allocated memory
 */
void* allocate_memory(size_t size);

/**
 * Reallocate a memory previously allocated
 * using realloc.
 * @param ptr memory previously allocated
 * @param size new size to allocate
 * @return new pointer with new memory
 */
void* realloc_memory(void* ptr, size_t size);

/**
 * Mmap a file descriptor with read permissions only.
 * @param length length of the file to map into memory
 * @param fd descriptor of the fiel to map into memory
 * @return pointer to the mapped file
 */
void* mmap_file_read(size_t length, int fd);

/**
 * Mmap a file descriptor with write permissions only.
 * @param length length of the file to map into memory
 * @param fd descriptor of the fiel to map into memory
 * @return pointer to the mapped file
 */
void* mmap_file_write(size_t length, int fd);

/**
 * Mmap a file descriptor with read and write permissions.
 * @param length length of the file to map into memory
 * @param fd descriptor of the fiel to map into memory
 * @return pointer to the mapped file
 */
void* mmap_file_read_write(size_t length, int fd);

/**
 * Free allocated memory.
 * @param ptr pointer to allocated memory
 * @return error code
 */
int free_memory(void *ptr);

/**
 * Unmap mapped memory.
 * @param ptr pointer to mapped memory
 * @param size size of mapped memory
 * @return error code
 */
int munmap_memory(void* ptr, size_t size);

#endif