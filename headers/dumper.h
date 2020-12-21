#ifndef DUMPER_H
#define DUMPER_H

#include "headers.h"

int dump_process(pid_t pid);
int dump_segments_to_file();
int create_sections();
void* retrieve_base_address(pid_t pid);
int fix_got(pid_t pid, void* address);

int is_in_elf_segment(void* addr);
int read_from_elf_segment(void *dst, void *src, size_t memsz);
int write_from_elf_segment(void *dst, void *src, size_t memsz);
Elf64_Addr search_plt_in_elf_segment();

#endif