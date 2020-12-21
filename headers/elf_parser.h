#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include "headers.h"
#include "elf_generic_types.h"
#include "ptrace_utils.h"
#include "memory_management.h"


int analyze_headers(pid_t pid, void* address);
int read_elf_ehdr_header(pid_t pid, void* address);
int read_elf_phdr_headers(pid_t pid, void* address);
int read_elf_dynamic_header(pid_t pid, void* address);
int get_is_32_bit_binary();
int get_is_dyn_binary();

Elf_Shdr* create_elf_shdr(uint32_t sh_name, uint32_t sh_type, uint64_t sh_flags, 
    Elf64_Addr sh_addr, Elf64_Off sh_offset, uint64_t sh_size, uint32_t sh_link, 
    uint32_t sh_info, uint64_t sh_addralign, uint64_t sh_entsize);

void destroy_elf_shdr(Elf_Shdr* elf_shdr);

Elf_Ehdr* get_elf_ehdr();
size_t get_loadable_elf_phdr_number();
Elf_Phdr* get_elf_phdr(size_t index);
Elf_Dyn* get_elf_dyn(size_t index);
size_t get_dynamic_headers_size();


#endif