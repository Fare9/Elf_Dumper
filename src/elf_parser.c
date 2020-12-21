#include "elf_parser.h"
#include "logger.h"

Elf_Ehdr *elf_ehdr = NULL;
Elf_Phdr *elf_phdr = NULL;
Elf_Dyn *elf_dyn = NULL;

// is 32 or 64 bit binary?
int is_32_bit_binary;
// is EXE or DYN binary?
int is_dyn_binary;

size_t dynamic_headers = 0;

int analyze_headers(pid_t pid, void *address)
{
    int i;
    int ret_value = 0;
    long addr = (long)address;

    unsigned char e_ident[EI_NIDENT];

    log_info("Analyzing headers for process with pid %d and address 0x%016lx", pid, address);

    if ((ret_value = ptrace_read_buffer(pid, e_ident, address, EI_NIDENT)) < 0)
        return ret_value;

    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 || e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3)
    {
        log_error("elf incorrect header");
        return (-2);
    }

    if (e_ident[EI_CLASS] == ELFCLASS32)
    {
        log_info("Process is 32 bit");
        is_32_bit_binary = 1;
    }
    else
    {
        log_info("Process is 64 bit");
        is_32_bit_binary = 0;
    }

    // Read Elf_ehdr
    if ((ret_value = read_elf_ehdr_header(pid, (void *)addr)) < 0)
        return ret_value;

    addr = ((long)address + elf_ehdr->e_phoff);

    // Read Elf_phdr
    if ((ret_value = read_elf_phdr_headers(pid, (void *)addr)) < 0)
        return ret_value;

    for (i = 0; i < elf_ehdr->e_phnum; i++)
    {
        if (elf_phdr[i].p_type == PT_DYNAMIC)
        {
            // DYN binaries use RVAs
            if (is_dyn_binary)
                addr = ((long)address + elf_phdr[i].p_vaddr);
            // EXE use absolute addresses
            else
                addr = elf_phdr[i].p_vaddr;

            break;
        }
    }

    if ((ret_value = read_elf_dynamic_header(pid, (void *)addr)) < 0)
        return ret_value;

    return 0;
}

// ELF_Ehdr header functions
static void
print_elf_ehdr()
{
    log_debug("Elf Header\n");
    log_debug("Elf magic: %x %c %c %c %x %x %x %x %x %x %x %x %x %x %x %x\n", elf_ehdr->e_ident[0], elf_ehdr->e_ident[1], elf_ehdr->e_ident[2], elf_ehdr->e_ident[3], elf_ehdr->e_ident[4], elf_ehdr->e_ident[5], elf_ehdr->e_ident[6], elf_ehdr->e_ident[7], elf_ehdr->e_ident[8], elf_ehdr->e_ident[9], elf_ehdr->e_ident[10], elf_ehdr->e_ident[11], elf_ehdr->e_ident[12], elf_ehdr->e_ident[13], elf_ehdr->e_ident[14], elf_ehdr->e_ident[15]);
    log_debug("Elf type:                               %d\n", elf_ehdr->e_type);
    log_debug("Elf machine:                            %d\n", elf_ehdr->e_machine);
    log_debug("Elf version:                            %d\n", elf_ehdr->e_version);
    log_debug("Elf entry:                              %x\n", elf_ehdr->e_entry);
    log_debug("Elf phoff:                              %x\n", elf_ehdr->e_phoff);
    log_debug("Elf shoff:                              %x\n", elf_ehdr->e_shoff);
    log_debug("Elf flags:                              %x\n", elf_ehdr->e_flags);
    log_debug("Elf ehsize:                             %d\n", elf_ehdr->e_ehsize);
    log_debug("Elf phentsize:                          %d\n", elf_ehdr->e_phentsize);
    log_debug("Elf phnum:                              %d\n", elf_ehdr->e_phnum);
    log_debug("Elf shentsize:                          %d\n", elf_ehdr->e_shentsize);
    log_debug("Elf shnum:                              %d\n", elf_ehdr->e_shnum);
    log_debug("Elf shstrndx:                           %d\n", elf_ehdr->e_shstrndx);
}

int read_elf_ehdr_header(pid_t pid, void *address)
{
    int ret_value = 0;
    Elf32_Ehdr elf32_ehdr;
    Elf64_Ehdr elf64_ehdr;

    log_info("Reading Elf_Ehdr header from address 0x%016lx", address);

    if (address == NULL)
    {
        log_error("Address given is null");
        return (-2);
    }

    if (elf_ehdr != NULL)
    {
        free(elf_ehdr);
        elf_ehdr = NULL;
    }

    elf_ehdr = allocate_memory(sizeof(Elf_Ehdr));

    if (is_32_bit_binary)
    {
        if ((ret_value = ptrace_read_buffer(pid, &elf32_ehdr, address, sizeof(Elf32_Ehdr))) < 0)
            return ret_value;

        memcpy(elf_ehdr->e_ident, elf32_ehdr.e_ident, EI_NIDENT);
        elf_ehdr->e_type = elf32_ehdr.e_type;
        elf_ehdr->e_machine = elf32_ehdr.e_machine;
        elf_ehdr->e_version = elf32_ehdr.e_version;
        elf_ehdr->e_entry = elf32_ehdr.e_entry;
        elf_ehdr->e_phoff = elf32_ehdr.e_phoff;
        elf_ehdr->e_shoff = elf32_ehdr.e_shoff;
        elf_ehdr->e_flags = elf32_ehdr.e_flags;
        elf_ehdr->e_ehsize = elf32_ehdr.e_ehsize;
        elf_ehdr->e_phentsize = elf32_ehdr.e_phentsize;
        elf_ehdr->e_phnum = elf32_ehdr.e_phnum;
        elf_ehdr->e_shentsize = elf32_ehdr.e_shentsize;
        elf_ehdr->e_shnum = elf32_ehdr.e_shnum;
        elf_ehdr->e_shstrndx = elf32_ehdr.e_shstrndx;
    }
    else
    {
        if ((ret_value = ptrace_read_buffer(pid, &elf64_ehdr, address, sizeof(Elf64_Ehdr))) < 0)
            return ret_value;

        memcpy(elf_ehdr->e_ident, elf64_ehdr.e_ident, EI_NIDENT);
        elf_ehdr->e_type = elf64_ehdr.e_type;
        elf_ehdr->e_machine = elf64_ehdr.e_machine;
        elf_ehdr->e_version = elf64_ehdr.e_version;
        elf_ehdr->e_entry = elf64_ehdr.e_entry;
        elf_ehdr->e_phoff = elf64_ehdr.e_phoff;
        elf_ehdr->e_shoff = elf64_ehdr.e_shoff;
        elf_ehdr->e_flags = elf64_ehdr.e_flags;
        elf_ehdr->e_ehsize = elf64_ehdr.e_ehsize;
        elf_ehdr->e_phentsize = elf64_ehdr.e_phentsize;
        elf_ehdr->e_phnum = elf64_ehdr.e_phnum;
        elf_ehdr->e_shentsize = elf64_ehdr.e_shentsize;
        elf_ehdr->e_shnum = elf64_ehdr.e_shnum;
        elf_ehdr->e_shstrndx = elf64_ehdr.e_shstrndx;
    }

    print_elf_ehdr();

    if (elf_ehdr->e_phoff == 0 || elf_ehdr->e_phnum == 0 || elf_ehdr->e_phentsize == 0)
    {
        log_error("No e_phoff, e_phnum or e_phentsize, not possible to dump");
        return -2;
    }

    if (elf_ehdr->e_type == ET_DYN)
    {
        log_info("File to dump is DYN file");
        is_dyn_binary = 1;
    }
    else if (elf_ehdr->e_type == ET_EXEC)
    {
        log_info("File to dump is EXE file");
        is_dyn_binary = 0;
    }
    else
    {
        log_error("Error ELF e_type not supported");
        return -2;
    }

    log_info("Correctly read Elf_Ehdr header");

    return 0;
}

// ELF_Phdr header functions
static void
print_elf_phdr()
{
    int i;

    log_debug("Elf Program Header:\n");

    log_debug("%s|%s|%s|%s|%s|%s|%s|%s\n", "TYPE", "FLAGS", "Offset", "V.Addr", "P.Addr", "F.Size", "M.Size", "Align");

    for (i = 0; i < elf_ehdr->e_phnum; i++)
    {
        log_debug("%x|%x|%x|%x|%x|%x|%x|%x|%x\n", elf_phdr[i].p_type, elf_phdr[i].p_flags, elf_phdr[i].p_offset, elf_phdr[i].p_vaddr, elf_phdr[i].p_paddr, elf_phdr[i].p_filesz, elf_phdr[i].p_memsz, elf_phdr[i].p_align);
    }
}

int read_elf_phdr_headers(pid_t pid, void *address)
{
    int ret_value;
    int i;
    Elf32_Phdr elf32_phdr;
    Elf64_Phdr elf64_phdr;

    log_info("Reading %d Elf_Phdr headers from address 0x%016lx", elf_ehdr->e_phnum, address);

    if (elf_phdr != NULL)
    {
        free_memory(elf_phdr);
        elf_phdr = NULL;
    }

    elf_phdr = allocate_memory(sizeof(Elf_Phdr) * elf_ehdr->e_phnum);

    if (is_32_bit_binary)
    {
        for (i = 0; i < elf_ehdr->e_phnum; i++)
        {
            if ((ret_value = ptrace_read_buffer(pid, &elf32_phdr, address, sizeof(Elf32_Phdr))) < 0)
                return ret_value;

            elf_phdr[i].p_type = elf32_phdr.p_type;
            elf_phdr[i].p_flags = elf32_phdr.p_flags;
            elf_phdr[i].p_offset = elf32_phdr.p_offset;
            elf_phdr[i].p_vaddr = elf32_phdr.p_vaddr;
            elf_phdr[i].p_paddr = elf32_phdr.p_paddr;
            elf_phdr[i].p_filesz = elf32_phdr.p_filesz;
            elf_phdr[i].p_memsz = elf32_phdr.p_memsz;
            elf_phdr[i].p_align = elf32_phdr.p_align;

            address = (void *)((long)address + sizeof(Elf32_Phdr));
        }
    }
    else
    {
        for (i = 0; i < elf_ehdr->e_phnum; i++)
        {
            if ((ret_value = ptrace_read_buffer(pid, &elf64_phdr, address, sizeof(Elf64_Phdr))) < 0)
                return ret_value;

            elf_phdr[i].p_type = elf64_phdr.p_type;
            elf_phdr[i].p_flags = elf64_phdr.p_flags;
            elf_phdr[i].p_offset = elf64_phdr.p_offset;
            elf_phdr[i].p_vaddr = elf64_phdr.p_vaddr;
            elf_phdr[i].p_paddr = elf64_phdr.p_paddr;
            elf_phdr[i].p_filesz = elf64_phdr.p_filesz;
            elf_phdr[i].p_memsz = elf64_phdr.p_memsz;
            elf_phdr[i].p_align = elf64_phdr.p_align;

            address = (void *)((long)address + sizeof(Elf64_Phdr));
        }
    }

    print_elf_phdr();

    log_info("Correctly read Elf_Phdr headers");

    return 0;
}

// Elf_Dyn header functions
int read_elf_dynamic_header(pid_t pid, void *address)
{
    int i;
    int ret_value;

    Elf32_Dyn elf32_dyn;
    Elf64_Dyn elf64_dyn;

    log_info("Reading Elf_Dyn headers from address 0x%016lx", address);

    // first let's see if there are dynamic headers already
    if (elf_dyn != NULL)
    {
        free_memory(elf_dyn);
        elf_dyn = NULL;

        dynamic_headers = 0;
    }

    // Now get number of dynamic headers
    for (i = 0; i < elf_ehdr->e_phnum; i++)
    {
        if (elf_phdr[i].p_type == PT_DYNAMIC)
        {
            if (is_32_bit_binary)
            {
                dynamic_headers = elf_phdr[i].p_filesz / sizeof(Elf32_Dyn);
            }
            else
            {
                dynamic_headers = elf_phdr[i].p_filesz / sizeof(Elf64_Dyn);
            }
            break;
        }
    }

    if (dynamic_headers)
    {
        elf_dyn = allocate_memory(dynamic_headers * sizeof(Elf_Dyn));
    }

    for (i = 0; i < dynamic_headers; i++)
    {
        if (is_32_bit_binary)
        {
            if ((ret_value = ptrace_read_buffer(pid, &elf32_dyn, address, sizeof(Elf32_Dyn))) < 0)
                return ret_value;

            elf_dyn[i].d_tag = elf32_dyn.d_tag;
            elf_dyn[i].d_un.d_ptr = elf32_dyn.d_un.d_ptr;

            address = (void *)((long)address + sizeof(Elf32_Dyn));
        }
        else
        {
            if ((ret_value = ptrace_read_buffer(pid, &elf64_dyn, address, sizeof(Elf64_Dyn))) < 0)
                return ret_value;

            elf_dyn[i].d_tag = elf64_dyn.d_tag;
            elf_dyn[i].d_un.d_ptr = elf64_dyn.d_un.d_ptr;

            address = (void *)((long)address + sizeof(Elf64_Dyn));
        }
    }

    log_info("Correctly read Elf_Dyn headers.");

    return 0;
}

Elf_Shdr *
create_elf_shdr(uint32_t sh_name, uint32_t sh_type, uint64_t sh_flags,
                Elf64_Addr sh_addr, Elf64_Off sh_offset, uint64_t sh_size, uint32_t sh_link,
                uint32_t sh_info, uint64_t sh_addralign, uint64_t sh_entsize)
{
    Elf_Shdr *elf_shdr = allocate_memory(sizeof(Elf_Shdr));

    elf_shdr->sh_name = sh_name;
    elf_shdr->sh_type = sh_type;
    elf_shdr->sh_flags = sh_flags;
    elf_shdr->sh_addr = sh_addr;
    elf_shdr->sh_offset = sh_offset;
    elf_shdr->sh_size = sh_size;
    elf_shdr->sh_link = sh_link;
    elf_shdr->sh_info = sh_info;
    elf_shdr->sh_addralign = sh_addralign;
    elf_shdr->sh_entsize = sh_entsize;

    return elf_shdr;
}

void destroy_elf_shdr(Elf_Shdr *elf_shdr)
{
    free_memory(elf_shdr);
}

Elf_Ehdr *
get_elf_ehdr()
{
    return elf_ehdr;
}

size_t
get_loadable_elf_phdr_number()
{
    int i;
    size_t loadable_phdr = 0;

    for (i = 0; i < elf_ehdr->e_phnum; i++)
    {
        if (elf_phdr[i].p_type == PT_LOAD)
            loadable_phdr += 1;
    }

    return loadable_phdr;
}

Elf_Phdr *
get_elf_phdr(size_t index)
{
    if (elf_phdr == NULL || index >= elf_ehdr->e_phnum)
        return NULL;

    return &elf_phdr[index];
}

Elf_Dyn *
get_elf_dyn(size_t index)
{
    if (elf_dyn == NULL || dynamic_headers == 0 || index >= dynamic_headers)
        return NULL;

    return &elf_dyn[index];
}

size_t
get_dynamic_headers_size()
{
    return dynamic_headers;
}

int get_is_32_bit_binary()
{
    return is_32_bit_binary;
}

int get_is_dyn_binary()
{
    return is_dyn_binary;
}