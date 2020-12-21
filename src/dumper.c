#include "dumper.h"
#include "elf_parser.h"
#include "elf_generic_types.h"
#include "logger.h"

#define MAX_PATH 1024
#define FILE_MAP "/proc/%d/maps"

typedef struct elf_segment
{
    Elf_Phdr *phdr;
    uint8_t *byte;
} elf_segment_t;

void *base_address;
Elf64_Addr got_address = 0;
Elf64_Addr plt_addr = 0;
size_t number_of_plt_entries = 0;
size_t size_type_of_rel = 0;
elf_segment_t *segments = NULL;
int fd;

uint8_t plt_pattern_64_bit[] = {
    0xf3, 0x0f, 0x1e, 0xfa,             // endbr64
    0x68, 0x00, 0x00, 0x00, 0x00,       // pushq  $0x0
    0xf2, 0xe9, 0xe1, 0xff, 0xff, 0xff, // bnd jmpq -31
    0x90                                // nop
};

uint8_t plt_pattern_32_bit[] = {
    0xf3, 0x0f, 0x1e, 0xfb,       // endbr32
    0x68, 0x00, 0x00, 0x00, 0x00, // push  $0x0
    0xe9, 0xe2, 0xff, 0xff, 0xff, // jmp -32
    0x66, 0x90                    // xchg %ax, %ax
};

// the shstrtable from quenya project by Ryan O'Neill (C) 2010
char shstrtable[] =
    "\0"
    ".interp\0"
    ".hash\0"
    ".note.ABI-tag\0"
    ".gnu.hash\0"
    ".dynsym\0"
    ".dynstr\0"
    ".gnu.version\0"
    ".gnu.version_r\0"
    ".rel.dyn\0"
    ".rel.plt\0"
    ".rela.dyn\0"
    ".rela.plt\0"
    ".init\0"
    ".plt\0"
    ".text\0"
    ".fini\0"
    ".rodata\0"
    ".eh_frame_hdr\0"
    ".eh_frame\0"
    ".ctors\0"
    ".dtors\0"
    ".jcr\0"
    ".dynamic\0"
    ".got\0"
    ".got.plt\0"
    ".data\0"
    ".bss\0"
    ".shstrtab\0"
    ".symtab\0"
    ".strtab\0";

static elf_segment_t * return_elf_segment(Elf64_Addr addr);

int dump_process(pid_t pid)
{
    size_t i, j = 0;
    int ret_value;
    size_t dynamic_headers;
    Elf_Dyn *elf_dyn;
    size_t size_plt_entries;

    // Get base address from binary
    if ((base_address = retrieve_base_address(pid)) == NULL)
        return -2;

    log_info("Attaching to process %d", pid);

    // attach to process
    if ((ret_value = ptrace_attach(pid)) < 0)
        return ret_value;

    // Analyze the available headers
    if ((ret_value = analyze_headers(pid, base_address)) < 0)
        return ret_value;

    // Read information of segments and read segments
    segments = allocate_memory(sizeof(elf_segment_t) * get_loadable_elf_phdr_number());

    for (i = 0; i < get_elf_ehdr()->e_phnum; i++)
    {
        if (get_elf_phdr(i)->p_type == PT_LOAD)
        {
            segments[j].phdr = get_elf_phdr(i);

            segments[j].byte = allocate_memory(segments[j].phdr->p_memsz);

            void *phdr_addr;

            if (get_is_dyn_binary())
                phdr_addr = (void *)((Elf64_Addr)base_address + segments[j].phdr->p_vaddr);
            else
                phdr_addr = (void *)segments[j].phdr->p_vaddr;

            log_info("Reading %ld bytes from segment %d (0x%016lx)", segments[j].phdr->p_memsz, i, phdr_addr);

            if ((ret_value = ptrace_read_buffer(pid, (void *)segments[j].byte, phdr_addr, segments[j].phdr->p_memsz)) < 0)
                return ret_value;

            j++;
        }
    }

    // Retrieve information from Dynamic headers
    dynamic_headers = get_dynamic_headers_size();

    for (i = 0; i < dynamic_headers; i++)
    {
        elf_dyn = get_elf_dyn(i);

        switch (elf_dyn->d_tag)
        {
        case DT_PLTGOT:
            got_address = elf_dyn->d_un.d_ptr;
            log_info("Found DT_PLTGOT in address 0x%016lx", got_address);
            break;
        case DT_PLTREL:
            if (get_is_32_bit_binary())
            {
                if (elf_dyn->d_un.d_val == DT_REL)
                    size_type_of_rel = sizeof(Elf32_Rel);
                else if (elf_dyn->d_un.d_val == DT_RELA)
                    size_type_of_rel = sizeof(Elf32_Rela);
            }
            else
            {
                if (elf_dyn->d_un.d_val == DT_REL)
                    size_type_of_rel = sizeof(Elf64_Rel);
                else if (elf_dyn->d_un.d_val == DT_RELA)
                    size_type_of_rel = sizeof(Elf64_Rela);
            }
            break;
        case DT_PLTRELSZ:
            size_plt_entries = elf_dyn->d_un.d_val;
            break;
        }
    }

    number_of_plt_entries = size_plt_entries / size_type_of_rel;

    fix_got(pid, (void *)got_address);

    log_info("Detaching from process %d", pid);

    if ((ret_value = ptrace_detach(pid)) < 0)
        return ret_value;

    fd = open("dump_file.out", O_TRUNC | O_CREAT | O_WRONLY, S_IRWXU);
    
    dump_segments_to_file();

    create_sections();

    // modify the access permissions
    fchown(fd, getuid(), getgid());

    close(fd);

    return 0;
}

int
dump_segments_to_file()
{
    int i = 0;
    Elf_Phdr* segment;

    for (i = 0; i < get_loadable_elf_phdr_number(); i++)
    {
        segment = segments[i].phdr;

        lseek(fd, segment->p_offset, SEEK_SET);

        write(fd, segments[i].byte, segment->p_filesz);
    }

    return 0;
}

static off_t
get_offset_in_shstrtable(char *name)
{
    int i;
    char *p;

    for (i = 0, p = shstrtable;; i++)
    {
        if (strcmp(name, p+i) == 0)
        {
            return i;
        }
    }

    return -1;
}

static int
write_section_to_file(Elf_Shdr* section)
{
    Elf32_Shdr shdr32;
    Elf64_Shdr shdr64;

    if (get_is_32_bit_binary())
    {
        shdr32.sh_addr = section->sh_addr;
        shdr32.sh_addralign = section->sh_addralign;
        shdr32.sh_entsize = section->sh_entsize;
        shdr32.sh_flags = section->sh_flags;
        shdr32.sh_info = section->sh_info;
        shdr32.sh_link = section->sh_link;
        shdr32.sh_name = section->sh_name;
        shdr32.sh_offset = section->sh_offset;
        shdr32.sh_size = section->sh_size;
        shdr32.sh_type = section->sh_type;

        write(fd, &shdr32, sizeof(Elf32_Shdr));
    }
    else
    {
        shdr64.sh_addr = section->sh_addr;
        shdr64.sh_addralign = section->sh_addralign;
        shdr64.sh_entsize = section->sh_entsize;
        shdr64.sh_flags = section->sh_flags;
        shdr64.sh_info = section->sh_info;
        shdr64.sh_link = section->sh_link;
        shdr64.sh_name = section->sh_name;
        shdr64.sh_offset = section->sh_offset;
        shdr64.sh_size = section->sh_size;
        shdr64.sh_type = section->sh_type;

        write(fd, &shdr64, sizeof(Elf64_Shdr));
    }
    
    return 0;
}

static int
write_elf_header_to_file(Elf_Ehdr* header)
{
    Elf32_Ehdr header32;
    Elf64_Ehdr header64;

    off_t curr_offset = lseek(fd, 0, SEEK_CUR);

    // move to the beginning
    lseek(fd, 0, SEEK_SET);

    if (get_is_32_bit_binary())
    {
        memcpy(&header32.e_ident, &header->e_ident, EI_NIDENT);
        header32.e_entry = header->e_entry;
        header32.e_type = header->e_type;
        header32.e_machine = header->e_machine;
        header32.e_version = header->e_version;
        header32.e_phoff = header->e_phoff;
        header32.e_shoff = header->e_shoff;
        header32.e_flags = header->e_flags;
        header32.e_ehsize = header->e_ehsize;
        header32.e_phentsize = header->e_phentsize;
        header32.e_phnum = header->e_phnum;
        header32.e_shentsize = header->e_shentsize;
        header32.e_shnum = header->e_shnum;
        header32.e_shstrndx = header->e_shstrndx;

        write(fd, &header32, sizeof(Elf32_Ehdr));
    }
    else
    {
        memcpy(&header64.e_ident, &header->e_ident, EI_NIDENT);
        header64.e_entry = header->e_entry;
        header64.e_type = header->e_type;
        header64.e_machine = header->e_machine;
        header64.e_version = header->e_version;
        header64.e_phoff = header->e_phoff;
        header64.e_shoff = header->e_shoff;
        header64.e_flags = header->e_flags;
        header64.e_ehsize = header->e_ehsize;
        header64.e_phentsize = header->e_phentsize;
        header64.e_phnum = header->e_phnum;
        header64.e_shentsize = header->e_shentsize;
        header64.e_shnum = header->e_shnum;
        header64.e_shstrndx = header->e_shstrndx;

        write(fd, &header64, sizeof(Elf64_Ehdr));
    }
    
    // return to offset
    lseek(fd, curr_offset, SEEK_SET);

    return 0;
}

int 
create_sections()
{
    int i;
    off_t shstrtable_offset = lseek(fd, 0, SEEK_END);
    off_t shdr_offset = 0;
    size_t n_of_sections = 0;
    size_t sh_entsize = 0;

    write(fd, shstrtable, sizeof(shstrtable));
    shdr_offset = lseek(fd, 0, SEEK_END);


    /* .null */
    Elf_Shdr* null_shdr = create_elf_shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    write_section_to_file(null_shdr);
    destroy_elf_shdr(null_shdr);
    
    n_of_sections += 1;

    /* .interp */
    Elf_Shdr* interp;
    for (i = 0; i < get_elf_ehdr()->e_phnum; i++)
    {
        if (get_elf_phdr(i)->p_type == PT_INTERP)
        {
            interp = create_elf_shdr(
                get_offset_in_shstrtable(".interp"),
                SHT_PROGBITS,
                SHF_ALLOC,
                get_elf_phdr(i)->p_vaddr,
                get_elf_phdr(i)->p_offset,
                get_elf_phdr(i)->p_filesz,
                0, 0, 1, 0
            );

            write_section_to_file(interp);
            destroy_elf_shdr(interp);
        }
    }
    n_of_sections += 1;

    /* .text */
    Elf_Shdr *text_section;

    for (i = 0; i < get_loadable_elf_phdr_number(); i++)
    {
        if (segments[i].phdr->p_flags & PF_W &&
            segments[i].phdr->p_flags & PF_R)
        {
            text_section = create_elf_shdr(
                get_offset_in_shstrtable(".text"),
                SHT_PROGBITS,
                SHF_ALLOC|SHF_EXECINSTR,
                get_elf_phdr(i)->p_vaddr,
                get_elf_phdr(i)->p_offset,
                get_elf_phdr(i)->p_filesz,
                0, 0, 0x10, 0
            );

            write_section_to_file(text_section);
            destroy_elf_shdr(text_section);
        }
    }

    n_of_sections += 1;

    /* .data and .bss */
    Elf_Shdr* data_section;
    Elf_Shdr* bss_section;

    for (i = 0; i < get_loadable_elf_phdr_number(); i++)
    {
        if (segments[i].phdr->p_flags & PF_R &&
            segments[i].phdr->p_flags & PF_W)
        {
            data_section = create_elf_shdr(
                get_offset_in_shstrtable(".data"),
                SHT_PROGBITS,
                SHF_ALLOC | SHF_WRITE,
                segments[i].phdr->p_vaddr,
                segments[i].phdr->p_offset,
                segments[i].phdr->p_filesz,
                0, 0, sizeof(void*), 0
            );

            write_section_to_file(data_section);

            bss_section = create_elf_shdr(
                get_offset_in_shstrtable(".bss"),
                SHT_NOBITS,
                SHF_ALLOC|SHF_WRITE,
                segments[i].phdr->p_vaddr + segments[i].phdr->p_filesz,
                segments[i].phdr->p_offset + segments[i].phdr->p_filesz,
                segments[i].phdr->p_memsz - segments[i].phdr->p_filesz,
                0, 0, sizeof(void*), 0
            );

            write_section_to_file(bss_section);

            destroy_elf_shdr(data_section);
            destroy_elf_shdr(bss_section);
        }
    }
    n_of_sections += 2;

    /* .dynamic */
    Elf_Shdr* dynamic_section;

    for (i = 0; i < get_elf_ehdr()->e_phnum; i++)
    {
        if (get_elf_phdr(i)->p_type == PT_DYNAMIC)
        {
            if (get_is_32_bit_binary())
                sh_entsize = sizeof(Elf32_Dyn);
            else
                sh_entsize = sizeof(Elf64_Dyn);

            dynamic_section = create_elf_shdr(
                get_offset_in_shstrtable(".dynamic"),
                SHT_DYNAMIC,
                SHF_WRITE | SHF_ALLOC,
                get_elf_phdr(i)->p_vaddr,
                get_elf_phdr(i)->p_offset,
                get_elf_phdr(i)->p_filesz,
                0, 0, sizeof(void*), sh_entsize
            );

            write_section_to_file(dynamic_section);
            destroy_elf_shdr(dynamic_section);
        }
    }

    n_of_sections += 1;

    /* .got.plt & .plt */
    Elf_Shdr* got_section;
    Elf64_Addr got_offset;
    elf_segment_t *got_segment = return_elf_segment(got_address);

    if (get_is_dyn_binary())
        got_address -= (Elf64_Addr)base_address;
    
    got_offset = got_address - got_segment->phdr->p_vaddr;
    
    got_section = create_elf_shdr(
        get_offset_in_shstrtable(".got.plt"),
        SHT_PROGBITS,
        SHF_WRITE | SHF_ALLOC,
        got_segment->phdr->p_vaddr + got_offset,
        got_segment->phdr->p_offset + got_offset,
        (number_of_plt_entries * sizeof(void*)) + (sizeof(void*) * 3),
        0, 0, sizeof(void*), sizeof(void*)
    );

    write_section_to_file(got_section);
    destroy_elf_shdr(got_section);

    Elf_Shdr* plt_section;
    Elf64_Addr plt_offset;
    size_t plt_size;
    elf_segment_t *plt_segment = return_elf_segment(plt_addr);

    if (get_is_dyn_binary())
        plt_addr -= (Elf64_Addr)base_address;

    if (get_is_32_bit_binary())
        plt_size = (sizeof(plt_pattern_32_bit)*number_of_plt_entries) + 0x10;
    else
        plt_size = (sizeof(plt_pattern_64_bit)*number_of_plt_entries) + 0x10;
    
    
    plt_offset = plt_addr - plt_segment->phdr->p_vaddr;

    plt_section = create_elf_shdr(
        get_offset_in_shstrtable(".plt"),
        SHT_PROGBITS,
        SHF_ALLOC | SHF_EXECINSTR,
        plt_segment->phdr->p_vaddr + plt_offset,
        plt_segment->phdr->p_offset + plt_offset,
        plt_size,
        0, 0, 0x10, size_type_of_rel
    );

    write_section_to_file(plt_section);
    destroy_elf_shdr(plt_section);

    n_of_sections += 2;

    /* .rel.plt or .rela.plt */
    Elf_Shdr* rel_plt_section;
    char *name;
    int type = 0;
    elf_segment_t *rel_plt_segment;

    if (get_is_32_bit_binary())
    {
        if (size_type_of_rel == sizeof(Elf32_Rel))
        {
            type = SHT_REL;
            name = ".rel.plt";
        }
        else if (size_type_of_rel == sizeof(Elf32_Rela))
        {
            type = SHT_RELA;
            name = ".rela.plt";
        }
    }
    else
    {
        if (size_type_of_rel == sizeof(Elf64_Rel))
        {
            type = SHT_REL;
            name = ".rel.plt";
        }
        else if (size_type_of_rel == sizeof(Elf64_Rela))
        {
            type = SHT_RELA;
            name = ".rela.plt";
        }
    }

    // Retrieve information from Dynamic headers
    for (i = 0; i < get_dynamic_headers_size(); i++)
    {
        if (get_elf_dyn(i)->d_tag == DT_JMPREL)
        {   
            Elf64_Addr rel_plt_address = get_elf_dyn(i)->d_un.d_ptr;
            Elf64_Addr rel_offset;

            rel_plt_segment = return_elf_segment(rel_plt_address);

            if (get_is_dyn_binary())
                rel_plt_address -= (Elf64_Addr)base_address;

            rel_offset = rel_plt_address - rel_plt_segment->phdr->p_vaddr;

            rel_plt_section = create_elf_shdr(
                get_offset_in_shstrtable(name),
                type,
                SHF_ALLOC | SHF_INFO_LINK,
                rel_plt_segment->phdr->p_vaddr + rel_offset,
                rel_plt_segment->phdr->p_offset + rel_offset,
                size_type_of_rel * number_of_plt_entries,
                0, 0, sizeof(void*), size_type_of_rel
            );

            write_section_to_file(rel_plt_section);

            destroy_elf_shdr(rel_plt_section);

            break;
        }
    }
    n_of_sections += 1;
    
    
    /* .shstrtab */
    Elf_Shdr *shstrtab_section = create_elf_shdr(
        get_offset_in_shstrtable(".shstrtab"),
        SHT_STRTAB,
        0,
        0,
        shstrtable_offset,
        sizeof(shstrtable),
        0, 0, 1, 0
    );
    
    write_section_to_file(shstrtab_section);
    destroy_elf_shdr(shstrtab_section);

    n_of_sections += 1;

    // modify Elf_Ehdr values
    get_elf_ehdr()->e_shoff = shdr_offset;
    get_elf_ehdr()->e_shnum = n_of_sections;

    if (get_is_32_bit_binary())
        get_elf_ehdr()->e_shentsize = sizeof(Elf32_Shdr);
    else
        get_elf_ehdr()->e_shentsize = sizeof(Elf64_Shdr);

    get_elf_ehdr()->e_shstrndx = n_of_sections-1;

    write_elf_header_to_file(get_elf_ehdr());

    return 0;
}   

void *
retrieve_base_address(pid_t pid)
{
    char file_name[MAX_PATH], line[MAX_PATH / 2];
    Elf64_Addr base;
    char *start, *p;
    FILE *fd;
    int i;

    snprintf(file_name, MAX_PATH - 1, FILE_MAP, pid);

    log_info("Retrieving base address from '%s'", file_name);

    if ((fd = fopen(file_name, "r")) == NULL)
    {
        return (void *)NULL;
    }

    if (fgets(line, sizeof(line), fd) == 0)
    {
        return (void *)NULL;
    }

    for (i = 0, start = alloca(32), p = line; *p != '-'; i++, p++)
        start[i] = *p;
    start[i] = '\0';
    base = strtoul(start, NULL, 16);

    log_info("Base address is 0x%016lx", base);

    return (void *)base;
}

int fix_got(pid_t pid, void *address)
{
    int i;
    int ret_value;
    size_t memsize = sizeof(void *);
    Elf64_Addr value_to_fix;
    Elf64_Addr fixed_value;
    Elf64_Addr plt_addr_bk;

    log_info("Analyzing GOT in address 0x%016lx", address);

    // the entry of got has to move to third value
    // avoid GOT_ENTRY[0], GOT_ENTRY[1] and GOT_ENTRY[2]
    address = (void *)((Elf64_Addr)address + (memsize * 3));

    // if first function has not been used
    // the PLT value is in GOT yet.
    if ((ret_value = read_from_elf_segment((void *)&plt_addr, address, memsize)) < 0)
        return ret_value;

    if (is_in_elf_segment((void *)plt_addr)) // plt address is inside of binary
    {
        // add base address
        if (get_is_dyn_binary())
            plt_addr += (Elf64_Addr)base_address;

        log_info("Found PLT in address 0x%016lx", plt_addr);
    }
    else // plt address is already resolved.
    {
        log_info("PLT not found in first GOT entry, using heuristics");
        plt_addr = search_plt_in_elf_segment();

        if (plt_addr == 0)
        {
            log_info("PLT not found");
            return -2;
        }

        log_info("Found PLT in address 0x%016lx", plt_addr);
    }

    plt_addr_bk = plt_addr;

    log_info("Number of PLT entries %d", number_of_plt_entries);

    log_info("Patching GOT to PLT");
    for (i = 0; i < number_of_plt_entries; i++)
    {
        if (read_from_elf_segment((void *)&value_to_fix, address, memsize) < 0)
            return ret_value;

        // fix the value
        if (get_is_dyn_binary())
            fixed_value = plt_addr - (Elf64_Addr)base_address;
        else
            fixed_value = plt_addr;

        if (write_from_elf_segment((void *)address, &fixed_value, memsize) < 0)
            return ret_value;

        log_info("Patch #%d [0x%016x] -> [0x%016x]", i, value_to_fix, fixed_value);

        address = (void *)((Elf64_Addr)address + memsize);

        if (get_is_32_bit_binary())
            plt_addr = plt_addr + sizeof(plt_pattern_32_bit);
        else 
            plt_addr = plt_addr + sizeof(plt_pattern_64_bit);
    }

    // restore plt address for later
    // create the section
    plt_addr = plt_addr_bk - 0x10;

    return 0;
}

int is_in_elf_segment(void *addr)
{
    int i;
    Elf64_Addr a = (Elf64_Addr)addr;

    // check by rva
    if (get_is_dyn_binary())
        a -= (Elf64_Addr)base_address;

    for (i = 0; i < get_loadable_elf_phdr_number(); i++)
    {
        if (a >= segments[i].phdr->p_vaddr && a <= (segments[i].phdr->p_vaddr + segments[i].phdr->p_memsz))
        {
            return 1;
        }
    }

    return 0;
}

static elf_segment_t * 
return_elf_segment(Elf64_Addr addr)
{
    int i;
    Elf64_Addr a = (Elf64_Addr)addr;

    // check by rva
    if (get_is_dyn_binary())
        a -= (Elf64_Addr)base_address;

    for (i = 0; i < get_loadable_elf_phdr_number(); i++)
    {
        if (a >= segments[i].phdr->p_vaddr && a <= (segments[i].phdr->p_vaddr + segments[i].phdr->p_memsz))
        {
            return &segments[i];
        }
    }

    return NULL;
}

int read_from_elf_segment(void *dst, void *src, size_t memsz)
{
    int i = 0;
    elf_segment_t *segment = NULL;
    Elf64_Addr s = (Elf64_Addr)src;

    // check by rva
    if (get_is_dyn_binary())
        s -= (Elf64_Addr)base_address;

    for (i = 0; i < get_loadable_elf_phdr_number(); i++)
    {
        if (s >= segments[i].phdr->p_vaddr && s <= (segments[i].phdr->p_vaddr + segments[i].phdr->p_memsz))
        {
            segment = &segments[i];
            break;
        }
    }

    if (segment == NULL)
        return -2;

    Elf64_Addr offset = s - segment->phdr->p_vaddr;

    // copy in dst what is inside
    log_debug("Reading %d bytes from address 0x%lx (offset 0x%lx) from segment with vaddr 0x%lx", memsz, s, offset, segment->phdr->p_vaddr);

    memcpy(dst, (void *)(segment->byte + offset), memsz);

    return 0;
}

int write_from_elf_segment(void *dst, void *src, size_t memsz)
{
    int i = 0;
    elf_segment_t *segment = NULL;
    Elf64_Addr d = (Elf64_Addr)dst;

    // check by rva
    if (get_is_dyn_binary())
        d -= (Elf64_Addr)base_address;

    for (i = 0; i < get_loadable_elf_phdr_number(); i++)
    {
        if (d >= segments[i].phdr->p_vaddr && d <= (segments[i].phdr->p_vaddr + segments[i].phdr->p_memsz))
        {
            segment = &segments[i];
            break;
        }
    }

    if (segment == NULL)
        return -2;

    Elf64_Addr offset = d - segment->phdr->p_vaddr;

    log_debug("Writing %d bytes from 0x%lx (offset 0x%lx) from segment with vaddr 0x%lx", memsz, d, offset, segment->phdr->p_vaddr);
    memcpy((void *)(segment->byte + offset), src, memsz);

    return 0;
}

static int64_t
search_pattern_in_buffer(uint8_t *buffer, uint8_t *pattern, size_t buffer_size, size_t pattern_size)
{
    Elf64_Addr p1 = 0, p2 = 0;
    Elf64_Addr hits = 0;

    while (p2 < buffer_size)
    {
        for (p1 = 0; p1 < pattern_size; p1++)
        {
            if ((buffer + p2) >= (buffer + buffer_size))
                return -1;

            if ((pattern[p1] == buffer[p2]))
            {
                p2++;
                hits++;
            }

            else
            {
                break;
            }
        }

        if (hits == pattern_size)
        {
            return (p2 - pattern_size);
        }
        else
        {
            p2 -= hits;
            hits = 0;
        }

        p2++;
    }

    return -1;
}

Elf64_Addr
search_plt_in_elf_segment()
{
    int i = 0;
    int64_t offset_in_buffer;
    Elf64_Addr plt_addr;

    for (i = 0; i < get_loadable_elf_phdr_number(); i++)
    {
        if (get_is_32_bit_binary())
        {
            if ((offset_in_buffer = search_pattern_in_buffer(segments[i].byte, plt_pattern_32_bit, segments[i].phdr->p_memsz, 16)) == -1)
                continue;
        }
        else
        {
            if ((offset_in_buffer = search_pattern_in_buffer(segments[i].byte, plt_pattern_64_bit, segments[i].phdr->p_memsz, 16)) == -1)
                continue;
        }

        // if we get here, it means that we have found PLT
        plt_addr = segments[i].phdr->p_vaddr + offset_in_buffer;

        // now we return VAs
        if (get_is_dyn_binary())
            plt_addr += (Elf64_Addr)base_address;

        return plt_addr;
    }

    return 0;
}