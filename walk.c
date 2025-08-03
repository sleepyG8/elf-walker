#include <fcntl.h>     
#include <stdio.h>     

///////////////////////////////////////////////////////////////////
//         Reading elfs from disk using raw parsing              //
///////////////////////////////////////////////////////////////////

// gcc walk.c -o walk

// Sleepy 2025

typedef unsigned short      uint16_t;  
typedef unsigned int        uint32_t;  
typedef unsigned long long  uint64_t;  

// structs who needs elf.h
typedef struct {
    unsigned char e_ident[16]; // Magic number and other info
    uint16_t e_type;           // Object file type
    uint16_t e_machine;        // Architecture
    uint32_t e_version;        // Object file version
    uint64_t e_entry;          // Entry point virtual address
    uint64_t e_phoff;          // Program header table file offset
    uint64_t e_shoff;          // Section header table file offset
    uint32_t e_flags;          // Processor-specific flags
    uint16_t e_ehsize;         // ELF header size in bytes
    uint16_t e_phentsize;      // Program header table entry size
    uint16_t e_phnum;          // Program header table entry count
    uint16_t e_shentsize;      // Section header table entry size
    uint16_t e_shnum;          // Section header table entry count
    uint16_t e_shstrndx;       // Section header string table index
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;    // Segment type
    uint32_t p_flags;   // Segment flags
    uint64_t p_offset;  // Offset in file
    uint64_t p_vaddr;   // Virtual address in memory
    uint64_t p_paddr;   // Physical address (unused)
    uint64_t p_filesz;  // Size of segment in file
    uint64_t p_memsz;   // Size of segment in memory
    uint64_t p_align;   // Alignment
} Elf64_Phdr;

typedef struct {
    uint32_t sh_name;      // Section name (index into string table)
    uint32_t sh_type;      // Section type
    uint64_t sh_flags;     // Section attributes
    uint64_t sh_addr;      // Virtual address in memory
    uint64_t sh_offset;    // Offset in file
    uint64_t sh_size;      // Size of section
    uint32_t sh_link;      // Link to another section
    uint32_t sh_info;      // Additional section information
    uint64_t sh_addralign; // Section alignment
    uint64_t sh_entsize;   // Entry size if section holds table
} Elf64_Shdr;

typedef uint64_t Elf64_Addr;   // Unsigned program address
typedef uint16_t Elf64_Half;   // Unsigned medium integer
typedef uint64_t Elf64_Off;    // Unsigned file offset
typedef int      Elf64_Sword;  // Signed 32-bit integer
typedef uint32_t Elf64_Word;   // Unsigned 32-bit integer
typedef int long long  Elf64_Sxword; // Signed 64-bit integer
typedef uint64_t Elf64_Xword;  // Unsigned 64-bit integer


typedef struct {
    Elf64_Sxword d_tag;     // Dynamic entry type (e.g., DT_SYMTAB, DT_STRTAB)
    union {
        Elf64_Xword d_val;  // Integer value
        Elf64_Addr  d_ptr;  // Program virtual address
    } d_un;
} Elf64_Dyn;

typedef struct {
    Elf64_Word    st_name;   // Index into the string table
    unsigned char st_info;   // Symbol type and binding
    unsigned char st_other;  // Visibility
    Elf64_Half    st_shndx;  // Section index
    Elf64_Addr    st_value;  // Symbol value (e.g., address)
    Elf64_Xword   st_size;   // Size of the symbol
} Elf64_Sym;

#define ELF64_ST_BIND(val)   ((val) >> 4)
#define ELF64_ST_TYPE(val)   ((val) & 0xf)

#define DT_NULL     0   // Marks end of dynamic array
#define DT_NEEDED   1   // Name of needed library
#define DT_PLTRELSZ 2   // Size of relocation entries for PLT
#define DT_PLTGOT   3   // Address of PLT/GOT
#define DT_HASH     4   // Address of symbol hash table
#define DT_STRTAB   5   // Address of string table
#define DT_SYMTAB   6   // Address of symbol table
#define DT_RELA     7   // Address of relocation table
#define DT_RELASZ   8   // Size of relocation table
#define DT_RELAENT  9   // Size of each relocation entry
#define DT_STRSZ    10  // Size of string table
#define DT_SYMENT   11  // Size of each symbol table entry
#define DT_INIT     12  // Address of initialization function
#define DT_FINI     13  // Address of termination function
#define DT_SONAME   14  // Name of shared object
#define DT_RPATH    15  // Library search path
#define DT_SYMBOLIC 16  // Symbol resolution behavior
#define DT_REL      17  // Address of REL relocation table
#define DT_RELSZ    18  // Size of REL relocation table
#define DT_RELENT   19  // Size of each REL entry
#define DT_PLTREL   20  // Type of relocation for PLT
#define DT_DEBUG    21  // Debugging info
#define DT_TEXTREL  22  // Indicates text relocations
#define DT_JMPREL   23  // Address of PLT relocations

// like VAtoRVA but elf style gets actual offset 
size_t vaddr_to_offset(Elf64_Addr vaddr, Elf64_Phdr* phdr, int phnum) {
    for (int i = 0; i < phnum; i++) {
        if (phdr[i].p_type == 1 &&
            vaddr >= phdr[i].p_vaddr &&
            vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
            return phdr[i].p_offset + (vaddr - phdr[i].p_vaddr);
        }
    }
    return 0;
}


int main(int argc, char* argv[]) {

const char* filepath = argv[1];
    
// Open the file 
int fd = open(filepath, O_RDONLY);
if (fd < 0) return 1;

size_t size = lseek(fd, 0, SEEK_END);
lseek(fd, 0, SEEK_SET);

char* buff = malloc(size);
read(fd, buff, size);

// Header / check elf
Elf64_Ehdr* hdr = (Elf64_Ehdr*)buff;

if (hdr->e_ident[0] == 0x7F &&
hdr->e_ident[1] == 'E' &&
hdr->e_ident[2] == 'L' &&
hdr->e_ident[3] == 'F') {
// elf
} else {
    return 1;
}
    
// phdr
Elf64_Phdr* phdr = (Elf64_Phdr*)(buff + hdr->e_phoff);

for (int i = 0; i < hdr->e_phnum; i++) {

        // Check for export entry only
    if (phdr[i].p_type != 2) continue;

        // Entry stuff
    Elf64_Dyn* dyn = (Elf64_Dyn*)(buff + phdr[i].p_offset);

    Elf64_Addr symtab_offset = 0;
    Elf64_Addr strtab_offset = 0;
    Elf64_Xword syment_size = sizeof(Elf64_Sym);

// Setting symtab strtab and syment size
for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
    if (dyn[i].d_tag == DT_SYMTAB) {
        symtab_offset = dyn[i].d_un.d_ptr;
    } else if (dyn[i].d_tag == DT_STRTAB) {
        strtab_offset = dyn[i].d_un.d_ptr;
    } else if (dyn[i].d_tag == DT_SYMENT) {
        syment_size = dyn[i].d_un.d_val;
    }
}

printf("syment size: %lu\n", syment_size);
printf("strtab_offset %x\n", strtab_offset);
printf("symtab %lu\n", symtab_offset);

// Export time
// vaddr_to_offset gets actual RVA like on PE files for windows
// symtab is the offset of the symbol directory
Elf64_Sym* symtab = (Elf64_Sym*)(buff + vaddr_to_offset(symtab_offset, phdr, hdr->e_phnum));

// string offset inside of symtab
char* strtab = (char*)(buff + vaddr_to_offset(strtab_offset, phdr, hdr->e_phnum));

if (symtab == 0 || strtab == 0) {
    fprintf(stderr, "Failed to resolve offsets\n");
    return 1;
}

for (size_t i = 0; i < 1000; i++) {
    // getting the symbol from symtab directory
    Elf64_Sym* sym = (Elf64_Sym*)((char*)symtab + i * syment_size);

    // strtab + str loaction = actual string in memory
    const char* name = strtab + sym->st_name;
    if (name == NULL) break;
    printf("%s at 0x%lx\n", name, sym->st_value);
}

}


    return 0;
}
