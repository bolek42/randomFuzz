//gcc -o loader loader.c  -lelf -Wl,-Ttext-segment=0x1000000 -static

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#include <sys/procfs.h> //elf_prstatus
#include <sys/user.h> //user_regs_struct
#include <elf.h> //Elf64_Nhdr
#include <signal.h> //sigcontext
#include <sys/auxv.h> //auxv_t
#include <ucontext.h> //get_context()

#include <asm/prctl.h>
#include <sys/prctl.h>

#include "sys/ucontext.h"

#define round8(x) (((x)%8 == 0) ? (x) : (x)+8-(x)%8)

void *translate_ptr(void *elf_file, void *ptr) {
    int i;
    #ifdef __x86_64__
        Elf64_Ehdr *elf_hdr = elf_file;
        Elf64_Phdr *phdr = elf_file + elf_hdr->e_phoff;
    #endif
    
    for (i=0; i < elf_hdr->e_phnum ; i++)
        if (phdr[i].p_type == PT_LOAD) 
            if ((size_t)ptr >= phdr[i].p_vaddr && (size_t)ptr < phdr[i].p_vaddr + phdr[i].p_filesz)
                return elf_file + phdr[i].p_offset + (size_t)ptr - phdr[i].p_vaddr;

    return NULL;
}

void *get_phdr(void *elf_file, int phdr_type) {
    int i;
    void *note_ptr, *note_end;
    #ifdef __x86_64__
        Elf64_Ehdr *elf_hdr;
        Elf64_Phdr *phdr;
    #endif
    elf_hdr = elf_file;
    phdr = elf_file + elf_hdr->e_phoff;
    
    //parsing programheader
    for (i=0; i < elf_hdr->e_phnum ; i++)
        if (phdr[i].p_type == phdr_type) return &phdr[i];

    printf("PHDR %d not found!\n");
    exit(-1);
}

                                                         
void *get_note(void *elf_file, int note_type) {
    int i;
    void *note_ptr, *note_end;
    #ifdef __x86_64__
        Elf64_Ehdr *elf_hdr = elf_file;
        Elf64_Phdr *phdr = elf_file + elf_hdr->e_phoff;
        Elf64_Nhdr *note_hdr;
    #endif
    
    //parsing programheader
    phdr = get_phdr(elf_file, PT_NOTE);
    
    note_ptr = note_hdr = elf_file + phdr->p_offset;
    note_end = note_ptr + phdr->p_filesz;

    //iterate over all notes
    while (note_ptr < note_end) {
        note_hdr = note_ptr;
        if (note_hdr->n_type == note_type) return note_ptr;

        note_ptr += sizeof(*note_hdr);
        note_ptr += round8(note_hdr->n_namesz);
        note_ptr += round8(note_hdr->n_descsz);
        note_hdr = note_ptr;
    }
    return NULL;
}

void *get_auvx(void *core_file, int auvx_type) {
    #ifdef __x86_64__
        Elf64_Nhdr *note_hdr;
        Elf64_auxv_t *auvx_entry;
        Elf64_auxv_t *auvx_end;
    #endif

    note_hdr = get_note(core_file, NT_AUXV);
    if (!note_hdr) {
        printf("NT_AUXV not Found!\n");
        return NULL;
    }

    auvx_entry = (void *)note_hdr + sizeof(*note_hdr) + round8(note_hdr->n_namesz);
    auvx_end = (void *)auvx_entry + note_hdr->n_descsz;
    for (;auvx_entry < auvx_end; auvx_entry++)
            if (auvx_type == auvx_entry->a_type)
                return (void *)auvx_entry->a_un.a_val;

    return NULL; //TODO error handling
}


//  __  __       _       
// |  \/  | __ _(_)_ __  
// | |\/| |/ _` | | '_ \ 
// | |  | | (_| | | | | |
// |_|  |_|\__,_|_|_| |_|

void *load_file(char *fname, int *size){
    void *buf = NULL;
    int fd = open(fname, O_RDONLY, 0);

    *size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    buf = malloc(*size);
    read(fd, buf,  *size);
    close(fd);

    return buf;
}


int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Gets exec filename from corefile\n");
        printf("Usage: %s file.core\n", argv[0]);
        exit(1);
    }

    int core_size;
    void *core_file = load_file(argv[1], &core_size);
    char *exec_fname = translate_ptr(core_file, get_auvx(core_file, AT_EXECFN));
    printf("%s", exec_fname);
}
