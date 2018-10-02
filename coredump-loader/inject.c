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

void *load_file(char *fname, int *size){
    void *buf = NULL;
    int fd = open(fname, O_RDONLY, 0);

    *size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    //printf("Loading %s (%d bytes)\n", fname, *size);
    buf = malloc(*size);
    read(fd, buf,  *size);
    close(fd);

    return buf;
}

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

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Inject shellcode into main function\n");
        printf("Usage: %s elf_file shellcode.bin\n", argv[0]);
        exit(1);
    }

    printf("Patching %s with %s\n", argv[1], argv[2]);

    int trampolin_size, core_size, exec_size;
    void *exec_file = load_file(argv[1], &exec_size);
    void *trampolin_file = load_file(argv[2], &trampolin_size);
    #ifdef __x86_64__
        Elf64_Ehdr *exec_hdr = exec_file;
        Elf64_Phdr *exec_phdr = exec_file + exec_hdr->e_phoff;
        Elf64_Shdr *shdr = exec_file + exec_hdr->e_shoff;
        Elf64_Sym *sym = NULL;
    #endif

    printf("Replacing main\n");
    int src = 0;
    int dst = 0;
    int i,j;

    void *main = NULL;
    for (i=0; i < exec_hdr->e_shnum; i++) {
        if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
            printf("Found Symbol Table\n");
            sym = exec_file + shdr[i].sh_offset;
            char *str = exec_file + shdr[shdr[i].sh_link].sh_offset;
            for (j=0; j < shdr[i].sh_size/sizeof(*sym); j++) {
                //printf("%d, %p %s\n", j, sym[j].st_value, str + sym[j].st_name);
                if (strcmp("main", str + sym[j].st_name) == 0) {
                    printf("found main @ %p\n", sym[j].st_value);
                    main = sym[j].st_value;
                }
            }
        }
    }

    if (!main) {
        printf("error main not found\n");
        exit(1);
    }

    printf("patching main() with %d bytes\n", trampolin_size);
    memcpy(translate_ptr(exec_file, main), trampolin_file, trampolin_size);
    
    //save patched file
    FILE * f = fopen("./patched.elf", "w");
    if (!f) {perror("fopen"); exit(1);}
    fwrite(exec_file, 1, exec_size, f);
    fclose(f);
    printf("Done\n");
}
