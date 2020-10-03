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
#define round_n(x,n) (((x)%(n) == 0) ? (x) : (x)+(n)-(x)%(n))

void sigret(void *arg, void *fs_base) { asm("push %rdi"); arch_prctl(ARCH_SET_FS, fs_base); asm("pop %rdi; mov %fs:0x30,%rdx; mov %rdi, %rsp; mov $0xf, %rax; syscall");}
//void sigret(void *arg) { asm("push %rdi"); arch_prctl(ARCH_SET_FS, 0x7ffff7f6c500); asm("pop %rdi; mov %fs:0x30,%rdx; mov %rdi, %rsp; mov $0xf, %rax; syscall");}


void hexdump(char *buf, int size) {int i; for(i=0; i<size; i++) printf("%02x ", buf[i]&0xff); printf("\n");}

void *mmap_handler(void *addr, size_t len, int prot, int flags, int fildes, off_t off) {
    static void **maps = NULL;
    static int n_maps = 0;
    int i;

    for (i = 0; i < n_maps; i++) {
        if (maps[i] == addr) {
            printf("\t%p already mapped, using munmap\n", addr);
            munmap(addr, len);
            //mprotect(addr, len, prot);
            //return addr;
        }
    }

    void *ret = mmap(addr, len, prot, flags, fildes, off);
    if (ret+1 == NULL) {perror("mmap"); exit(1);}

    //tracking maps
    n_maps ++;
    maps = realloc(maps, n_maps * sizeof(void *));
    maps[n_maps-1] = ret;

    return addr;
}

//  ____                                        _   _                _           
// |  _ \ _ __ ___   __ _ _ __ __ _ _ __ ___   | | | | ___  __ _  __| | ___ _ __ 
// | |_) | '__/ _ \ / _` | '__/ _` | '_ ` _ \  | |_| |/ _ \/ _` |/ _` |/ _ \ '__|
// |  __/| | | (_) | (_| | | | (_| | | | | | | |  _  |  __/ (_| | (_| |  __/ |   
// |_|   |_|  \___/ \__, |_|  \__,_|_| |_| |_| |_| |_|\___|\__,_|\__,_|\___|_|   
//                  |___/                                                        

void map_core_phdr(void *elf_file) {
    int i;
    #ifdef __x86_64__
        Elf64_Ehdr *elf_hdr = elf_file;
        Elf64_Phdr *phdr = elf_file + elf_hdr->e_phoff;
    #endif
    
    printf("Loading core program headers\n");
    //parsing programheader
    for (i=0; i < elf_hdr->e_phnum ; i++) {
        //loading memory sections
        if (phdr[i].p_type == PT_LOAD) {
            printf("\tloading %p (%8p bytes, offset %8p ", phdr[i].p_vaddr, phdr[i].p_memsz, phdr[i].p_offset);
            if (phdr[i].p_memsz < phdr[i].p_filesz)
                printf("phdr.p_memsz < phdr.p_filesz\n");

            //get memory protection
            int prot = 0;
            if (phdr[i].p_flags & PF_R) prot |= PROT_READ, printf("r"); else printf("-");
            if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE, printf("w"); else printf("-");
            if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC, printf("x");  else printf("-");
            printf(")\n");

            //map memory and copy data
            void *ret = mmap_handler((void *)phdr[i].p_vaddr, phdr[i].p_memsz, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (ret) memcpy(ret, elf_file + phdr[i].p_offset, phdr[i].p_filesz);
            mprotect((void *)phdr[i].p_vaddr, phdr[i].p_memsz, prot);
        }
    }
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

void map_phdr(void *elf_file, void *offset) {
    int i;
    #ifdef __x86_64__
        Elf64_Ehdr *elf_hdr = elf_file;
        Elf64_Phdr *phdr = elf_file + elf_hdr->e_phoff;
    #endif
    
    printf("Mapping program headers\n");
    //parsing programheader
    for (i=0; i < elf_hdr->e_phnum ; i++) {
        //loading memory sections
        if (phdr[i].p_type == PT_LOAD) {
            printf("\tloading %p (%8p bytes, offset %8p ", phdr[i].p_vaddr+(size_t)offset, phdr[i].p_memsz, phdr[i].p_offset);
            if (phdr[i].p_memsz < phdr[i].p_filesz)
                printf("phdr.p_memsz < phdr.p_filesz\n");

            //get memory protection
            int prot = 0;
            if (phdr[i].p_flags & PF_R) prot |= PROT_READ, printf("r"); else printf("-");
            if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE, printf("w"); else printf("-");
            if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC, printf("x");  else printf("-");
            printf(")\n");

            printf("%p\n", offset);
            printf("%p\n", (void *)phdr[i].p_vaddr+(size_t)offset);
            //map memory and copy data
            if (phdr[i].p_vaddr & (getpagesize()-1)) {
                printf("Invalid alignment\n");
            }
            else {
                void *ret = mmap_handler((void *)phdr[i].p_vaddr+(size_t)offset, phdr[i].p_memsz, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                if (ret) memcpy(ret, elf_file + phdr[i].p_offset, phdr[i].p_filesz);
            }
            mprotect((void *)phdr[i].p_vaddr+(size_t)offset, phdr[i].p_memsz, prot);
        }
    }
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

//  _   _       _         _   _                _           
// | \ | | ___ | |_ ___  | | | | ___  __ _  __| | ___ _ __ 
// |  \| |/ _ \| __/ _ \ | |_| |/ _ \/ _` |/ _` |/ _ \ '__|
// | |\  | (_) | ||  __/ |  _  |  __/ (_| | (_| |  __/ |   
// |_| \_|\___/ \__\___| |_| |_|\___|\__,_|\__,_|\___|_|   

void *print_notes(void *elf_file) {
    int i;
    void *note_ptr, *note_end;
    #ifdef __x86_64__
        Elf64_Phdr *phdr;
        Elf64_Nhdr *note_hdr;
    #endif
    phdr = get_phdr(elf_file, PT_NOTE);
    
    note_ptr = note_hdr = elf_file + phdr->p_offset;
    note_end = note_ptr + phdr->p_filesz;

    //iterate over all notes
    while (note_ptr < note_end) {
        note_hdr = note_ptr;
        printf("Found Note %p %s\n", note_hdr->n_type, note_ptr + sizeof(*note_hdr));

        hexdump(note_ptr + sizeof(*note_hdr) + round8(note_hdr->n_namesz), note_hdr->n_descsz);

        note_ptr += sizeof(*note_hdr);
        note_ptr += round8(note_hdr->n_namesz);
        note_ptr += round8(note_hdr->n_descsz);
    }
    return NULL;
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

//FIXME
struct sigret_ctx {
    char pad[40];
    struct sigcontext regs;
};

void load_prstatus(void *core_file, struct sigret_ctx *sigret_ctx) {
    #ifdef __x86_64__
        Elf64_Nhdr *note_hdr;
    #endif
    note_hdr = get_note(core_file, NT_PRSTATUS);
    if (!note_hdr) {
        printf("NT_PRSTATUS not Found!\n");
        exit(-1);
    }
    printf("Loading NT_PRSTATUS\n");

    //prstatus header
    struct elf_prstatus *prstatus;
    prstatus = (void *)note_hdr + sizeof(*note_hdr) + round8(note_hdr->n_namesz);
    struct user_regs_struct *regs = (struct user_regs_struct*)&prstatus->pr_reg;

    //sigret header
    //struct sigcontext *regsig = &sigret_ctx->uc_mcontext;

    #define reg(r) sigret_ctx->regs.r = regs->r; printf("\t"#r": %p\n", regs->r);
    #ifdef __x86_64__
        reg(rax);
        reg(rbx);
        reg(rcx);
        reg(rdx);
        reg(rdi);
        reg(rsi);
        reg(r8);
        reg(r9);
        reg(r10);
        reg(r11);
        reg(r12);
        reg(r13);
        reg(r14);
        reg(r15);
        reg(rbp);
        reg(rsp);
        reg(rip);
        reg(eflags);
        reg(cs);
        reg(gs);
        reg(fs);
    #endif
}


void load_mapped_files(void *core_file) {
    int i;
    #ifdef __x86_64__
        Elf64_Nhdr *note_hdr;
    #endif

    note_hdr = get_note(core_file, NT_FILE);
    if (!note_hdr) {
        printf("NT_FILE not Found!\n");
        return;
    }

    void **maps_start = (void *)note_hdr + sizeof(*note_hdr) + round8(note_hdr->n_namesz);
    size_t n_files = (size_t) *maps_start;
    printf("Found %d mapped files\n", n_files);

    char *fname = (char *)&maps_start[2 + n_files*3];
    for (i=0; i < n_files; i++) {
        void *start = maps_start[i*3 + 2];
        void *stop = maps_start[i*3 + 3];
        size_t offset = (size_t)maps_start[i*3 + 4];
        printf("\tMapping %p %p %p %s\n", start, stop, offset, fname);

        int map_fd = open(fname, O_RDONLY, 0);
        mmap_handler(start, stop-start, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, map_fd, offset);
        close(map_fd);

        fname += strlen(fname) + 1;
    }
}

//     __ _ _   ___   ____  __
//    / _` | | | \ \ / /\ \/ /
//   | (_| | |_| |\ V /  >  < 
//    \__,_|\__,_| \_/  /_/\_\

char *auvx_to_a(int type) {
    switch(type) {
        case AT_NULL:
            return "AT_NULL";
        case AT_IGNORE:
            return "AT_IGNORE";
        case AT_EXECFD:
            return "AT_EXECFD";
        case AT_PHDR:
            return "AT_PHDR";
        case AT_PHENT:
            return "AT_PHENT";
        case AT_PHNUM:
            return "AT_PHNUM";
        case AT_PAGESZ:
            return "AT_PAGESZ";
        case AT_BASE:
            return "AT_BASE";
        case AT_FLAGS:
            return "AT_FLAGS";
        case AT_ENTRY:
            return "AT_ENTRY";
        case AT_NOTELF:
            return "AT_NOTELF";
        case AT_UID:
            return "AT_UID";
        case AT_EUID:
            return "AT_EUID";
        case AT_GID:
            return "AT_GID";
        case AT_EGID:
            return "AT_EGID";
        case AT_CLKTCK:
            return "AT_CLKTCK";
        case AT_PLATFORM:
            return "AT_PLATFORM";
        case AT_HWCAP:
            return "AT_HWCAP";
        case AT_FPUCW:
            return "AT_FPUCW";
        case AT_DCACHEBSIZE:
            return "AT_DCACHEBSIZE";
        case AT_ICACHEBSIZE:
            return "AT_ICACHEBSIZE";
        case AT_UCACHEBSIZE:
            return "AT_UCACHEBSIZE";
        case AT_IGNOREPPC:
            return "AT_IGNOREPPC";
        case AT_SECURE:
            return "AT_SECURE";
        case AT_BASE_PLATFORM:
            return "AT_BASE_PLATFORM";
        case AT_RANDOM:
            return "AT_RANDOM";
        case AT_HWCAP2:
            return "AT_HWCAP2";
        case AT_EXECFN:
            return "AT_EXECFN";
        case AT_SYSINFO:
            return "AT_SYSINFO";
        case AT_SYSINFO_EHDR:
            return "AT_SYSINFO_EHDR";
        case AT_L1I_CACHESHAPE:
            return "AT_L1I_CACHESHAPE";
        case AT_L1D_CACHESHAPE:
            return "AT_L1D_CACHESHAPE";
        case AT_L2_CACHESHAPE:
            return "AT_L2_CACHESHAPE";
        case AT_L3_CACHESHAPE:
            return "AT_L3_CACHESHAPE";
        case AT_L1I_CACHESIZE:
            return "AT_L1I_CACHESIZE";
        case AT_L1I_CACHEGEOMETRY:
            return "AT_L1I_CACHEGEOMETRY";
        case AT_L1D_CACHESIZE:
            return "AT_L1D_CACHESIZE";
        case AT_L1D_CACHEGEOMETRY:
            return "AT_L1D_CACHEGEOMETRY";
        case AT_L2_CACHESIZE:
            return "AT_L2_CACHESIZE";
        case AT_L2_CACHEGEOMETRY:
            return "AT_L2_CACHEGEOMETRY";
        case AT_L3_CACHESIZE:
            return "AT_L3_CACHESIZE";
        case AT_L3_CACHEGEOMETRY:
            return "AT_L3_CACHEGEOMETRY";
    }
}
                             
void print_auvx(void *core_file) {
    #ifdef __x86_64__
        Elf64_Nhdr *note_hdr;
        Elf64_auxv_t *auvx_entry;
        Elf64_auxv_t *auvx_end;
    #endif

    note_hdr = get_note(core_file, NT_AUXV);
    if (!note_hdr) {
        printf("NT_AUXV not Found!\n");
        return;
    }

    printf("Dumping NT_AUXV\n");
    auvx_entry = (void *)note_hdr + sizeof(*note_hdr) + round8(note_hdr->n_namesz);
    auvx_end = (void *)auvx_entry + note_hdr->n_descsz;
    for (;auvx_entry < auvx_end; auvx_entry++) {
                printf("\t%s: %p\n", auvx_to_a(auvx_entry->a_type), auvx_entry->a_un.a_val);
    }

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
    //printf("Loading %s (%d bytes)\n", fname, *size);
    buf = malloc(*size);
    read(fd, buf,  *size);
    close(fd);

    return buf;
}

extern void __init_tls(size_t *aux);
void load_elf(char *fname, void *offset) {
    printf("Loading %s at offset %p\n", fname, offset);
    int elf_size;
    void *elf_file = load_file(fname, &elf_size);

    int i;
    #ifdef __x86_64__
        Elf64_Ehdr *elf_hdr = elf_file;
        Elf64_Phdr *phdr = elf_file + elf_hdr->e_phoff;
    #endif
    
    print_auvx(elf_file);
    printf("Mapping program headers\n");
    for (i=0; i < elf_hdr->e_phnum ; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            printf("\tloading %p (%8p bytes, offset %8p ", phdr[i].p_vaddr+(size_t)offset, phdr[i].p_memsz, phdr[i].p_offset);
            if (phdr[i].p_memsz < phdr[i].p_filesz)
                printf("phdr.p_memsz < phdr.p_filesz\n");

            //get memory protection
            int prot = 0;
            if (phdr[i].p_flags & PF_R) prot |= PROT_READ, printf("r"); else printf("-");
            if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE, printf("w"); else printf("-");
            if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC, printf("x");  else printf("-");
            printf(")\n");

            //map memory and copy data
            if (phdr[i].p_vaddr & (getpagesize()-1)) {
                printf("\tInvalid alignment\n");
            }
            else {
                int fd = open(fname, O_RDONLY, 0);
                //mmap_handler((void *)phdr[i].p_vaddr+(size_t)offset, phdr[i].p_memsz, prot, MAP_PRIVATE, fd, phdr[i].p_offset);
                mmap_handler((void *)phdr[i].p_offset+(size_t)offset, phdr[i].p_memsz, prot, MAP_PRIVATE, fd, phdr[i].p_offset);
                close(fd);
            }

        }
        else if (phdr[i].p_type == PT_TLS) {
            printf("Found TLS Section %p (%8p bytes, offset %8p ", phdr[i].p_vaddr, phdr[i].p_memsz, phdr[i].p_offset);
            int prot = 0;
            if (phdr[i].p_flags & PF_R) prot |= PROT_READ, printf("r"); else printf("-");
            if (phdr[i].p_flags & PF_W) prot |= PROT_WRITE, printf("w"); else printf("-");
            if (phdr[i].p_flags & PF_X) prot |= PROT_EXEC, printf("x");  else printf("-");
            printf(")\n");

            printf("Target FS Base: 0x4aa880\n");

            hexdump(elf_file + phdr[i].p_offset, phdr[i].p_filesz);
          }
    }
}

void load_mapped_libs(void *core_file) {
    int i;
    #ifdef __x86_64__
        Elf64_Nhdr *note_hdr;
    #endif

    note_hdr = get_note(core_file, NT_FILE);
    if (!note_hdr) {
        printf("NT_FILE not Found!\n");
        return;
    }

    void **maps_start = (void *)note_hdr + sizeof(*note_hdr) + round8(note_hdr->n_namesz);
    size_t n_files = (size_t) *maps_start;
    printf("Found %d mapped files\n", n_files);

    char *fname = (char *)&maps_start[2 + n_files*3];
    for (i=0; i < n_files; i++) {
        void *start = maps_start[i*3 + 2];
        void *stop = maps_start[i*3 + 3];
        size_t offset = (size_t)maps_start[i*3 + 4];
        printf("\tMapping %p %p %p %s\n", start, stop, offset, fname);
        load_elf(fname, start-offset - 0x1000);

        //int map_fd = open(fname, O_RDONLY, 0);
        //mmap_handler(start, stop-start, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, map_fd, offset);
        //close(map_fd);

        fname += strlen(fname) + 1;
    }
}

void load_corefile(char *fname, char *fs_base) {
    int core_size, fd;
    void *core_file = load_file(fname, &core_size);
    #ifdef __x86_64__
        Elf64_Ehdr *core_elf_hdr = core_file;
    #endif

    print_notes(core_file);
    print_auvx(core_file);
    //load_mapped_files(core_file);
    munmap(NULL,0);

    //Loading Binary
    char *exec_fname = translate_ptr(core_file, get_auvx(core_file, AT_EXECFN));
    printf("Exec filename: %s\n", exec_fname);
    void *binary_base = get_auvx(core_file, AT_PHDR) - sizeof(*core_elf_hdr);
    load_elf(exec_fname, binary_base);

    //mapping interpreter
    void *ld_base = get_auvx(core_file, AT_BASE);
    if (ld_base){
        printf("Found interpreter %p\n", ld_base);
        load_elf("/usr/lib/ld-2.28.so", ld_base);
    //    load_elf("/usr/lib/libc-2.28.so", (void *)0x00007ffff7da7000);
    }
    load_mapped_libs(core_file);

    //ucontext_t ctx; //XXX
    struct sigret_ctx sigret_ctx;
    memset(&sigret_ctx, 0x00, sizeof(sigret_ctx));
    load_prstatus(core_file, &sigret_ctx);
    map_core_phdr(core_file);

    printf("Sigreturn...\n");
    sigret(&sigret_ctx, strtol(fs_base, NULL, 0));
    
}

#define stack_addr 0xdead0000
int main(int argc, char **argv) {
    void *stack_pivot = mmap(stack_addr, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    asm ("mov %0, %%rsp; add $0x1000, %%rsp": "+r" (stack_pivot) ::"cc");
    load_corefile(argv[1], argv[2]);
    //int i;
    //if (argc == 2) {
    //    printf("Patching");

    //    int self_size, core_size, exec_size;
    //    void *self_file = load_file("hello", &self_size);
    //    void *core_file = load_file(argv[1], &core_size);
    //    #ifdef __x86_64__
    //        Elf64_Ehdr *core_hdr = core_file;
    //        Elf64_Ehdr *self_hdr = self_file;
    //        Elf64_Ehdr *exec_hdr;
    //    #endif

    //    //Loading Binary
    //    char *exec_fname = translate_ptr(core_file, get_auvx(core_file, AT_EXECFN));
    //    printf("Exec filename: %s\n", exec_fname);
    //    void *exec_file = load_file(exec_fname, &exec_size);
    //    exec_hdr = exec_file;

    //    printf("Elf HDR Size: %p\n", exec_hdr->e_ehsize);
    //    printf("PHDR Offset: %d Size: %d Count: %d\n", exec_hdr->e_phoff, exec_hdr->e_phentsize, exec_hdr->e_phnum);
    //    printf("SHDR Offset: %d Size: %d Count: %d\n", exec_hdr->e_shoff, exec_hdr->e_shentsize, exec_hdr->e_shnum);


    //    printf("Add PHDRs\n");
    //    #ifdef __x86_64__
    //        Elf64_Phdr *self_phdr = self_file + self_hdr->e_phoff;
    //        Elf64_Phdr *exec_phdr = exec_file + exec_hdr->e_phoff;
    //    #endif

    //    void *page_backup = malloc(getpagesize());
    //    memcpy(page_backup, exec_file, getpagesize());

    //    printf("Replacing .text\n");
    //    int src = 0;
    //    int dst = 0;
    //    for (src=0; src < self_hdr->e_phnum; src++) 
    //        if (self_phdr[src].p_type == PT_LOAD && self_phdr[src].p_flags & PF_X) break;

    //    for (dst=0; dst < exec_hdr->e_phnum; dst++) 
    //        if (exec_phdr[dst].p_type == PT_LOAD && exec_phdr[dst].p_flags & PF_X) break;

    //    memcpy(exec_file + exec_phdr[dst].p_offset, self_file + self_phdr[src].p_offset, self_phdr[src].p_filesz);
    //    
    //    //printf("Loading core program headers\n");
    //    //exec_size = round_n(exec_size, getpagesize());
    //    //exec_file = realloc(exec_file, exec_size);
    //    //exec_hdr = exec_file;
    //    //exec_phdr = exec_file + exec_hdr->e_phoff;
    //    //for (i=0; i < self_hdr->e_phnum -5; i++) {
    //    //    //loading memory sections
    //    //    if (self_phdr[i].p_type == PT_LOAD) {
    //    //        exec_size = round_n(exec_size, getpagesize());
    //    //        int new_offset = exec_size;
    //    //        printf("%d %p\n", i, new_offset);
    //    //        exec_size += self_phdr[i].p_filesz;
    //    //        exec_size = round_n(exec_size, getpagesize());
    //    //        exec_file = realloc(exec_file, exec_size);
    //    //        exec_hdr = exec_file;
    //    //        exec_phdr = exec_file + exec_hdr->e_phoff;
    //    //        memcpy(exec_file + new_offset, self_file + self_phdr[i].p_offset, self_phdr[i].p_filesz);

    //    //        exec_phdr[exec_hdr->e_phnum].p_type = PT_LOAD;
    //    //        exec_phdr[exec_hdr->e_phnum].p_flags = self_phdr[i].p_flags;
    //    //        exec_phdr[exec_hdr->e_phnum].p_offset = new_offset;
    //    //        exec_phdr[exec_hdr->e_phnum].p_vaddr = self_phdr[i].p_vaddr;
    //    //        exec_phdr[exec_hdr->e_phnum].p_paddr = self_phdr[i].p_paddr;
    //    //        exec_phdr[exec_hdr->e_phnum].p_filesz = self_phdr[i].p_filesz;
    //    //        exec_phdr[exec_hdr->e_phnum].p_memsz = self_phdr[i].p_memsz;
    //    //        exec_phdr[exec_hdr->e_phnum].p_align = self_phdr[i].p_align;

    //    //        exec_hdr->e_phnum ++;

    //    //        printf("\tAdded %p (%8p bytes, offset %8p ", self_phdr[i].p_vaddr, self_phdr[i].p_memsz, new_offset);
    //    //        if (self_phdr[i].p_flags & PF_R) printf("r"); else printf("-");
    //    //        if (self_phdr[i].p_flags & PF_W) printf("w"); else printf("-");
    //    //        if (self_phdr[i].p_flags & PF_X) printf("x"); else printf("-");
    //    //        printf(")\n");
    //    //        printf("%p\n", exec_size);
    //    //    }
    //    //}
    //    //exec_hdr->e_phnum = 8;

    //    //int offset = 0x800;//exec_hdr->e_phoff + (exec_hdr->e_phentsize * exec_hdr->e_phnum);
    //    //printf("Move Section Headers to offset %d\n", offset);
    //    //Elf64_Shdr *shdr = exec_file + exec_hdr->e_shoff;
    //    //for (i=0; i < exec_hdr->e_shnum; i++) {
    //    //    if (shdr[i].sh_offset < getpagesize() && shdr[i].sh_offset != 0) {
    //    //        printf("\tSection Size %d moved from %d => %d\n", shdr[i].sh_size, shdr[i].sh_offset, offset);
    //    //        memset(exec_file + shdr[i].sh_offset, 0x00, shdr[i].sh_size);
    //    //        memcpy(exec_file + offset, page_backup + shdr[i].sh_offset, shdr[i].sh_size);
    //    //        shdr[i].sh_addr += offset - shdr[i].sh_offset;
    //    //        shdr[i].sh_offset = offset;
    //    //        offset += round8(shdr[i].sh_size);
    //    //    }
    //    //}

    //    //save patched file
    //    FILE * f = fopen("patched.elf", "w");
    //    fwrite(exec_file, 1, exec_size, f);
    //    fclose(f);


    //}
    //else {
    //    printf("executing hook");


    //}


}
