#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h> //Elf64_Nhdr
#include <sys/procfs.h> //struct elf_prstatus
#include <signal.h> //struct sigcontext
#include <ucontext.h> //ucontext_t
#include <signal.h>

#define core_base ((void *)0xbeef0000)
#define debug 1

void _print_ptr(size_t p);

#if debug
    #define print_ptr(x) _print_ptr((size_t)x)
    #define print(x) {char _x[] = x; write(1, (_x), strlen(_x));}
#else
    #define print_ptr(x) 
    #define print(x) 
#endif


#define round8(x) (((x)%8 == 0) ? (x) : (x)+8-(x)%8)
void load_core_phdr(void *elf_file);
void load_prstatus(void *core_file);
void pivot_restore();
void restore();

void _start(int argc, char **argv) {
    print("Hello \\o/\n");
    if (argc != 3) {
        print("Execute Corefile\n");
        print("Usage: ")
        write(1, argv[0], strlen(argv[0]));
        print(" trampolin.bin core_file\n");
        exit(1);
    }
    
    print("Loading Coredump "); write(1, argv[2], strlen(argv[2])); print("\n");

    int fd=open(argv[2], O_RDONLY);
    int size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    void *page = mmap(core_base, size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    print("Mapped @ "); print_ptr((size_t)page); print("\n");

    restore();
}

void pivot_restore(){
    asm("call get_rip; get_rip: pop %rax; mov $0xffff, %rbx; xor $-1, %rbx; and %rbx, %rax; add $0xf000, %rax; mov %rax, %rsp");
    restore();
}

void restore() {
    void **ptr = 0x7fffffffdba8;

    load_core_phdr(core_base);
    print_ptr(*ptr);print("\n");
    *ptr = pivot_restore;
    print_ptr(*ptr);print("\n");

    load_prstatus(core_base);

    exit(0);
}

void *memcpy(void *dest, const void *src, size_t n) {
    for (int i=0; i < n; i++) ((char *)dest)[i] = ((char *)src)[i];
    return dest;
}

void *memset(void *s, int c, size_t n) {
    for (int i=0; i < n; i++) ((char *)s)[i] = c;
    return s;
}

size_t strlen(const char *s) {
    int i;
    for (i=0; s[i]; i++);
    return i;
}

void _print_ptr(size_t p) {
    char chars[] = "0123456789abcdef";
    char prefix[] = "0x";
    char not_skip_prefix = 0;

    write(1, prefix, 2);
    for (int i=sizeof(size_t)-1; i>=0; i--) {
        if (not_skip_prefix = not_skip_prefix | ((p>>(i*8)&0xff))) {
            write(1, &chars[(p>>(i*8+4))&0xf], 1);
            write(1, &chars[(p>>(i*8))&0xf], 1);
        }
    }
}

asm ("write:    mov $0x01, %rax; syscall; ret");
asm ("open:     mov $0x02, %rax; syscall; ret");
asm ("close:    mov $0x03, %rax; syscall; ret");
asm ("lseek:    mov $0x08, %rax; syscall; ret");
asm ("mmap:     mov $0x09, %rax; mov %rcx, %r10; syscall; ret");
asm ("mprotect: mov $0x0a, %rax; syscall; ret");
asm ("munmap:   mov $0x0b, %rax; syscall; ret");
asm ("exit:     mov $0x3c, %rax; syscall; ret");
void sigret(void *arg) { asm("mov %rdi, %rsp; mov $0xf, %rax; syscall");}

void load_core_phdr(void *elf_file) {
    int i;
    #ifdef __x86_64__
        Elf64_Ehdr *elf_hdr = elf_file;
        Elf64_Phdr *phdr = elf_file + elf_hdr->e_phoff;
    #endif

    //parsing programheader
    for (i=0; i < elf_hdr->e_phnum ; i++) {
        //loading memory sections
        if (phdr[i].p_type == PT_LOAD) {
            print("Loading ");
            print_ptr(phdr[i].p_vaddr);
            print(" ");

            if (phdr[i].p_vaddr & (((size_t)1)<<(sizeof(void*)*8-1))) {
                print("Skipping kernel addr\n");
                continue;
            }

            mprotect((void *)phdr[i].p_vaddr, phdr[i].p_memsz, PROT_READ|PROT_WRITE);

            //get memory protection
            int prot = 0;
            if (phdr[i].p_flags & PF_R) {prot |= PROT_READ;  print("r");} else print("-");
            if (phdr[i].p_flags & PF_W) {prot |= PROT_WRITE; print("w");} else print("-");
            if (phdr[i].p_flags & PF_X) {prot |= PROT_EXEC;  print("x");} else print("-");
            print("\n");

            memcpy((void *)phdr[i].p_vaddr, elf_file + phdr[i].p_offset, phdr[i].p_filesz);
            mprotect((void *)phdr[i].p_vaddr, phdr[i].p_memsz, prot);
        }
    }
}


void load_prstatus(void *core_file){
    int i;
    void *note_ptr, *note_end;
    struct elf_prstatus *prstatus = NULL;
    #ifdef __x86_64__
        Elf64_Ehdr *elf_hdr = NULL;
        Elf64_Phdr *phdr = NULL;
        Elf64_Nhdr *note_hdr = NULL;
    #endif

    elf_hdr = core_file;
    phdr = core_file + elf_hdr->e_phoff;

    print("Searching for PT_NOTE\n")
    for (i=0; i < elf_hdr->e_phnum ; i++)
        if (phdr[i].p_type == PT_NOTE) {
            note_ptr = note_hdr = core_file + phdr->p_offset;
            note_end = note_ptr + phdr->p_filesz;
            break;
        }

    if (!note_hdr) {print("Failed"); exit(-1);}
    print("Found @"); print_ptr(note_hdr); print("\n");

    print("Searching for NT_PRSTATUS\n")
    while (note_ptr < note_end) {
        note_hdr = note_ptr;
        if (note_hdr->n_type == NT_PRSTATUS){
            prstatus = note_ptr + sizeof(*note_hdr) + round8(note_hdr->n_namesz);
            break;
        }

        note_ptr += sizeof(*note_hdr);
        note_ptr += round8(note_hdr->n_namesz);
        note_ptr += round8(note_hdr->n_descsz);
        note_hdr = note_ptr;
    }

    if (!prstatus) {print("Failed"); exit(-1);}
    print("Found @"); print_ptr(note_hdr); print("\n");

    //prstatus header
    struct user_regs_struct *regs = (struct user_regs_struct*)&prstatus->pr_reg;

    //sigret header
    ucontext_t sigret_ctx;
    memset(&sigret_ctx, 0x00, sizeof(sigret_ctx));
    struct sigcontext *regsig = &sigret_ctx.uc_mcontext.gregs;

    #define reg(r) regsig->r = regs->r; print("  "#r": "); print_ptr(regs->r);print("\n");
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

    print("Sigreturn...\n");
    sigret(&sigret_ctx);
}
