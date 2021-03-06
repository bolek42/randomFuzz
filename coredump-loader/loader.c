#define _GNU_SOURCE

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
#include <sched.h> //clone

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

void init_tracer(char *fname);
void create_breakpoints();
void tracer_register();
void tracer_postprocess();

#define round8(x) (((x)%8 == 0) ? (x) : (x)+8-(x)%8)
void load_core_phdr(void *elf_file);
void load_prstatus(void *core_file);
void restore();

void _start(int argc, char **argv) {
    print("Hello \\o/\n");
    int fd, size;
    void *page;
    if (argc < 3) {
        print("Execute Corefile\n");
        print("Usage: ")
        write(1, argv[0], strlen(argv[0]));
        print(" loader.bin core_file [tracepoints.bin]\n");
        exit(1);
    }

    fd=open(argv[2], O_RDONLY);
    size = lseek(fd, 0, SEEK_END); lseek(fd, 0, SEEK_SET);
    page = mmap(core_base, size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
    print("Coredump "); write(1, argv[2], strlen(argv[2]));
    print(" mapped @ "); print_ptr((size_t)page); print("\n");

    init_tracer(argv[3]);
    load_core_phdr(core_base);
    create_breakpoints();

    restore();
}

void restore() {
    //reset stack
    asm("call get_rip; get_rip: pop %rax; mov $0xffff, %rbx; xor $-1, %rbx; and %rbx, %rax; add $0xf000, %rax; mov %rax, %rsp");
    load_prstatus(core_base);
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
    if (!s) return 0;
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
    if (!not_skip_prefix) write(1, &chars[0], 1);
}

asm ("read:      mov $0x00, %rax; syscall; ret");
asm ("write:     mov $0x01, %rax; syscall; ret");
asm ("open:      mov $0x02, %rax; syscall; ret");
asm ("close:     mov $0x03, %rax; syscall; ret");
asm ("lseek:     mov $0x08, %rax; syscall; ret");
asm ("mmap:      mov $0x09, %rax; mov %rcx, %r10; syscall; ret");
asm ("mprotect:  mov $0x0a, %rax; syscall; ret");
asm ("munmap:    mov $0x0b, %rax; syscall; ret");
asm ("sigaction: mov $0x0d, %rax; mov $0x8, %r10; syscall; ret");
asm ("sigreturn: mov $0x0f, %rax; syscall");
asm ("exit:      mov $0x3c, %rax; syscall; ret");
//Also Jump to Sigret for child
asm ("clone:     mov $0x38, %rax; mov %rcx, %r10; syscall; cmp $0x00, %rax; je sigreturn; ret");
asm ("fork:      mov $0x39, %rax; syscall; ret;");
asm ("wait4:     mov $0x3d, %rax; syscall; ret;");
void sigret(void *arg) { asm("mov %rdi, %rsp; mov $0xf, %rax; syscall");}

void load_core_phdr(void *elf_file) {
    int i, ret;
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
                print("Skipping kernel page\n");
                continue;
            }

            ret = mprotect((void *)phdr[i].p_vaddr, phdr[i].p_memsz, PROT_READ|PROT_WRITE);
            if (ret != 0) {
                print("mprotect failed, using mmap ");
                mmap((void *)phdr[i].p_vaddr, phdr[i].p_memsz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);

            }

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

void exit_thread() {
    print("exit thread sighandler\n")
    exit(0);
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
            phdr = &phdr[i];
            break;
        }

    if (!note_hdr) {print("Failed"); exit(-1);}
    print("Found @"); print_ptr(note_hdr); print("\n");

    int n_threads = 0;
    print("Searching for NT_PRSTATUS\n");
    while (note_ptr < note_end) {
        note_hdr = note_ptr;
        if (note_hdr->n_type == NT_PRSTATUS) n_threads++;

        note_ptr += sizeof(*note_hdr);
        note_ptr += round8(note_hdr->n_namesz);
        note_ptr += round8(note_hdr->n_descsz);
        note_hdr = note_ptr;
    }
    if (!n_threads) {print("Failed"); exit(-1);}

    print("Found "); print_ptr(n_threads); print(" Threads\n")

    int tid = 0;
    ucontext_t sigret_ctx[n_threads];
    note_ptr = note_hdr = core_file + phdr->p_offset;
    note_end = note_ptr + phdr->p_filesz;
    print("Preparing ucontext_t\n");
    while (note_ptr < note_end) {
        note_hdr = note_ptr;
        if (note_hdr->n_type == NT_PRSTATUS){
            print("Thread: "); print_ptr(tid); print(" @ "); print_ptr(&sigret_ctx[tid]); print("\n");

            //prstatus header
            prstatus = note_ptr + sizeof(*note_hdr) + round8(note_hdr->n_namesz);
            struct user_regs_struct *regs = (struct user_regs_struct*)&prstatus->pr_reg;
            //sigret header
            memset(&sigret_ctx[tid], 0x00, sizeof(ucontext_t));
            struct sigcontext *regsig = &sigret_ctx[tid].uc_mcontext.gregs;

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
            tid ++;
        }

        note_ptr += sizeof(*note_hdr);
        note_ptr += round8(note_hdr->n_namesz);
        note_ptr += round8(note_hdr->n_descsz);
        note_hdr = note_ptr;
    }
    
    int pid = fork();

    if (pid == 0) {
        print("Sigreturn...\n");
        tracer_register();
        //register_signal(SIGTERM, &exit_thread, &exit_thread);
        for (tid=1; tid < n_threads; tid++) {
            clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM, &sigret_ctx[tid], NULL, NULL);
        }

        //register_signal(SIGTERM, &pivot_restore, &pivot_restore);
        sigret(&sigret_ctx[0]);
    }
    else {
        wait4(pid, NULL, 0, NULL);
        print("Child Exit\n");
        tracer_postprocess();
        //exit(0);
        restore();
    }
}

//  _                           
// | |_ _ __ __ _  ___ ___ _ __ 
// | __| '__/ _` |/ __/ _ \ '__|
// | |_| | | (_| | (_|  __/ |   
//  \__|_|  \__,_|\___\___|_|   


#include <signal.h>
#define breakpoints ((size_t *)0xd47a0000)

asm ("kill:      mov $0x3e, %rax; syscall; ret");
asm ("getpid:    mov $0x27, %rax; syscall; ret");

void init_tracer(char *fname) {
    int fd, size;
    void *page;

    fd=open(fname, O_RDONLY);
    if (fd < 0) {
        print("No tracepoints found\n");
        mmap(breakpoints, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
        return;
    }
    size = lseek(fd, 0, SEEK_END); lseek(fd, 0, SEEK_SET);
    page = mmap(breakpoints, size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
    read(fd, page, size);
    close(fd);
    print("Tracepoints "); write(1, fname, strlen(fname));
    print(" loaded @ "); print_ptr((size_t)page); print("\n");
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

void write_code(void *pc, char value) {
    //get page
    #ifdef __x86_64__
        Elf64_Ehdr *elf_hdr = core_base;
        Elf64_Phdr *phdr = core_base + elf_hdr->e_phoff;
    #endif

    //Searching for Page, that hit the breakpoint
    for (int i=0; i < elf_hdr->e_phnum ; i++)
        if (phdr[i].p_type == PT_LOAD)
            if (phdr[i].p_vaddr <= pc && phdr[i].p_vaddr + phdr[i].p_memsz > pc) {
                //print("Found Page\n");
                phdr = &phdr[i];
                break;
            }

    //get protection
    int prot = 0;
    if (phdr->p_flags & PF_R) prot |= PROT_READ;
    if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
    if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

    //restore value
    mprotect(phdr->p_vaddr, phdr->p_memsz, PROT_READ|PROT_WRITE);
    *((char *)pc) = value & 0xff;
    mprotect(phdr->p_vaddr, phdr->p_memsz, prot);
}

void create_breakpoints() {
    print("Creating "); print_ptr(breakpoints[0]); print(" Breakpoints\n");
    for (int i=0; i < breakpoints[0]; i++) {
        print("Added Breakpoint "); print_ptr(breakpoints[i+1]); print("\n");
        char *brk = translate_ptr(core_base, breakpoints[i+1]);
        write_code(breakpoints[i+1], 0xcc);
        breakpoints[i+1] = 0;
    }
    breakpoints[0] = 0;
}

void tracer_postprocess() {
    print("Postprocess\n");
    for (int i=0; i < breakpoints[0]; i++) {
        print("Found new tracepoint "); print_ptr(breakpoints[i+1]); print("\n");
        char *val_orig = translate_ptr(core_base, breakpoints[i+1]);
        write_code(breakpoints[i+1], *val_orig);
        breakpoints[i+1] = 0;
    }
    breakpoints[0] = 0;
}

#define SA_RESTORER 0x04000000
//The original sigaction struct has _sa_mask after sa_handler
//as this has changed with rt_sigaction, here is the redefinition
struct rt_sigaction {
	void * _sa_handler;
	unsigned long sa_flags;
	void * sa_restorer;
	unsigned long _sa_mask;
};

void register_signal(int sig, void *sighandler, void *restorer) {
    struct rt_sigaction action;
    memset(&action, 0, sizeof(action));
    action._sa_handler = sighandler;
    action._sa_mask |= 1<<(sig-1);
    action.sa_flags = SA_RESTART;
    if (restorer) action.sa_flags |= SA_RESTORER;
    action.sa_restorer = restorer;
    sigaction(sig, &action, NULL);
}

void breakpoint_handler(ucontext_t *sigret_ctx) {
    struct sigcontext *regsig = &sigret_ctx->uc_mcontext.gregs;
    regsig->rip -= 1;
    print("SIGTRAP @ "); print_ptr(regsig->rip); print("\n");

    //delte breakpoint
    char *val_orig = translate_ptr(core_base, regsig->rip);
    write_code(regsig->rip, *val_orig);

    //track breakpoint XXX not threadsafe
    breakpoints[breakpoints[0]+1] = regsig->rip;
    breakpoints[0] ++;
}

void sigreturn_wrap();
asm ("sigreturn_wrap: mov %rsp, %rdi; call breakpoint_handler; mov $0xf, %rax; syscall");


void dummy() {}
void tracer_register() {
    register_signal(SIGTRAP, dummy, &sigreturn_wrap);
}


