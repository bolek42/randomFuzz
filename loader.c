//gcc -o restore restore.c  -lelf

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#include <sys/procfs.h> //elf_prstatus
#include <sys/user.h> //user_regs_struct
#include <elf.h> //Elf64_Nhdr
#include <signal.h> //sigcontext

#include "sys/ucontext.h"

#define round8(x) (((x)%8 == 0) ? (x) : (x)+8-(x)%8)

void sigret(void *arg) { asm("mov %rdi, %rsp; mov $0xf, %rax; syscall");}

int main(int argc, char **argv) {
    int fd = open(argv[1], O_RDONLY, 0);
    //int size = lseek(fd, 0, SEEK_END);
    //lseek(fd, 0, SEEK_SET);

    elf_version(EV_CURRENT);
    Elf *e = elf_begin(fd, ELF_C_READ, NULL);

    void *base = mmap(NULL, lseek(fd, 0, SEEK_END), PROT_READ, MAP_PRIVATE, fd, 0);
    printf("coredump file at %p\n", base);

    size_t i,n;
    int note_idx = 0;
    elf_getphdrnum(e, &n);
    printf("Found %d phdrs\n", n);

    //parsing programheader
    GElf_Phdr phdr;
    for (i=0; i < n ; i++) {
        gelf_getphdr(e, i, &phdr);

        if (phdr.p_type == PT_NOTE) note_idx = i;

        //loading memory sections
        else if (phdr.p_type == PT_LOAD) {
            printf("loading %p (%d bytes, offset %d ", phdr.p_vaddr, phdr.p_memsz, phdr.p_offset);
            if (phdr.p_memsz < phdr.p_filesz)
                printf("phdr.p_memsz < phdr.p_filesz\n");
            printf(")\n");
            //size_t fpos =
            void *ret = mmap((void *)phdr.p_vaddr, phdr.p_memsz, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (ret+1 == NULL) {perror("mmap"); exit(1);}
            lseek(fd, phdr.p_offset, SEEK_SET);
            read(fd, ret,  phdr.p_filesz);

            int prot = 0;
            if (phdr.p_flags & PF_R) prot |= PROT_READ, printf("r"); else printf("-");
            if (phdr.p_flags & PF_W) prot |= PROT_WRITE, printf("w"); else printf("-");
            if (phdr.p_flags & PF_X) prot |= PROT_EXEC, printf("x");  else printf("-");
            mprotect(ret, phdr.p_memsz, prot);
        }
    }



    printf("loading notes\n");
    #ifdef __x86_64__
        Elf64_Nhdr notehdr;
    #endif

    gelf_getphdr(e, note_idx, &phdr);
    lseek(fd, phdr.p_offset, SEEK_SET);

    struct sigret_ctx {
        char pad[40];
        struct sigcontext regs;
    } sigret_ctx;
    memset(&sigret_ctx, 0x00, sizeof(sigret_ctx));
    //ucontext_t ctx;
    //memset(&ctx, 0x00, sizeof(struct ucontext_t));

    while ((int)phdr.p_filesz > 0) {
        read(fd, &notehdr, sizeof(notehdr));
        lseek(fd, round8(notehdr.n_namesz), SEEK_CUR);

        printf("%d\n", notehdr.n_descsz);
        switch (notehdr.n_type) {
            case NT_PRSTATUS:
                printf("found type NT_PRSTATUS\n");
                struct elf_prstatus prstatus;
                struct user_regs_struct *regs = (struct user_regs_struct*)&prstatus.pr_reg;
                read(fd, &prstatus, sizeof(prstatus));
                //struct sigcontext *regsig = &ctx.uc_mcontext;
                //#define reg(r) regsig->r = regs->r; printf(#r": %p\n", regs->r);
                #define reg(r) sigret_ctx.regs.r = regs->r; printf(#r": %p\n", regs->r);
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
                break;

            case NT_FILE:
                printf("found type NT_FILE:\n");
                void **maps_start = base + lseek(fd, 0, SEEK_CUR);
                size_t n_files = (size_t) *maps_start;
                printf("found %d mapped files\n", n_files);

                char *fname = (char *)&maps_start[2 + n_files*3];
                for (i=0; i < n_files; i++) {
                    void *start = maps_start[i*3 + 2];
                    void *stop = maps_start[i*3 + 3];
                    long unsigned int offset = maps_start[i*3 + 4];
                    printf("Mapping %p %p %p %s\n", start, stop, offset, fname);

                    int map_fd = open(fname, O_RDONLY, 0);
                    void *ret = mmap(start, stop-start, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, map_fd, 0);
                    printf("%p\n", ret);
                    close(map_fd);

                    fname += strlen(fname) + 1;
                }

                lseek(fd, notehdr.n_descsz, SEEK_CUR);
                break;

            default:
                printf("found type %x\n", notehdr.n_type);
                char c;
                for (i=0; i < round8(notehdr.n_descsz); i++) {
                    read(fd, &c, 1);
                    printf("%02x ", 0xff&c);
                }
                printf("\n");
                //lseek(fd, notehdr.n_descsz, SEEK_CUR);
                break;
        }
        phdr.p_filesz -= sizeof(notehdr) + round8(notehdr.n_namesz) + round8(notehdr.n_descsz);
    }

    printf("cleanup\n");
    elf_end(e);
    close(fd);

    printf("sigreturn...\n");
    //printf("%p\n", sigret_ctx.rip);
    printf("%p\n", &sigret_ctx);
    //printf("%p\n", &ctx);
    //register int syscall_no  asm("rax") = 15;
    //register void* arg1        asm("rdi") = ptr;
    sigret(&sigret_ctx);



    exit(1);
}
