

# Setting the fs Base

    init_tls //Thread Local Storage

    #define ARCH_SET_FS     0x1002

    TLS_INIT_TP
        mov    eax,0x9e //sycall 158
        mov    rdx,0x20 //???
        mov    rsi, 0x4aa880 //fs base

    0x00000000004a30a0

fs_base = tsblock

```
# define TLS_INIT_TCB_SIZE sizeof (struct pthread)
#define TCB_ALIGNMENT                64

size_t max_align = TCB_ALIGNMENT;

tcb_offset = roundup (memsz + GL(dl_tls_static_size), max_align);
tlsblock = __sbrk (tcb_offset + TLS_INIT_TCB_SIZE + max_align);

tcb_offset = roundup (TLS_INIT_TCB_SIZE, align ?: 1);
tlsblock = __sbrk (tcb_offset + memsz + max_align + TLS_PRE_TCB_SIZE + GL(dl_tls_static_size));
tlsblock += TLS_PRE_TCB_SIZE;
tlsblock = (void *) (((uintptr_t) tlsblock + max_align - 1) & ~(max_align - 1));
```

not easily reconstructable
return of brk not easily known
no other bointers to fs_base

#Injecting New PHDR
Overwriting rela.plt (directly after phdrs)
causes



# Writing Shellcode in C
```bash
gcc hello.c -o hello -static -nostdlib -fno-stack-protector 
readelf -l hello
objdump -d hello
./hello
```

```
#include <stddef.h>

void write(int fd, char *buf, size_t size);
void exit();

void _start() {
    char str[] = "asd";
    write(1, str, 4); 
    exit();
}

asm ("exit: mov $0x3c, %rax; mov $0x00, %rdi; syscall;");
asm ("write: mov $0x1, %rax; syscall; ret");

```
