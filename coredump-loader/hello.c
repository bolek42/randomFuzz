#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define pivot 0xbeef0000
#define pivot_size 0x1000
#define STR_HELP(x) #x
#define STR(x) STR_HELP(x)

void pivot_start();
void pivot_end();

void _start() {
    void *page = mmap(pivot, pivot_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    memcpy(pivot, pivot_start, pivot_end - pivot_start);
    asm ("mov %0, %%rsp; add $"STR(pivot_size)", %%rsp": "+r" (page) ::"cc");
    ((void (*)(void)) pivot)();
}

asm ("pivot_start:");

void loader() {
    char str[] = "Hello \\o/\n";
    write(1, str, strlen(str));
    exit(0);
}

void *memcpy(void *dest, const void *src, size_t n) {
    for (int i=0; i < n; i++) ((char *)dest)[i] = ((char *)src)[i];
    return dest;
}

size_t strlen(const char *s) {
    int i;
    for (i=0; s[i]; i++);
    return i;
}

asm ("mmap:   mov $0x9, %rax; mov %rcx, %r10; syscall; ret;");
asm ("exit:   mov $0x3c, %rax; syscall; ret");
asm ("write:  mov $0x1, %rax; syscall; ret");

asm ("pivot_end:");
