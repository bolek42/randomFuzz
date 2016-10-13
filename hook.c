//gcc -shared -fPIC  hook.c -o hook.so -ldl

#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>

int memcmp(const void *s1, const void *s2, size_t n)
{
    int (*memcmp_orig)(const void *s1, const void *s2, size_t n) = dlsym(RTLD_NEXT,"memcmp");

    printf("memcmp\n");
    return memcmp_orig(s1, s2, n);
}

int strncmp(const char *s1, const char *s2, size_t n)
{
    int (*strncmp_orig)(const char *s1, const char *s2, size_t n) = dlsym(RTLD_NEXT,"strncmp");

    printf("strncmp\n");
    return strncmp_orig(s1, s2, n);
}
