#define _GNU_SOURCE

#include <stddef.h>
#include <stdio.h>


void main() __attribute__((constructor));
void main() {
    int *asd = NULL;
    *asd = 1337;
}
