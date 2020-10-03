#include <stdio.h>
#include <ucontext.h>

void print_uctx(ucontext_t *ctx){
    #define p(x) printf(#x" = %p\n", ctx->x)
    p(uc_stack.ss_sp);
    p(uc_stack.ss_flags);
    p(uc_stack.ss_size);
    p(uc_mcontext.gregs[0]);
    p(uc_mcontext.gregs[1]);
    p(uc_mcontext.gregs[2]);
    p(uc_mcontext.gregs[3]);

}

int main() {
    ucontext_t ctx;
    getcontext(&ctx);

    printf("Helloworld\n");

    void ** ptr;

    //for (ptr = &ctx; ptr < ((void *) &ctx) + sizeof(ctx); ptr ++)
    //    printf("%p\n", *ptr);
    print_uctx(&ctx);

    printf("%d\n", (void *)&ctx - (void *)&ctx.uc_mcontext.gregs);

    //setcontext(&ctx);
}
