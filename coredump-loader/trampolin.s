.text
_start:
    //save arguments
    push %rdi
    push %rsi

    //config
    mov $0xdead0000, %r15    ;//page addr
    mov $0xf000, %r14        ;//page size
    xor %rax, %rax

    //open(argv[1], O_RDONLY);
    mov $0x2, %al
    mov 0x8(%rsi), %rdi
    xor %rsi, %rsi
    syscall
    mov %rax, %r13

    //mmap(pivot, pivot_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0);
    mov $0x9, %al
    mov %r15, %rdi          ;//page addr
    mov %r14, %rsi          ;//page len
    xor %rdx, %rdx
    mov $0x7, %dl           ;//PROT_READ|PROT_WRITE|PROT_EXEC
    mov $0x22, %r10         ;//MAP_PRIVATE|MAP_ANONYMOUS
    xor %r8, %r8            ;//fd
    dec %r8
    xor %r9, %r9            ;//offset
    syscall


    //read(0xdead0000, 0x4000, fd);
    mov %r13, %rdi          ;//fd
    mov %r15, %rsi          ;//buff
    mov %r14, %rdx          ;//n_bytes
    xor %rax, %rax
    syscall
    

    //close(fd);
    xor %rax, %rax
    mov $0x03, %al
    syscall

    //pivot & exec
    pop %rsi
    pop %rdi
    mov %r15, %rsp
    add %r14, %rsp
    call %r15
