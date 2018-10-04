.PHONY: all test inject loader hello getexec final trampolin tracer

all: getexec hello inject trampolin loader final

old:
	gcc -o loader loader.c  -Wl,-Ttext-segment=0x1000000 -static
	#gdb -q -ex "set disable-randomization off" loader -ex "r test/test-64-static.core"
	#gdb -q -ex "set disable-randomization off" loader -ex "b sigret" -ex "r test/test-64-static.core"
	./loader test/test-64-static.core 0x4aa880
	./loader test/test-64-dyn.core 0x7ffff7f6c500
	./loader bash.core 0x7ffff78e6b80
	#chmod +x patched.elf


test:
	make -C test

getexec:
	gcc get_exec.c -o get_exec

hello:
	clear
	gcc hello.c -o hello -nostdlib -fno-stack-protector
	objdump -d hello
	objcopy -O binary --only-section=.text hello hello.bin
	./hello

inject: #hello
	clear
	gcc inject.c -o inject
	./inject test/test-64-static hello.bin
	chmod +x patched.elf
	gdb -q ./patched.elf -ex "r" -ex q

trampolin: #inject
	clear
	gcc trampolin.s -o trampolin -nostdlib -fno-stack-protector
	objdump -d trampolin
	objcopy -O binary --only-section=.text trampolin trampolin.bin
	./inject test/test-64-static trampolin.bin
	chmod +x patched.elf
	#strace ./patched.elf hello.bin
	gdb -q ./patched.elf -ex "b main" -ex "r hello.bin" -ex c -ex q

loader: #trampolin
	clear
	gcc loader.c -o loader -nostdlib -fno-stack-protector
	objcopy -O binary --only-section=.text loader loader.bin
	./inject test/test-64-dyn trampolin.bin
	chmod +x patched.elf
	#gdb -q ./patched.elf -ex "r loader.bin test/test-64-static.core" -ex q
	#strace ./patched.elf loader.bin test/test-64-dyn.core
	./patched.elf loader.bin test/test-64-dyn.core

tracer: loader
	./execute_corefile_toplevel test/test-64-dyn.core
	python2 create_tracepoints.py test/test-64-dyn.core tracepoints.bin
	./patched.elf loader.bin test/test-64-dyn.core tracepoints.bin


final:
	#./execute_corefile_toplevel test/test-64-static.core
	./execute_corefile_toplevel test/test-64-dyn.core

