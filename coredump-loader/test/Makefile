.PHONY=all
all:
	gcc -o test-64-dyn test.c
	gdb -q -ex "b main" -ex r -ex "gcore test-64-dyn.core" -ex vmmap -ex c -ex q test-64-dyn
	gcc -o test-64-static test.c -static
	gdb -q -ex "b main" -ex r -ex "gcore test-64-static.core" -ex vmmap -ex q test-64-static
	gcc -o test-64-thread test-thread.c -l pthread
	gdb -q -ex r -ex "gcore test-64-thread.core" -ex vmmap -ex c -ex q test-64-thread
