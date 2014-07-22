all: test_harness

bclib.o: bclib.c
	gcc -Iinclude -g -c bclib.c -o bclib.o

test_harness: test_harness.c bclib.o bclib.h
	gcc -Iinclude -I. -g test_harness.c bclib.o -lcrypto -lssl \
            -lgmp -o test_harness

clean:
	rm -f bclib.o test_harness
