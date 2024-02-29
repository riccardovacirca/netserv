
CC=clang
CFLAGS=-std=gnu99 -shared -fPIC
INCLUDES=-I. -I/usr/include -I/usr/include/apr-1.0
LD_FLAGS=-lapr-1 -laprutil-1 -ljson-c -lcrypto

all: 
	$(CC) $(CFLAGS) -o libnsruntime.so ns_runtime.c $(INCLUDES) $(LD_FLAGS)

install:
	mkdir -p /usr/lib/libnsruntime
	cp ./ns_runtime.h /usr/include/ns_runtime.h
	cp ./libnsruntime.so /usr/lib/libnsruntime/libnsruntime.so
	ln -s /usr/lib/libnsruntime/libnsruntime.so /usr/lib/libnsruntime.so
	ldconfig

uninstall:
	rm -rf /usr/include/ns_runtime.h /usr/lib/libnsruntime.so /usr/lib/libnsruntime
	ldconfig

test:
	$(CC) -std=gnu99 -o test ns_runtime.c ns_test.c  $(INCLUDES) $(LD_FLAGS)
	./test

clean:
	rm -rf *.so

.PHONY: all install uninstall test clean
