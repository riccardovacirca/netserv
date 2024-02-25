# MIT License
# Copyright (c) 2024 Riccardo Vacirca <rvacirca23@gmail.com>

CC=clang
CFLAGS=-std=gnu99
INCLUDES=-I. -I/usr/include -I/usr/include/apr-1.0
LD_FLAGS=-lapr-1 -laprutil-1 -lnsruntime

all: libnsusers service run

libnsusers:
	$(CC) $(CFLAGS) -shared -fPIC -o libnsusers.so nsusers.c $(INCLUDES) $(LD_FLAGS)

service:
	$(CC) $(CFLAGS) \
	-o nsusers ../../ns-http/mongoose.c ../../ns-http/ns_http.c \
	$(INCLUDES) -L. $(LD_FLAGS) -lnsusers

run:
	LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:. \
	./nsusers -h 0.0.0.0 -p 8081 -l ./nsusers.log -d mysql \
	-D "host=127.0.0.1,port=3306,user=test,pass=test,dbname=test"

debug:
	LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:. \
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
	./nsusers -h 0.0.0.0 -p 8081 -l ./nsusers.log -d mysql \
	-D "host=127.0.0.1,port=3306,user=test,pass=test,dbname=test"

clean:
	rm -rf *.so *.log *.d nsusers

.PHONY: all libnsusers service run
