
CC=clang
CFLAGS=-std=gnu99
INCLUDES=-I. -I/usr/include -I/usr/include/apr-1.0 -I../../../mongoose
LD_FLAGS=-lapr-1 -laprutil-1 -lnsruntime

all: libnshello service run

libnshello:
	$(CC) $(CFLAGS) -shared -fPIC -o libnshello.so nshello.c $(INCLUDES) $(LD_FLAGS)

service:
	$(CC) $(CFLAGS) \
	-o nshello ../../../mongoose/mongoose.c ../../ns-http/ns_http.c \
	$(INCLUDES) -L. $(LD_FLAGS) -lnshello

run:
	LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:. \
	./nshello -h 0.0.0.0 -p 8081 -l ./nshello.log

debug:
	LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:. \
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
	./nshello -h 0.0.0.0 -p 8081 -l ./nshello.log

test:
	curl -i -X GET "http://localhost:8081/api/hello"

clean:
	rm -rf *.so *.log *.d nshello

.PHONY: all libnshello service run debug test clean
