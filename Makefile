
include .tools/Makefile.config

CC:=clang
CFLAGS:=-std=gnu99 -D_MONGOOSE -DMG_TLS=MG_TLS_OPENSSL -D_TLS -D_TLS_TWOWAY
INCLUDES:=-I. $(APR_INCLUDES) -I/usr/include $(JSON_C_INCLUDES) -I../mongoose
LIBS:=$(APR_LIBS) $(JSON_C_LIBS)
LDFLAGS:=-lapr-2 -ljson-c -lssl -lcrypto
SRC:=../mongoose/mongoose.c libnetsrv.c netsrv.c
BUILDS:=.tools/builds
DIST:=echo
VALGRIND:=

all:
	@echo "Usage:"
	@echo "  make cert                      Builds OpenSSL certificates"
	@echo "  make [debug [daemon]] service  Builds service"
	@echo "  make run service_name          Runs service locally"
	@echo "  make dist                      Builds Debian distribution"
	@echo "  make clean                     Removes the builds directory"
	@echo

debug:
	$(eval CFLAGS :=-g -D_DEBUG $(CFLAGS))
	$(eval VALGRIND :=valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes)

daemon:
	$(eval CFLAGS :=-D_DAEMON $(CFLAGS))

dist:
	$(eval DIST :=.tools/dist.sh)

# todo: make certs by service name
cert:
	@.tools/cert.sh

%:
	@mkdir -p $(BUILDS) && rm -rf $(BUILDS)/demo $(BUILDS)/demo.log
	$(CC) $(CFLAGS) -o $(BUILDS)/$@ $(SRC) examples/$@.c $(INCLUDES) $(LIBS) $(LDFLAGS)
	@cp $(BUILDS)/$@ $(BUILDS)/demo
	@cp -r $(dist-apr) $(BUILDS)
	@cp -r $(dist-json-c) $(BUILDS)
	@$(DIST) $(dist-$@)

run:
	LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:$(BUILDS) \
	$(VALGRIND) $(BUILDS)/demo -h 0.0.0.0 -p 2310 -s 2443 \
	-l $(BUILDS)/demo.log -d mysql \
	-D "host=127.0.0.1,port=3306,user=test,pass=test,dbname=test"

test:
	curl -k -c "/tmp/cookie.txt" -b "/tmp/cookie.txt" \
	--key ".tools/certs/client.key" --cert ".tools/certs/client.crt" \
	-i "https://localhost:2443/api/hello"

clean:
	rm -rf $(BUILDS)

.PHONY: all debug daemon dist cert run test clean
