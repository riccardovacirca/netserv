name:=$(lastword $(MAKECMDGOALS))

include src/$(name)/Makefile.config

CC:=clang
CFLAGS:=-std=gnu99 -D_MONGOOSE -DMG_TLS=MG_TLS_OPENSSL -D_TLS -D_TLS_TWOWAY
INCLUDES:=-I. -Isrc/$(name) -I.tools/include/apr-2 -I.tools/include/json-c -I.tools/include -I/usr/include
LIBS:=-L.tools/lib/apr-2 -L.tools/lib/json-c
LDFLAGS:=-lapr-2 -ljson-c -lssl -lcrypto
SRC:=.tools/src/mongoose.c libnetsrv.c netsrv.c

cmd:=$(CC) $(CFLAGS) -o .tools/bin/$(name) $(SRC) src/$(name)/$(name).c \
		 $(INCLUDES) $(LIBS) $(LDFLAGS)

all: help

help:
	@echo "Usage:"
	@echo "  make [debug[ daemon]] <service_name>  Builds service"
	@echo "  make run <db_name> <service_name>     Runs service locally"
	@echo "  make deb                              Builds Debian distribution"
	@echo "  make clean                            Removes the builds directory"
	@echo

cert-ca:
	@chmod +x .tools/bin/cert_ca && .tools/bin/cert_ca

cert-client:
	@chmod +x .tools/bin/cert_client && .tools/bin/cert_client

cert-service:
	$(eval cmd:=.tools/bin/cert_service $(name))
	@chmod +x .tools/bin/cert_service

service:
	$(eval cmd:=.tools/bin/serv $(name))
	@mkdir -p src/$(name) && chmod +x .tools/bin/serv

deb:
	$(eval cmd:=.tools/bin/deb $(name))
	@chmod +x .tools/bin/deb

deps:
	$(eval cmd:=.tools/bin/deps $(name))
	@chmod +x .tools/bin/deps

client:

mysql:
ifneq ($(mysql_driver),)
	$(eval cmd:=$(cmd) -d $(mysql_driver) -D $(mysql_conn_s))
	@echo "Run with MySQL"
endif

run:
	$(eval cmd:=LD_LIBRARY_PATH=$$LD_LIBRARY_PATH)
	$(eval cmd:=$(cmd):.tools/lib/apr-2:.tools/lib/json-c)
	$(eval cmd:=$(cmd) $(valgrind))
	$(eval cmd:=$(cmd) .tools/bin/$(name) -h $(host) -p $(port) -s $(ssl_port))
	$(eval cmd:=$(cmd) -l .tools/var/log/$(name).log)
	@chmod +x .tools/bin/$(name)

debug:
	$(eval CFLAGS :=-g -D_DEBUG $(CFLAGS))

daemon:
	$(eval CFLAGS :=-D_DAEMON $(CFLAGS))

prova:

%:
ifneq ($(wildcard src/$(name)/$(name).c),)
	$(cmd)
endif

clean:

.PHONY: all cert-ca cert-client cert-service serv deb deps client
