
CC:=clang
CFLAGS:=-std=gnu99 -D_MONGOOSE -DMG_TLS=MG_TLS_OPENSSL -D_TLS -D_TLS_TWOWAY
INCLUDES:=-I. -I.tools/include/apr-2 -I.tools/include/json-c
LIBS:=-L.tools/lib/apr-2 -L.tools/lib/json-c
LDFLAGS:=-lapr-2 -ljson-c -lssl -lcrypto
SRC:=mongoose.c libnetsrv.c netsrv.c

EXTRA_CFLAGS:=
EXTRA_INCLUDES:=
EXTRA_LIBS:=
EXTRA_LDFLAGS:=
EXTRA_SRC:=

all:
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -o $(NAME) $(SRC) $(EXTRA_SRC) \
	$(NAME).c $(INCLUDES) $(EXTRA_INCLUDES) $(LIBS) $(EXTRA_LIBS) \
	$(LDFLAGS) $(EXTRA_LDFLAGS)

$(NAME):
	@chmod +x .tools/bin/tools_mkdir
	@.tools/bin/tools_mkdir
	@chmod +x .tools/bin/service
	.tools/bin/service $(NAME)
	@chmod +x .tools/bin/cert_ca
	.tools/bin/cert_ca
	@chmod +x .tools/bin/cert_service
	.tools/bin/cert_service $(NAME)
