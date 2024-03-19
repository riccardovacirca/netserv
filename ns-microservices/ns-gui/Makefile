NAME=hello
BIND=0.0.0.0
PORT=8000
VERS=0.0.1
HOME=http:\/\/riccardovacirca.com
AUTHOR=Riccardo Vacirca<rvacirca23@gmail.com>

E_CFLAGs=
E_INCLUDEs=
E_LIBs=

MTFS=mtfs/hello.js mtfs/hello.css mtfs/main.html mtfs/404.html
all:
	gcc -o ../.toolchain/pack ../.toolchain/pack.c
	../.toolchain/pack $(MTFS) > mtfs.c
	$(CC) $(CFLAGS) $(E_CFLAGS) -DDEBUG -DMT_ENV_NS=\"$(MT_ENV_NS)\" $(INCLUDES) $(E_INCLUDES) -o ../.toolchain/bin/$(NAME) mtfs.c main.c $(LIBS) $(E_LIBS)
	@rm mtfs.c