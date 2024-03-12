
NAME:=nsusers

all:
	@echo "Usage: make debug|release|run|test|dist"
	@echo

runtime:
	clang -std=gnu99 -shared -fPIC -o ./libnsruntime.so \
	../../ns-runtime/ns_runtime.c \
	-I. -I../../ns-runtime/ -I/usr/include -I/usr/include/apr-1.0 \
	-lapr-1 -laprutil-1 -ljson-c -lcrypto

lib$(NAME):
	clang -std=gnu99 -shared -fPIC -o lib$(NAME).so $(NAME).c \
	-I. -I../../ns-runtime -I/usr/include -I/usr/include/apr-1.0 \
	-L. -lapr-1 -laprutil-1 -lnsruntime

debug: runtime lib$(NAME)
	clang -std=gnu99 -g \
	-o $(NAME) ../../../mongoose/mongoose.c ../../ns-http/ns_http.c \
	-I. -I../../ns-runtime -I/usr/include -I/usr/include/apr-1.0 \
	-I../../../mongoose -L. -lapr-1 -laprutil-1 -lnsruntime -l$(NAME)

release: runtime lib$(NAME)
	clang -std=gnu99 -DDAEMONIZED \
	-o $(NAME) ../../../mongoose/mongoose.c ../../ns-http/ns_http.c \
	-I. -I../../ns-runtime -I/usr/include -I/usr/include/apr-1.0 \
	-I../../../mongoose -L. -lapr-1 -laprutil-1 -lnsruntime -l$(NAME)

run:
	LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:. \
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
	./$(NAME) -h 0.0.0.0 -p 2310 -l ./$(NAME).log -d mysql \
	-D "host=127.0.0.1,port=3306,user=test,pass=test,dbname=test"

test:
	@echo "\n\n"
	curl -i -v -c /tmp/cookies.txt \
	"http://localhost:2310/api/sign-in" -d "username=bob&password=secret"
	@echo "\n\n"
	curl -i -v -X GET -b /tmp/cookies.txt \
	"http://localhost:2310/api/user-data?id=1"
	@echo "\n\n"
	curl -i -v -X GET -b /tmp/cookies.txt \
	"http://localhost:2310/api/users-list"
	@echo "\n\n"
	@echo "done."
	@echo

dist:
	./dist.sh

clean:
	rm -rf *.so *.log *.d *.deb $(NAME)

.PHONY: all lib$(NAME) debug release run dist clean
