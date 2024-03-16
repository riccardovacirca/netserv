
NAME:=nsusers

include ../../Makefile.config

all:
	@echo "Usage: make debug|release|run|test|dist"
	@echo

runtime:
	clang -std=gnu99 -shared -fPIC -o ./libnsruntime.so \
	$(PROJ_DIR)/ns-runtime/ns_runtime.c -I. -I$(PROJ_DIR)/ns-runtime -I/usr/include \
	$(APR_INCLUDES) $(JSON_C_INCLUDES) $(APR_LIBS) $(JSON_C_LIBS) $(APR_LDFLAGS) \
	$(JSON_C_LDFLAGS) -lcrypto
	@echo

lib$(NAME):
	clang -std=gnu99 -shared -fPIC -o lib$(NAME).so $(NAME).c \
	-I. -I$(PROJ_DIR)/ns-runtime -I/usr/include $(APR_INCLUDES) $(JSON_C_INCLUDES) \
	-L. $(APR_LIBS) $(APR_LDFLAGS) -lnsruntime
	@echo

debug: runtime lib$(NAME)
	clang -std=gnu99 -g -D_DEBUG -o $(NAME) $(MONGOOSE_SRC) \
	$(PROJ_DIR)/ns-http/ns_http.c -I. -I$(PROJ_DIR)/ns-runtime -I/usr/include \
	$(APR_INCLUDES) $(MONGOOSE_INCLUDES) $(JSON_C_INCLUDES) -L. $(APR_LIBS) \
	$(APR_LDFLAGS) -lnsruntime -l$(NAME)
	@echo

release: runtime lib$(NAME)
	clang -std=gnu99 -D_DAEMONIZED -o $(NAME) $(MONGOOSE_SRC) \
	$(PROJ_DIR)/ns-http/ns_http.c -I. -I$(PROJ_DIR)/ns-runtime -I/usr/include \
	$(APR_INCLUDES) $(MONGOOSE_INCLUDES) -L. $(APR_LIBS) $(APR_LDFLAGS) \
	-lnsruntime -l$(NAME)
	@echo

#	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes
run:
	LD_LIBRARY_PATH=$$LD_LIBRARY_PATH:.:$(APR_LIB_DIST):$(JSON_C_LIB_DIST) \
	./$(NAME) -h 0.0.0.0 -p 2310 -l ./$(NAME).log -d mysql \
	-D "host=127.0.0.1,port=3306,user=test,pass=test,dbname=test"
	@echo

test/%:
	@chmod +x ./$@.sh && ./$@.sh

dist:
	./dist.sh

clean:
	rm -rf *.so *.log *.d *.deb $(NAME)

.PHONY: all lib$(NAME) debug release run dist clean
