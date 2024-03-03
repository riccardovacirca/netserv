
NAME:=nsusers
DESC:=Example HTTP microservice for user management
VERS:=0.0.1
MANT:=Riccardo Vacirca<rvacirca23@gmail.com>
HOME:=http:\/\/riccardovacirca.com

PORT_1:=8081
DBD_1:=mysql
CONN_S_1:=host=127.0.0.1,port=3306,user=test,pass=test,dbname=test

PORT_2:=8082
DBD_2:=mysql
CONN_S_2:=host=127.0.0.1,port=3306,user=test,pass=test,dbname=test

PORT_3:=8083
DBD_3:=mysql
CONN_S_3:=host=127.0.0.1,port=3306,user=test,pass=test,dbname=test

CC:=clang
CFLAGS:=-std=gnu99
INCLUDES:=-I. -I/usr/include -I/usr/include/apr-1.0 -I../../../mongoose
LD_FLAGS:=-lapr-1 -laprutil-1 -lnsruntime -lcrypto

all: lib$(NAME) debug run

lib$(NAME):
	$(CC) $(CFLAGS) -shared -fPIC -o \
	lib$(NAME).so $(NAME).c $(INCLUDES) $(LD_FLAGS)

debug:
	$(CC) $(CFLAGS) \
	-o $(NAME) ../../../mongoose/mongoose.c ../../ns-http/ns_http.c \
	$(INCLUDES) -L. $(LD_FLAGS) -l$(NAME)

release:
	$(CC) $(CFLAGS) -DDAEMONIZED \
	-o $(NAME) ../../../mongoose/mongoose.c ../../ns-http/ns_http.c \
	$(INCLUDES) -L. $(LD_FLAGS) -l$(NAME)

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

depend:
	@echo
	@readelf -d $(NAME) | grep 'NEEDED'
	@echo

dist: lib$(NAME) release
	mkdir -p /tmp/$(NAME)
	cp -r dist/debian-pkg/* /tmp/$(NAME)
	rm /tmp/$(NAME)/etc/systemd/system/.gitkeep
	rm /tmp/$(NAME)/usr/bin/.gitkeep /tmp/$(NAME)/usr/lib/.gitkeep
	sed -i 's/{NAME}/$(NAME)/g' /tmp/$(NAME)/DEBIAN/control
	sed -i 's/{VERS}/$(VERS)/g' /tmp/$(NAME)/DEBIAN/control
	sed -i 's/{DESC}/$(DESC)/g' /tmp/$(NAME)/DEBIAN/control
	sed -i 's/{MANT}/$(MANT)/g' /tmp/$(NAME)/DEBIAN/control
	sed -i 's/{HOME}/$(HOME)/g' /tmp/$(NAME)/DEBIAN/control
	sed -i 's/{NAME}/$(NAME)/g' /tmp/$(NAME)/DEBIAN/postinst

	sed -i 's/{PORT_1}/$(PORT_1)/g' /tmp/$(NAME)/DEBIAN/postinst
	sed -i 's/{PORT_2}/$(PORT_2)/g' /tmp/$(NAME)/DEBIAN/postinst
	sed -i 's/{PORT_3}/$(PORT_3)/g' /tmp/$(NAME)/DEBIAN/postinst

	sed -i 's/{NAME}/$(NAME)/g' /tmp/$(NAME)/DEBIAN/prerm
	sed -i 's/{PORT_1}/$(PORT_1)/g' /tmp/$(NAME)/DEBIAN/prerm
	sed -i 's/{PORT_2}/$(PORT_2)/g' /tmp/$(NAME)/DEBIAN/prerm
	sed -i 's/{PORT_3}/$(PORT_3)/g' /tmp/$(NAME)/DEBIAN/prerm
	chmod +x /tmp/$(NAME)/DEBIAN/postinst
	chmod +x /tmp/$(NAME)/DEBIAN/prerm
	chmod +x /tmp/$(NAME)/DEBIAN/postrm
	cp $(NAME) /tmp/$(NAME)/usr/bin/$(NAME)
	cp lib$(NAME).so /tmp/$(NAME)/usr/lib/lib$(NAME).so
	cp $(NAME).service /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_1).service
	cp $(NAME).service /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_2).service
	cp $(NAME).service /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_3).service
# to add a config file
#	mkdir -p /tmp/$(NAME)/etc/systemd/system/$(NAME).service.d

	sed -i 's/{NAME}/$(NAME)/g' /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_1).service
	sed -i 's/{PORT}/$(PORT_1)/g' /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_1).service
	sed -i 's/{DBD}/$(DBD_1)/g' /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_1).service
	sed -i 's/{CONN_S}/$(CONN_S_1)/g' /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_1).service

	sed -i 's/{NAME}/$(NAME)/g' /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_2).service
	sed -i 's/{PORT}/$(PORT_2)/g' /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_2).service
	sed -i 's/{DBD}/$(DBD_2)/g' /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_2).service
	sed -i 's/{CONN_S}/$(CONN_S_2)/g' /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_2).service

	sed -i 's/{NAME}/$(NAME)/g' /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_3).service
	sed -i 's/{PORT}/$(PORT_3)/g' /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_3).service
	sed -i 's/{DBD}/$(DBD_3)/g' /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_3).service
	sed -i 's/{CONN_S}/$(CONN_S_3)/g' /tmp/$(NAME)/etc/systemd/system/$(NAME)_$(PORT_3).service

	dpkg-deb --build /tmp/$(NAME) ./$(NAME)-$(VERS)_amd64.deb
	rm -rf /tmp/$(NAME)
	@echo "done."
	@echo

clean:
	rm -rf *.so *.log *.d $(NAME)

.PHONY: all lib$(NAME) debug release run depend dist clean
