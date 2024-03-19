
NAME=z_qrcode
HANDLE=qr
VERS=0.0.1

EXTRA_CFLAGS=
EXTRA_INCLUDES=
EXTRA_LIBS=
EXTRA_LDFLAGS=-lqrencode

CC=gcc
CFLAGS=-std=gnu99 -Wall -O3 $(EXTRA_CFLAGS)
INCLUDES=-I/usr/include/apr-1.0 -I/usr/include/apache2 -I/usr/include $(EXTRA_INCLUDES)
LIBS=$(EXTRA_LIBS)
LDFLAGS=$(EXTRA_LDFLAGS)

APACHE_LIBEXECDIR=`apxs -q LIBEXECDIR`
APACHE_SYSMODSDIR=`apxs -q SYSCONFDIR`/mods-available

all: mod_$(NAME).so

mod_$(NAME).so: mod_$(NAME).c
	$(CC) $(CFLAGS) $(INCLUDES) -fPIC -shared -o $@ $^ $(LDFLAGS)

install: mod-install clean
	service apache2 restart

uninstall: mod-uninstall clean
	service apache2 restart

mod-install:
	cp mod_$(NAME).so $(APACHE_LIBEXECDIR)/mod_$(NAME).so
	chmod 644 $(APACHE_LIBEXECDIR)/mod_$(NAME).so
	@echo "<Location /$(HANDLE)>" > $(APACHE_SYSMODSDIR)/$(NAME).conf
	@echo "SetHandler $(HANDLE)" >> $(APACHE_SYSMODSDIR)/$(NAME).conf
	@echo "</Location>" >> $(APACHE_SYSMODSDIR)/$(NAME).conf
	@echo "LoadModule $(NAME)_module /usr/lib/apache2/modules/mod_$(NAME).so" > \
		$(APACHE_SYSMODSDIR)/$(NAME).load
	a2enmod $(NAME)

mod-uninstall:
	a2dismod $(NAME)
	rm -rf $(APACHE_LIBEXECDIR)/mod_$(NAME).so $(APACHE_SYSMODSDIR)/$(NAME).*

dist-install: dist
	apt-get install -y ./$(NAME)-$(VERS)_amd64.deb
	a2enmod $(NAME)

dist-uninstall:
	a2dismod $(NAME)
	apt-get purge -y $(NAME)
	apt-get autoremove -y

test:
	curl -i -X GET -H "X-Zet-Auth: HMAC-HS256" "http://client.local/$(HANDLE)"

dep:
	@echo
	@readelf -d mod_$(NAME).so | grep 'NEEDED'
	@echo

dist:
	mkdir -p /tmp/$(NAME)/DEBIAN
	mkdir -p /tmp/$(NAME)$(APACHE_LIBEXECDIR)
	mkdir -p /tmp/$(NAME)$(APACHE_SYSMODSDIR)
	cp -r mod_$(NAME).so /tmp/$(NAME)$(APACHE_LIBEXECDIR)/mod_$(NAME).so
	@echo "<Location /$(HANDLE)>" > /tmp/$(NAME)$(APACHE_SYSMODSDIR)/$(NAME).conf
	@echo "SetHandler $(HANDLE)" >> /tmp/$(NAME)$(APACHE_SYSMODSDIR)/$(NAME).conf
	@echo "</Location>" >> /tmp/$(NAME)$(APACHE_SYSMODSDIR)/$(NAME).conf
	@echo "LoadModule $(NAME)_module /usr/lib/apache2/modules/mod_$(NAME).so" > \
		/tmp/$(NAME)$(APACHE_SYSMODSDIR)/$(NAME).load
	cp -r deb-control /tmp/$(NAME)/DEBIAN/control
	cp -r deb-postinst /tmp/$(NAME)/DEBIAN/postinst
	cp -r deb-prerm /tmp/$(NAME)/DEBIAN/prerm
	chmod 755 /tmp/$(NAME)/DEBIAN/postinst
	chmod 755 /tmp/$(NAME)/DEBIAN/prerm
	dpkg-deb --build /tmp/$(NAME) $(NAME)-$(VERS)_amd64.deb
	rm -rf /tmp/$(NAME)

clean:
	rm -rf *.o *.so *.deb

.PHONY: mod_$(NAME).so install uninstall mod-install mod-uninstall \
				dist-install dist-uninstall host test dist dep clean
