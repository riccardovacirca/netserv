
all: install

install:
	cp ns_gateway /etc/nginx/sites-available/ns_gateway.conf
	ln -s /etc/nginx/sites-available/ns_gateway /etc/nginx/sites-enabled/ns_gateway.conf
	nginx -t

uninstall:
	rm /etc/nginx/sites-enabled/ns_gateway /etc/nginx/sites-available/ns_gateway.conf

restart:
	service nginx restart

.PHONY: all install uninstall restart
