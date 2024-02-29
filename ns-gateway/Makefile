
all: install

install:
	cp ns_gateway /etc/nginx/sites-available/ns_gateway
	ln -s /etc/nginx/sites-available/ns_gateway /etc/nginx/sites-enabled/ns_gateway
	nginx -t

uninstall:
	rm /etc/nginx/sites-enabled/ns_gateway /etc/nginx/sites-available/ns_gateway

restart:
	service nginx restart

.PHONY: all install uninstall restart
