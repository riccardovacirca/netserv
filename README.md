# netsrv
Lightweight microservices framework

### Debian development environment
```bash
$ sudo apt install clang make curl git python autoconf libtool-bin libexpat1-dev cmake
$ sudo apt install libssl-dev libmariadb-dev libpq-dev libsqlite3-dev unixodbc-dev
$ git clone https://github.com/apache/apr.git
$ git clone https://github.com/json-c/json-c.git
$ git clone https://github.com/cesanta/mongoose.git
$ cd apr && mkdir dist
$ ./buildconf
$ ./configure --prefix=/path/to/apr/dist \
              --with-mysql --with-pgsql --with-sqlite3 --with-odbc
$ make && make install
$ cd json-c && mkdir dist && cd dist && cmake .. && make
```

### GNUstep OBJ-C support
```bash
$ sudo apt install gnustep-devel gobjc
$ ln -s /usr/lib/gcc/x86_64-linux-gnu/10/include/objc /usr/local/include/objc
```

### Nginx local API gateway

#### /etc/nginx/sites-available/netsrv_gateway.conf
```bash
include /etc/nginx/sites-available/ns_*_upstream.conf;
server {
  listen 80;
  server_name example.local;
  include /etc/nginx/sites-available/ns_*_location.conf;
  location / {
    root /var/www/html/ns-webapp;
  }
}
```
## Nginx local service config

#### /etc/nginx/sites-available/helloworld_location.conf
```bash
location /api/helloworld/ {
  rewrite ^/api/helloworld(.*) /api$1 break;
  proxy_pass https://ns-helloworld;
  proxy_set_header SSL_CLIENT_CERT $ssl_client_cert;
  proxy_ssl_certificate /path/to/client.crt;
  proxy_ssl_certificate_key /path/to/client.key;
  proxy_ssl_trusted_certificate /path/to/ca.crt;
  proxy_ssl_verify on;
  proxy_ssl_verify_depth 2;
  proxy_ssl_name remote.host;
}
```

#### /etc/nginx/sites-available/helloworld_upstream.conf
```bash
upstream ns-helloworld {
  server remote.host:8081 fail_timeout=10s max_fails=3;
  server remote.host:8082 fail_timeout=10s max_fails=3;
  server remote.host:8083 fail_timeout=10s max_fails=3;
}
```
