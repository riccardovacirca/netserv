# netsrv
Lightweight microservices framework

### Install common development tools
```bash
sudo apt install clang make curl git python autoconf libtool-bin libexpat1-dev cmake
sudo apt install libssl-dev libmariadb-dev libpq-dev libsqlite3-dev unixodbc-dev
```

### Install GNUstep OBJ-C support
```bash
sudo apt install gnustep-devel gobjc
ln -s /usr/lib/gcc/x86_64-linux-gnu/10/include/objc /usr/local/include/objc
```

### Install apr-2 dependencies
```bash
git clone https://github.com/apache/apr.git apr
cd apr && ./buildconf
./configure --prefix=/tmp/apr-install --with-mysql --with-pgsql --with-sqlite3 --with-odbc
make && make install
mv /tmp/apr-install/include/apr-2 /path/to/netsrv/.tools/include
mv /tmp/apr-install/lib /path/to/netsrv/.tools/lib
rm -rf /tmp/apr-install
```

### Install json-c dependencies
```bash
git clone https://github.com/json-c/json-c.git json-c
mkdir json-c-build && cd json-c-build
cmake ../json-c -DCMAKE_INSTALL_PREFIX=/tmp/json-c-install
make && make install
mv /tmp/json-c-install/include/json-c /path/to/netsrv/.tools/include
mv /tmp/json-c-install/lib /path/to/netsrv/.tools/lib
rm -rf /tmp/json-c-install
```

### Install Mongoose dependencies
```bash
git clone https://github.com/cesanta/mongoose.git mongoose
cp ./mongoose/mongoose.h /path/to/netsrv/.tools/include
cp ./mongoose/mongoose.c /path/to/netsrv/.tools/src

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
