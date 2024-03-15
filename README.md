# netserv
Lightweight HTTP microservices framework

## Build a Debian development environment
```
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
