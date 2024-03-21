#!/bin/bash

function make_instance {
NAME=$1
DIR=$2
PORT=$3
DBD=$4
CONN_S=$5
echo "systemctl enable ${NAME}_${PORT}.service" >> ${DIR}/DEBIAN/postinst
echo "systemctl start ${NAME}_${PORT}.service" >> ${DIR}/DEBIAN/postinst
echo "if systemctl is-active ${NAME}_${PORT}.service >/dev/null; then" >> ${DIR}/DEBIAN/prerm
echo "systemctl stop ${NAME}_${PORT}.service" >> ${DIR}/DEBIAN/prerm
echo "fi" >> ${DIR}/DEBIAN/prerm
  
cat <<EOF > ${DIR}/etc/systemd/system/${NAME}_${PORT}.service
[Unit]
Description={NAME} service
After=network.target
StartLimitIntervalSec=0

[Service]
Type=forking
Restart=always
RestartSec=1
User=root
ExecStart=/usr/bin/{NAME} -h 0.0.0.0 -p {PORT} -l ./{NAME}.log -d {DBD} -D "{CONN_S}"
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

sed -i "s/{NAME}/${NAME}/g" ${DIR}/etc/systemd/system/${NAME}_${PORT}.service
sed -i "s/{PORT}/${PORT}/g" ${DIR}/etc/systemd/system/${NAME}_${PORT}.service
sed -i "s/{DBD}/${DBD}/g" ${DIR}/etc/systemd/system/${NAME}_${PORT}.service
sed -i "s/{CONN_S}/${CONN_S}/g" ${DIR}/etc/systemd/system/${NAME}_${PORT}.service
}

NAME="nsusers"
DIR=/tmp/${NAME}
DESC="NetServ HTTP microservice for user management"
VERS="0.0.1"
MANT="Riccardo Vacirca<rvacirca23@gmail.com>"
HOME="http:\/\/riccardovacirca.com"
DBD="mysql"
CONN_S="host=127.0.0.1,port=3306,user=test,pass=test,dbname=test"

mkdir -p ${DIR}/DEBIAN
mkdir -p ${DIR}/etc
mkdir -p ${DIR}/etc/nginx/sites-available
mkdir -p ${DIR}/etc/systemd/system
mkdir -p ${DIR}/usr/bin
mkdir -p ${DIR}/usr/lib

cat <<EOF > ${DIR}/DEBIAN/control
Source: {NAME}
Section: devel
Priority: optional
Maintainer: {MANT}
Standards-Version: {VERS}
Build-Depends: debhelper (>= 7)
Homepage: {HOME}
Package: {NAME}
Version: {VERS}
Essential: no
Architecture: amd64
Depends: libapr1 (>= 1.6.5), libaprutil1 (>= 1.6.1), libssl1.1 (>= 1.1.0)
Description: {DESC}
EOF

cat <<EOF > ${DIR}/DEBIAN/postinst
#!/bin/bash
sudo ln -sf /etc/nginx/sites-available/ns_gateway.conf /etc/nginx/sites-enabled/ns_gateway.conf
chown -R root:root /usr/bin/{NAME}
systemctl daemon-reload
EOF

cat <<EOF > ${DIR}/DEBIAN/postrm
#!/bin/bash
systemctl daemon-reload
EOF

cat <<EOF > ${DIR}/DEBIAN/prerm
#!/bin/bash
set -e
EOF

sed -i "s/{NAME}/${NAME}/g" ${DIR}/DEBIAN/control
sed -i "s/{VERS}/${VERS}/g" ${DIR}/DEBIAN/control
sed -i "s/{DESC}/${DESC}/g" ${DIR}/DEBIAN/control
sed -i "s/{MANT}/${MANT}/g" ${DIR}/DEBIAN/control
sed -i "s/{HOME}/${HOME}/g" ${DIR}/DEBIAN/control

sed -i "s/{NAME}/${NAME}/g" ${DIR}/DEBIAN/postinst
chmod +x ${DIR}/DEBIAN/postinst
chmod +x ${DIR}/DEBIAN/prerm
chmod +x ${DIR}/DEBIAN/postrm

cp .tools/builds/${NAME} ${DIR}/usr/bin/${NAME}
cp .tools/builds/lib${NAME}.so ${DIR}/usr/lib/lib${NAME}.so
cp .tools/builds/libnsruntime.so ${DIR}/usr/lib/libnsruntime.so


cat <<EOF > ${DIR}/etc/nginx/sites-available/ns_gateway.conf
include /etc/nginx/sites-available/ns_*_upstream.conf;
server {
  listen 80;
  server_name example.local;
  include /etc/nginx/sites-available/ns_*_location.conf;
  location / {
    root /var/www/html/ns-webapp;
  }
}
EOF

cat <<EOF > ${DIR}/etc/nginx/sites-available/${NAME}_location.conf
location /api/users/ {
  rewrite ^/api/users(.*) /api$1 break;
  proxy_pass http://ns-users;
}
EOF

cat <<EOF > ${DIR}/etc/nginx/sites-available/${NAME}_upstream.conf
upstream ns-users {
  server localhost:8081 fail_timeout=10s max_fails=3;
  server localhost:8082 fail_timeout=10s max_fails=3;
  server localhost:8083 fail_timeout=10s max_fails=3;
}
EOF

make_instance "${NAME}" "${DIR}" "8081" "${DBD}" "${CONN_S}"
make_instance "${NAME}" "${DIR}" "8082" "${DBD}" "${CONN_S}"
make_instance "${NAME}" "${DIR}" "8083" "${DBD}" "${CONN_S}"

dpkg-deb --build ${DIR} ./${NAME}-${VERS}_amd64.deb
#  rm -rf /tmp/${NAME}
echo "done."
echo


