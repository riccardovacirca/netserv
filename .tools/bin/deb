#!/bin/bash
# Usage: ./dist.sh <name> <vers> <port1> <port3> <port3>

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

if [ $# -eq 0 ]; then
  exit 0
fi

NAME=$1
VERS=$2
PORT_1=$3
PORT_2=$4
PORT_3=$5

DIR=/tmp/${NAME}
DESC="NetServ HTTP microservice for user management"
MANT="Riccardo Vacirca<rvacirca23@gmail.com>"
HOME="http:\/\/riccardovacirca.com"
DBD="mysql"
CONN_S="host=127.0.0.1,port=3306,user=test,pass=test,dbname=test"

mkdir -p ${DIR}/DEBIAN
mkdir -p ${DIR}/etc
# mkdir -p ${DIR}/etc/nginx/sites-available
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

make_instance "${NAME}" "${DIR}" "${PORT_1}" "${DBD}" "${CONN_S}"
make_instance "${NAME}" "${DIR}" "${PORT_2}" "${DBD}" "${CONN_S}"
make_instance "${NAME}" "${DIR}" "${PORT_3}" "${DBD}" "${CONN_S}"

mkdir -p .tools/dist
dpkg-deb --build ${DIR} .tools/dist/${NAME}-${VERS}_amd64.deb
#  rm -rf /tmp/${NAME}
echo "done."
echo
