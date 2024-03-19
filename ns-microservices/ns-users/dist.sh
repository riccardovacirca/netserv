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
  cp ${NAME}.service ${DIR}/etc/systemd/system/${NAME}_${PORT}.service
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

mkdir -p ${DIR}
cp -r dist/debian/* $DIR

rm ${DIR}/etc/systemd/system/.gitkeep
rm ${DIR}/usr/bin/.gitkeep
rm ${DIR}/usr/lib/.gitkeep
rm ${DIR}/etc/nginx/sites-available/.gitkeep

sed -i "s/{NAME}/${NAME}/g" ${DIR}/DEBIAN/control
sed -i "s/{VERS}/${VERS}/g" ${DIR}/DEBIAN/control
sed -i "s/{DESC}/${DESC}/g" ${DIR}/DEBIAN/control
sed -i "s/{MANT}/${MANT}/g" ${DIR}/DEBIAN/control
sed -i "s/{HOME}/${HOME}/g" ${DIR}/DEBIAN/control

sed -i "s/{NAME}/${NAME}/g" ${DIR}/DEBIAN/postinst
chmod +x ${DIR}/DEBIAN/postinst
chmod +x ${DIR}/DEBIAN/prerm
chmod +x ${DIR}/DEBIAN/postrm

cp ${NAME} ${DIR}/usr/bin/${NAME}
cp lib${NAME}.so ${DIR}/usr/lib/lib${NAME}.so
cp libnsruntime.so ${DIR}/usr/lib/libnsruntime.so

cp ../../ns-gateway/ns_gateway.conf ${DIR}/etc/nginx/sites-available/ns_gateway.conf
cp "${NAME}_location.conf" "${DIR}/etc/nginx/sites-available/${NAME}_location.conf"
cp "${NAME}_upstream.conf" "${DIR}/etc/nginx/sites-available/${NAME}_upstream.conf"

make_instance "${NAME}" "${DIR}" "8081" "${DBD}" "${CONN_S}"
make_instance "${NAME}" "${DIR}" "8082" "${DBD}" "${CONN_S}"
make_instance "${NAME}" "${DIR}" "8083" "${DBD}" "${CONN_S}"

dpkg-deb --build ${DIR} ./${NAME}-${VERS}_amd64.deb
#  rm -rf /tmp/${NAME}
echo "done."
echo


