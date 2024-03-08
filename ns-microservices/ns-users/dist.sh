#!/bin/bash

NAME="nsusers"
DESC="NetServ HTTP microservice for user management"
VERS="0.0.1"
MANT="Riccardo Vacirca<rvacirca23@gmail.com>"
HOME="http:\/\/riccardovacirca.com"

PORT_1="8081"
DBD_1="mysql"
CONN_S_1="host=127.0.0.1,port=3306,user=test,pass=test,dbname=test"

PORT_2="8082"
DBD_2="mysql"
CONN_S_2="host=127.0.0.1,port=3306,user=test,pass=test,dbname=test"

PORT_3="8083"
DBD_3="mysql"
CONN_S_3="host=127.0.0.1,port=3306,user=test,pass=test,dbname=test"

dist() {
  
  mkdir -p /tmp/${NAME}
  cp -r dist/debian/* /tmp/${NAME}
  
  rm /tmp/${NAME}/etc/systemd/system/.gitkeep
  rm /tmp/${NAME}/usr/bin/.gitkeep
  rm /tmp/${NAME}/usr/lib/.gitkeep
  rm /tmp/${NAME}/etc/nginx/sites-available/.gitkeep
  
  sed -i "s/{NAME}/${NAME}/g" /tmp/${NAME}/DEBIAN/control
  sed -i "s/{VERS}/${VERS}/g" /tmp/${NAME}/DEBIAN/control
  sed -i "s/{DESC}/${DESC}/g" /tmp/${NAME}/DEBIAN/control
  sed -i "s/{MANT}/${MANT}/g" /tmp/${NAME}/DEBIAN/control
  sed -i "s/{HOME}/${HOME}/g" /tmp/${NAME}/DEBIAN/control
  
  sed -i "s/{NAME}/${NAME}/g" /tmp/${NAME}/DEBIAN/postinst
  sed -i "s/{PORT_1}/${PORT_1}/g" /tmp/${NAME}/DEBIAN/postinst
  sed -i "s/{PORT_2}/${PORT_2}/g" /tmp/${NAME}/DEBIAN/postinst
  sed -i "s/{PORT_3}/${PORT_3}/g" /tmp/${NAME}/DEBIAN/postinst

  sed -i "s/{NAME}/${NAME}/g" /tmp/${NAME}/DEBIAN/prerm
  sed -i "s/{PORT_1}/${PORT_1}/g" /tmp/${NAME}/DEBIAN/prerm
  sed -i "s/{PORT_2}/${PORT_2}/g" /tmp/${NAME}/DEBIAN/prerm
  sed -i "s/{PORT_3}/${PORT_3}/g" /tmp/${NAME}/DEBIAN/prerm

  chmod +x /tmp/${NAME}/DEBIAN/postinst
  chmod +x /tmp/${NAME}/DEBIAN/prerm
  chmod +x /tmp/${NAME}/DEBIAN/postrm

  cp ${NAME} /tmp/${NAME}/usr/bin/${NAME}
  cp lib${NAME}.so /tmp/${NAME}/usr/lib/lib${NAME}.so
  cp libnsruntime.so /tmp/${NAME}/usr/lib/libnsruntime.so

  cp ../../ns-gateway/ns_gateway.conf /tmp/${NAME}/etc/nginx/sites-available/ns_gateway.conf
	cp "${NAME}_location.conf" "/tmp/${NAME}/etc/nginx/sites-available/${NAME}_location.conf"
  cp "${NAME}_upstream.conf" "/tmp/${NAME}/etc/nginx/sites-available/${NAME}_upstream.conf"

  cp ${NAME}.service /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_1}.service
  cp ${NAME}.service /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_2}.service
  cp ${NAME}.service /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_3}.service

  sed -i "s/{NAME}/${NAME}/g" /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_1}.service
  sed -i "s/{PORT}/${PORT_1}/g" /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_1}.service
  sed -i "s/{DBD}/${DBD_1}/g" /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_1}.service
  sed -i "s/{CONN_S}/${CONN_S_1}/g" /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_1}.service

  sed -i "s/{NAME}/${NAME}/g" /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_2}.service
  sed -i "s/{PORT}/${PORT_2}/g" /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_2}.service
  sed -i "s/{DBD}/${DBD_2}/g" /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_2}.service
  sed -i "s/{CONN_S}/${CONN_S_2}/g" /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_2}.service

  sed -i "s/{NAME}/${NAME}/g" /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_3}.service
  sed -i "s/{PORT}/${PORT_3}/g" /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_3}.service
  sed -i "s/{DBD}/${DBD_3}/g" /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_3}.service
  sed -i "s/{CONN_S}/${CONN_S_3}/g" /tmp/${NAME}/etc/systemd/system/${NAME}_${PORT_3}.service

  dpkg-deb --build /tmp/${NAME} ./${NAME}-${VERS}_amd64.deb
#  rm -rf /tmp/${NAME}
  echo "done."
  echo
}

dist
