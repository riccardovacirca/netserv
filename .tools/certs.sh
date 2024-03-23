#!/bin/bash

if [ $# -eq 0 ]; then
  exit 1
fi

name=$1
ucname=$(echo "$name" | tr '[:lower:]' '[:upper:]')
dir=.tools/certs/${name}
mkdir -p ${dir} && rm -rf ${dir}/*

openssl genrsa -out ${dir}/ca.key 4096
openssl req -new -x509 -days 365 -key ${dir}/ca.key -out ${dir}/ca.crt -subj "/CN=MyCA"

openssl genrsa -out ${dir}/server.key 2048
openssl req -new -key ${dir}/server.key -out ${dir}/server.csr -subj "/CN=MyServer"
openssl x509 -req -days 365 -in ${dir}/server.csr -CA ${dir}/ca.crt -CAkey ${dir}/ca.key -set_serial 01 -out ${dir}/server.crt

openssl genrsa -out ${dir}/client.key 2048
openssl req -new -key ${dir}/client.key -out ${dir}/client.csr -subj "/CN=MyClient"
openssl x509 -req -days 365 -in ${dir}/client.csr -CA ${dir}/ca.crt -CAkey ${dir}/ca.key -set_serial 01 -out ${dir}/client.crt

ca_crt_file=${dir}/ca.crt
ca_c_variable_name=s_tls_ca
server_crt_file=${dir}/server.crt
server_crt_c_variable_name=s_tls_cert
server_key_file=${dir}/server.key
server_key_c_variable_name=s_tls_key

# ca_crt
ca_crt_variable="const char *${ca_c_variable_name} ="
while IFS= read -r line; do
  ca_crt_variable="${ca_crt_variable}\n\"${line}\\\\n\""
done < "$ca_crt_file"
ca_crt_variable="${ca_crt_variable};"

# server_crt
server_crt_variable="const char *${server_crt_c_variable_name} ="
while IFS= read -r line; do
  server_crt_variable="${server_crt_variable}\n\"${line}\\\\n\""
done < "$server_crt_file"
server_crt_variable="${server_crt_variable};"

# server_key
server_key_variable="const char *${server_key_c_variable_name} ="
while IFS= read -r line; do
  server_key_variable="${server_key_variable}\n\"${line}\\\\n\""
done < "$server_key_file"
server_key_variable="${server_key_variable};"

echo -e "#ifndef CERT_H" > ${dir}/certs.h
echo -e "#define CERT_H\n" >> ${dir}/certs.h
echo -e "#ifdef _TLS" >> ${dir}/certs.h
echo -e "#ifdef _TLS_TWOWAY" >> ${dir}/certs.h
echo -e "$ca_crt_variable" >> ${dir}/certs.h
echo -e "#endif\n" >> ${dir}/certs.h
echo -e "$server_crt_variable" >> ${dir}/certs.h
echo -e "$server_key_variable" >> ${dir}/certs.h
echo -e "#endif" >> ${dir}/certs.h
echo -e "#endif /* CERT_H */" >> ${dir}/certs.h
