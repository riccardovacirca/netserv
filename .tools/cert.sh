#!/bin/bash



#!/bin/bash

C="IT"
ST="Italy"
L="Rome"
O="My Organization"
OU="My Organizational Unit"
CN="My Organization common name"

mkdir -p .tools/certs && rm -rf .tools/certs/*

# openssl genrsa -out .tools/certs/ca.key 2048
# openssl req -new -key .tools/certs/ca.key -out .tools/certs/ca.csr -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${CN}"
# openssl x509 -req -days 365 -in .tools/certs/ca.csr -signkey .tools/certs/ca.key -out .tools/certs/ca.crt

# openssl genrsa -out .tools/certs/server.key 2048
# openssl req -new -key .tools/certs/server.key -out .tools/certs/server.csr -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${CN}"

# openssl genrsa -out .tools/certs/client.key 2048
# openssl req -new -key .tools/certs/client.key -out .tools/certs/client.csr -subj "/C=${C}/ST=${ST}/L=${L}/O=${O}/OU=${OU}/CN=${CN}"

# openssl x509 -req -in .tools/certs/server.csr -CA .tools/certs/ca.crt -CAkey .tools/certs/ca.key -CAcreateserial -out .tools/certs/server.crt -days 365
# openssl x509 -req -in .tools/certs/client.csr -CA .tools/certs/ca.crt -CAkey .tools/certs/ca.key -CAcreateserial -out .tools/certs/client.crt -days 365


openssl genrsa -out .tools/certs/ca.key 4096
openssl req -new -x509 -days 365 -key .tools/certs/ca.key -out .tools/certs/ca.crt -subj "/CN=MyCA"

openssl genrsa -out .tools/certs/server.key 2048
openssl req -new -key .tools/certs/server.key -out .tools/certs/server.csr -subj "/CN=MyServer"
openssl x509 -req -days 365 -in .tools/certs/server.csr -CA .tools/certs/ca.crt -CAkey .tools/certs/ca.key -set_serial 01 -out .tools/certs/server.crt

openssl genrsa -out .tools/certs/client.key 2048
openssl req -new -key .tools/certs/client.key -out .tools/certs/client.csr -subj "/CN=MyClient"
openssl x509 -req -days 365 -in .tools/certs/client.csr -CA .tools/certs/ca.crt -CAkey .tools/certs/ca.key -set_serial 01 -out .tools/certs/client.crt

ca_crt_file=.tools/certs/ca.crt
ca_c_variable_name=s_tls_ca
server_crt_file=.tools/certs/server.crt
server_crt_c_variable_name=s_tls_cert
server_key_file=.tools/certs/server.key
server_key_c_variable_name=s_tls_key

# ca_crt
ca_crt_variable="const char *${ca_c_variable_name} = \n"
while IFS= read -r line; do
  ca_crt_variable="${ca_crt_variable}  \"${line}\\\\n\" \n"
done < "$ca_crt_file"
ca_crt_variable="${ca_crt_variable};"

# server_crt
server_crt_variable="const char *${server_crt_c_variable_name} = \n"
while IFS= read -r line; do
  server_crt_variable="${server_crt_variable}  \"${line}\\\\n\" \n"
done < "$server_crt_file"
server_crt_variable="${server_crt_variable};"

# server_key
server_key_variable="const char *${server_key_c_variable_name} = \n"
while IFS= read -r line; do
  server_key_variable="${server_key_variable}  \"${line}\\\\n\" \n"
done < "$server_key_file"
server_key_variable="${server_key_variable};"

echo -e "#ifndef NETSRV_H" > netsrv.h
echo -e "#define NETSRV_H\n" >> netsrv.h
echo -e "#ifdef _TLS" >> netsrv.h
echo -e "#ifdef _TLS_TWOWAY" >> netsrv.h
echo -e "$ca_crt_variable" >> netsrv.h
echo -e "#endif\n" >> netsrv.h
echo -e "$server_crt_variable" >> netsrv.h
echo -e "$server_key_variable" >> netsrv.h
echo -e "#endif" >> netsrv.h
echo -e "#endif /* NETSRV_H */" >> netsrv.h
