#!/bin/bash
# curl --cert ./certs/client.crt --key certs/client.key --cacert certs/ca.crt -i -c /tmp/cookies.txt "https://localhost:2443/api/sign-in" -d "username=bob&password=secret"

curl -k -c "/tmp/cookie.txt" -b "/tmp/cookie.txt" \
	--key "./certs/client.key" --cert "./certs/client.crt" -i \
  "https://localhost:2443/api/sign-in" -d "username=bob&password=secret"

echo
