#!/bin/bash
curl -i -c /tmp/cookies.txt "http://localhost:2310/api/sign-in" -d "username=bob&password=secret"
echo
