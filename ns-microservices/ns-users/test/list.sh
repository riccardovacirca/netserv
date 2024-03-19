#!/bin/bash
curl -i -X GET -b /tmp/cookies.txt "http://localhost:2310/api/users-list"
echo
