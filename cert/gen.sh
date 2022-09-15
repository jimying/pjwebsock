#!/bin/bash

#
# Generate self-signed test cert
#

openssl req -x509 -days 3650 -nodes -newkey rsa:2048 -keyout test.key -out test.pem

