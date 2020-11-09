#!/usr/bin/env sh

# create certificates for everyone
# usage: sbin/create_certs.sh path/prefix
# eg:
#
# sbin/create_certs.sh certs/dev
#
# will create certificates in dir ./certs with the prefix 'dev'
# (dev-ca.key, dev-server.key, etc.)


if [ $# -ne 1 ]
then
    echo "ERROR: need one positional argument (prefix)"
    echo "usage: sbin/create_certs.sh certs/dev"
    exit -1
fi

prefix=$1

# generate CA
openssl genrsa -out $prefix-ca.key 2048
openssl req -x509 -new -nodes -key $prefix-ca.key -sha256 -days 1825 -out $prefix-ca.crt

# generate server key and CSR
openssl genrsa -out $prefix-server.key 2048
openssl req -new -key $prefix-server.key -out $prefix-server.csr -config resources/certs.conf

exit 0
# sign key
openssl x509 -req -in $prefix-server.csr -CA $prefix-ca.crt -CAkey $prefix-ca.key -CAcreateserial -out $prefix-server.crt -days 10000
