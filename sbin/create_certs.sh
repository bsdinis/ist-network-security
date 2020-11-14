#!/usr/bin/env bash

# create certificates for everyone
# usage: sbin/create_certs.sh path/prefix
# eg:
#
# sbin/create_certs.sh certs/dev
#
# will create certificates in dir ./certs with the prefix 'dev'
# (dev-ca.key, dev-server.key, etc.)
set -e # exit on first error

HOST_DOMAIN_SUFFIX="${HOST_DOMAIN_SUFFIX:-.local}"
CA_HOSTNAME="${CA_HOSTNAME:-ca}"

if [ $# -lt 2 ]
then
    echo "ERROR: need at least two positional arguments (prefix)"
    echo "Usage: $0 <prefix> <hostname>*"
    echo "HOST_DOMAIN_SUFFIX: $HOST_DOMAIN_SUFFIX"
    echo "CA hostname: $CA_HOSTNAME"
    exit -1
fi

prefix=$1
shift 1

openssl_subj() {
    echo "/C=PT/ST=Lisboa/L=Lisboa/O=Universidade de Lisboa/OU=Instituto Superior Tecnico, SIRS G41/CN=${1}.local/"
}

openssl_cert_opts() {
    echo "-days 365 -sha3-512"
}

gen_privkey() {
    # Usage: gen_privkey <hostname>
    openssl genrsa -out "$prefix${1}.key" 3072
}

gen_cert() {
    # Usage: gen_cert <hostname>
    openssl req -new -key "$prefix${1}.key" -subj "$(openssl_subj ${1})" -out "$prefix${1}.csr"
    openssl x509 -req -in "$prefix${1}.csr" -CA "$prefix${CA_HOSTNAME}.pem" -CAkey "$prefix${CA_HOSTNAME}.key" -CAcreateserial -out "$prefix${1}.pem" $(openssl_cert_opts)
    rm "$prefix${1}.csr"
}

echo "Creating CA"
gen_privkey "$CA_HOSTNAME"
# create self-signed certificate for CA
openssl req -x509 -new -nodes -key "$prefix$CA_HOSTNAME.key" $(openssl_cert_opts) -subj "$(openssl_subj "${CA_HOSTNAME}")" -out "$prefix${CA_HOSTNAME}.pem"
echo

for host in $@; do
    echo "Creating key/cert for $host"
    gen_privkey "$host"
    gen_cert "$host"
    echo
done
