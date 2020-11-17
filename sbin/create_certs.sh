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
prefix_dir="$(echo "${prefix}" | sed -E 's|(.*)/[^/]*$|\1|')"
prefix_dir="$(realpath "${prefix_dir}")"
prefix_notdir="$(echo "${prefix}" | sed -E 's|.*/([^/]*)$|\1|')"
shift 1

openssl_cert_conf() {
    cat <<EOF
[ca]
default_ca = CA_default

[CA_default]
dir = $prefix_dir
certs = \$dir
crl_dir = \$dir
database = \$dir/.index.txt
new_certs_dir = \$dir
certificate = \$dir/${prefix_notdir}${CA_HOSTNAME}.pem
serial = \$dir/.serial
crl = \$dir/.crl.pem
private_key = \$dir/${prefix_notdir}${CA_HOSTNAME}.key
RANDFILE = \$dir/.rand
default_days = 365
default_md = sha3-512
default_crl_days = 30
policy = policy_match
prompt = no

[policy_match]
countryName = match
stateOrProvinceName = match
organizationName = match
organizationalUnitName = match
commonName = supplied
emailAddress = optional

[req]
default_bits = 3072
prompt = no
default_md = sha3-512
distinguished_name = req_dn
req_extensions = req_ext

[req_dn]
C=PT
ST=Lisboa
L=Lisboa
O=Universidade de Lisboa
OU=Instituto Superior Tecnico, SIRS G41
CN=${1}${HOST_DOMAIN_SUFFIX}

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${1}${HOST_DOMAIN_SUFFIX}

EOF
}

openssl_ext_file() {
	cat <<EOF
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${1}${HOST_DOMAIN_SUFFIX}
EOF
}

gen_privkey() {
    # Usage: gen_privkey <hostname>
    openssl genrsa -out "$prefix${1}.key" 3072
}

gen_cert() {
    # Usage: gen_cert <hostname>
    openssl req -new -key "$prefix${1}.key" -config <(openssl_cert_conf "${1}") -extensions req_ext -out "$prefix${1}.csr"
    openssl ca -in "$prefix${1}.csr" -cert "$prefix${CA_HOSTNAME}.pem" -extfile <(openssl_ext_file "$1") -create_serial -out "$prefix${1}.pem" -config <(openssl_cert_conf "${1}")
    rm "$prefix${1}.csr"
}

echo "Creating CA"
touch "${prefix_dir}/.index.txt"
gen_privkey "$CA_HOSTNAME"
# create self-signed certificate for CA
openssl req -x509 -new -nodes -key "$prefix$CA_HOSTNAME.key" -config <(openssl_cert_conf "${CA_HOSTNAME}") -out "$prefix${CA_HOSTNAME}.pem"

for host in $@; do
    echo "Creating key/cert for $host"
    gen_privkey "$host"
    gen_cert "$host"
    echo
done
