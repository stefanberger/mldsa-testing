#!/usr/bin/env bash

create_rsa_ca() {
	dir="$1"
	echo "Creating RSA CA"
	mkdir ${dir}
	mkdir -p ${dir}/ca.db.certs
	touch ${dir}/ca.db.index
	echo "01" > ${dir}/ca.db.serial

	openssl req -x509 \
		-newkey rsa:2048 -keyout ${dir}/ca.key -nodes \
		-days 3650 -out ${dir}/ca.crt \
		-subj '/CN=Testing-RSA-CA'

	openssl x509 -in ${dir}/ca.crt \
		-outform der -out ${dir}/ca.crt.der

	cat <<_EOF_ > ${dir}/rsaca.conf
[ ca ]
default_ca = ca_default
[ ca_default ]
dir = ./${dir}
certs = \$dir
new_certs_dir = \$dir/ca.db.certs
database = \$dir/ca.db.index
serial = \$dir/ca.db.serial
RANDFILE = \$dir/ca.db.rand
certificate = \$dir/ca.crt
private_key = \$dir/ca.key
default_days = 365
default_crl_days = 30
default_md = sha384
preserve = no
policy = generic_policy

x509_extensions = usr_cert

[ usr_cert ]

basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
extendedKeyUsage       = clientAuth
keyUsage               = digitalSignature

[ generic_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = optional
emailAddress = optional

[req]
x509_extensions        = v3_req
distinguished_name     = dn

[dn]

[v3_req]

#subjectKeyIdentifier   = hash
#authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:false

[v3_ca]

subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true

_EOF_
}

create_ecdsa_ca() {
	dir="$1"
	echo "Creating ECDSA CA"
	mkdir -p ${dir}/ca.db.certs
	touch ${dir}/ca.db.index
	echo "01" > ${dir}/ca.db.serial

	openssl req -x509 \
		-newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
			-keyout ${dir}/ca.key -nodes \
		-days 3650 -out ${dir}/ca.crt \
		-subj '/CN=Testing-ECDSA-CA'

	openssl x509 -in ${dir}/ca.crt \
		-outform der -out ${dir}/ca.crt.der

	cat <<_EOF_ > ${dir}/ecdsaca.conf
[ ca ]
default_ca = ca_default
[ ca_default ]
dir = ./${dir}
certs = \$dir
new_certs_dir = \$dir/ca.db.certs
database = \$dir/ca.db.index
serial = \$dir/ca.db.serial
RANDFILE = \$dir/ca.db.rand
certificate = \$dir/ca.crt
private_key = \$dir/ca.key
default_days = 365
default_crl_days = 30
default_md = sha1
preserve = no
policy = generic_policy

x509_extensions = usr_cert

[ usr_cert ]

basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
extendedKeyUsage       = clientAuth
keyUsage               = digitalSignature

[ generic_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = optional
emailAddress = optional

[req]
x509_extensions        = v3_req
distinguished_name     = dn

[dn]

[v3_req]

#subjectKeyIdentifier   = hash
#authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:false

[v3_ca]

subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true

_EOF_
}

create_mldsa_ca() {
	dir="$1"
	echo "Creating ML-DSA CA"
	mkdir ${dir}
	mkdir -p ${dir}/ca.db.certs
	touch ${dir}/ca.db.index
	echo "01" > ${dir}/ca.db.serial

	openssl req -x509 \
		-newkey mldsa65 -keyout ${dir}/ca.key -nodes \
		-days 3650 -out ${dir}/ca.crt \
		-subj '/CN=Testing-MLDSA-CA'

	openssl x509 -in ${dir}/ca.crt \
		-outform der -out ${dir}/ca.crt.der

	cat <<_EOF_ > ${dir}/mldsaca.conf
[ ca ]
default_ca = ca_default
[ ca_default ]
dir = ./${dir}
certs = \$dir
new_certs_dir = \$dir/ca.db.certs
database = \$dir/ca.db.index
serial = \$dir/ca.db.serial
RANDFILE = \$dir/ca.db.rand
certificate = \$dir/ca.crt
private_key = \$dir/ca.key
default_days = 365
default_crl_days = 30
default_md = shake256
preserve = no
policy = generic_policy

x509_extensions = usr_cert

[ usr_cert ]

basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer:always
extendedKeyUsage       = clientAuth
keyUsage               = digitalSignature

[ generic_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = optional
emailAddress = optional

[req]
x509_extensions        = v3_req
distinguished_name     = dn

[dn]

[v3_req]

#subjectKeyIdentifier   = hash
#authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:false

[v3_ca]

subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer:always
basicConstraints       = CA:true

_EOF_
}



dir=rsa-ca
if [ ! -d $dir ]; then
	create_rsa_ca "${dir}"
fi

dir=ecdsa-ca
if [ ! -d $dir ]; then
	create_ecdsa_ca "${dir}"
fi

dir=mldsa-ca
if [ ! -d $dir ]; then
	create_mldsa_ca "${dir}"
fi

if [ ! -f eckey.pem ]; then
	echo "Creating EC key"
	openssl ecparam -name prime256v1 -genkey -noout -out eckey.pem
	openssl ec -in eckey.pem -pubout -out eckeypub.pem
fi

if [ ! -f eckey-ecdsa.crt.der ]; then
	echo "Using ECDSA CA to sign EC key"
	openssl req -new -config ecdsa-ca/ecdsaca.conf \
		-key eckey.pem -out myreq-eckey.pem \
		-subj '/CN=ecdsa-ca-signed-ec-key' \
		-reqexts v3_req
	openssl ca -config ecdsa-ca/ecdsaca.conf -md sha256 \
		-out eckey-ecdsa.pem -infiles myreq-eckey.pem
	openssl x509 -in eckey-ecdsa.pem -outform der -out eckey-ecdsa.crt.der
	openssl verify -verbose -CAfile ecdsa-ca/ca.crt eckey-ecdsa.pem
fi

if [ ! -f eckey-rsa.crt.der ]; then
	echo "Using RSA CA to sign EC key"
	openssl req -new -config rsa-ca/rsaca.conf \
		-key eckey.pem -out myreq-rsakey.pem \
		-subj '/CN=rsa-ca-signed-ec-key' \
		-reqexts v3_req
	openssl ca -config rsa-ca/rsaca.conf -md sha256 \
		-out eckey-rsa.pem -infiles myreq-rsakey.pem
	openssl x509 -in eckey-rsa.pem -outform der -out eckey-rsa.crt.der
	openssl verify -verbose -CAfile rsa-ca/ca.crt eckey-rsa.pem
fi

if [ ! -f rsakey.pem ]; then
	echo "Creating RSA key"
	openssl genrsa -out rsakey.pem
	openssl rsa -in rsakey.pem -pubout -out rsakeypub.pem
fi

if [ ! -f rsakey-ecdsa.crt.der ]; then
	echo "Using ECDSA CA to sign RSA key"
	openssl req -new -config ecdsa-ca/ecdsaca.conf \
		-key rsakey.pem -out myreq-eckey.pem \
		-subj '/CN=ecdsa-ca-signed-rsa-key' \
		-reqexts v3_req
	openssl ca -config ecdsa-ca/ecdsaca.conf -md sha256 \
		-out rsakey-ecdsa.pem -infiles myreq-eckey.pem
	openssl x509 -in rsakey-ecdsa.pem -outform der -out rsakey-ecdsa.crt.der
	openssl verify -verbose -CAfile ecdsa-ca/ca.crt rsakey-ecdsa.pem
fi

if [ ! -f rsakey-rsa.crt.der ]; then
	echo "Using RSA CA to sign RSA key"
	openssl req -new -config rsa-ca/rsaca.conf \
		-key rsakey.pem -out myreq-rsakey.pem \
		-subj '/CN=rsa-ca-signed-rsa-key' \
		-reqexts v3_req
	openssl ca -config rsa-ca/rsaca.conf -md sha256 \
		-out rsakey-rsa.pem -infiles myreq-rsakey.pem
	openssl x509 -in rsakey-rsa.pem -outform der -out rsakey-rsa.crt.der
	openssl verify -verbose -CAfile rsa-ca/ca.crt rsakey-rsa.pem
fi


if [ ! -f mldsakey.pem ]; then
	echo "Creating MLDSA key"
	openssl genpkey -algorithm mldsa65 -out mldsakey.pem
	openssl pkey -in mldsakey.pem -pubout -out mldsakeypub.pem
fi

if [ ! -f rsakey-mldsa.crt.der ]; then
	echo "Using MLDSA CA to sign RSA key"
	openssl req -new -config mldsa-ca/mldsaca.conf \
		-key rsakey.pem -out myreq-rsakey.pem \
		-subj '/CN=mldsa-ca-signed-rsa-key' \
		-reqexts v3_req
	openssl ca -config mldsa-ca/mldsaca.conf \
		-out rsakey-mldsa.pem -infiles myreq-rsakey.pem
	openssl x509 -in rsakey-mldsa.pem -outform der -out rsakey-mldsa.crt.der
	openssl verify -verbose -CAfile mldsa-ca/ca.crt rsakey-mldsa.pem
fi

if [ ! -f eckey-mldsa.crt.der ]; then
	echo "Using MLDSA CA to sign EC key"
	openssl req -new -config mldsa-ca/mldsaca.conf \
		-key eckey.pem -out myreq-eckey.pem \
		-subj '/CN=mldsa-ca-signed-ec-key' \
		-reqexts v3_req
	openssl ca -config mldsa-ca/mldsaca.conf \
		-out eckey-mldsa.pem -infiles myreq-eckey.pem
	openssl x509 -in eckey-mldsa.pem -outform der -out eckey-mldsa.crt.der
	openssl verify -verbose -CAfile mldsa-ca/ca.crt eckey-mldsa.pem
fi

if [ ! -f mldsakey-mldsa.crt.der ]; then
	echo "Using MLDSA CA to sign MLDSA key"
	openssl req -new -config mldsa-ca/mldsaca.conf \
		-key mldsakey.pem -out myreq-mldsakey.pem \
		-subj '/CN=mldsa-ca-signed-mldsa-key' \
		-reqexts v3_req
	openssl ca -config mldsa-ca/mldsaca.conf \
		-out mldsakey-mldsa.pem -infiles myreq-mldsakey.pem
	openssl x509 -in mldsakey-mldsa.pem -outform der -out mldsakey-mldsa.crt.der
	openssl verify -verbose -CAfile mldsa-ca/ca.crt mldsakey-mldsa.pem
fi
