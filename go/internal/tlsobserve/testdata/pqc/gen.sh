#!/bin/sh
# Regenerates the post-quantum certificate fixtures with OpenSSL 3.5 or later,
# which implements ML-DSA (FIPS 204), SLH-DSA (FIPS 205) and ML-KEM (FIPS 203).
# The certificates are public; the private keys stay in a temporary
# directory that is deleted on exit.
#
#   mldsa65-root.pem     ML-DSA-65 root CA, self-signed
#   mldsa44-int.pem      ML-DSA-44 intermediate CA, signed by the root
#   ecdsa-leaf.pem       ECDSA P-256 server certificate, signed by the intermediate
#   mlkem768-leaf.pem    ML-KEM-768 key certificate, signed by the intermediate
#   slhdsa-root.pem      SLH-DSA-SHA2-128s root CA, self-signed
#   sha1-root.pem        RSA-2048 root CA, self-signed with SHA-1
set -eu
out=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > ca.ext
printf 'basicConstraints=CA:FALSE\nsubjectAltName=DNS:pq.observe.test\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > leaf.ext
root() { # key algorithm, subject, output, extra req options
  openssl genpkey -algorithm "$1" -out "$3.key" ${4:+-pkeyopt "$4"}
  openssl req -x509 -new -key "$3.key" -subj "/CN=$2" -days 3650 ${5:-} \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -out "$out/$3.pem"
}
issue() { # key algorithm, subject, output, issuer, extensions
  openssl genpkey -algorithm "$1" -out "$3.key" ${6:+-pkeyopt "$6"}
  openssl req -new -key "$3.key" -subj "/CN=$2" -out "$3.csr"
  openssl x509 -req -in "$3.csr" -CA "$out/$4.pem" -CAkey "$4.key" -set_serial 0x$(openssl rand -hex 8) \
    -days 825 -extfile "$5" -out "$out/$3.pem"
}

root ML-DSA-65 "PQ Test Root ML-DSA-65" mldsa65-root
issue ML-DSA-44 "PQ Test Issuing ML-DSA-44" mldsa44-int mldsa65-root ca.ext
issue EC "pq.observe.test" ecdsa-leaf mldsa44-int leaf.ext ec_paramgen_curve:P-256
openssl genpkey -algorithm ML-KEM-768 -out kem.key
openssl pkey -in kem.key -pubout -out kem.pub
openssl x509 -new -force_pubkey kem.pub -subj "/CN=kem.observe.test" -CA "$out/mldsa44-int.pem" -CAkey mldsa44-int.key \
  -set_serial 0x$(openssl rand -hex 8) -days 825 -extfile leaf.ext -out "$out/mlkem768-leaf.pem"
root SLH-DSA-SHA2-128s "PQ Test Root SLH-DSA-SHA2-128s" slhdsa-root
root RSA "Legacy Test Root SHA-1" sha1-root rsa_keygen_bits:2048 -sha1
