#!/usr/bin/env bash
# Generates the TEST-ONLY certificates the demo needs, into certs/:
#
#   root_ca.{crt,der,key}  "MockBank Root": the CA the notary trusts
#   bank.{crt,key}         leaf for netbanking.mockbank.test, signed by root_ca
#   evil_ca.{crt,der,key}  "Impostor Root": a CA the notary does NOT trust
#   evil.{crt,key}         leaf for the same hostname, signed by evil_ca
#
# Keys are generated locally and gitignored. They protect nothing: the
# hostname is under the reserved .test TLD and no real CA will ever issue for it.
# Re-running is a no-op unless --force is passed.
set -euo pipefail
cd "$(dirname "$0")/../certs"

if [[ -f root_ca.der && -f bank.crt && -f evil_ca.der && -f evil.crt && "${1:-}" != "--force" ]]; then
  echo "certs: already present (pass --force to regenerate)"
  exit 0
fi
command -v openssl >/dev/null || { echo "certs: openssl not found on PATH" >&2; exit 1; }

make_ca() { # name, subject
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null
  openssl req -x509 -new -key "$1.key" -sha256 -days 3650 -subj "$2" \
    -config openssl.cnf -extensions v3_ca -out "$1.crt"
  openssl x509 -in "$1.crt" -outform der -out "$1.der"
}

make_leaf() { # name, ca, subject
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$1.key" 2>/dev/null
  openssl req -new -key "$1.key" -subj "$3" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial -days 3650 -sha256 \
    -extfile openssl.cnf -extensions v3_req -out "$1.crt" 2>/dev/null
  rm -f "$1.csr"
}

make_ca root_ca "/O=MockBank Test CA/CN=MockBank Root (TEST ONLY)"
make_leaf bank root_ca "/O=MockBank/CN=netbanking.mockbank.test"
make_ca evil_ca "/O=Impostor CA/CN=Impostor Root (TEST ONLY)"
make_leaf evil evil_ca "/O=Impostor/CN=netbanking.mockbank.test"
chmod 600 ./*.key
echo "certs: generated test CA, bank and impostor certificates in certs/"
