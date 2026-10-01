#!/usr/bin/env bash
# Throwaway lab CA and a server certificate for localhost. Never committed (certs/ is git-ignored).
set -euo pipefail
export MSYS_NO_PATHCONV=1   # Git Bash on Windows would rewrite "/CN=..." as a path
dir="${1:-certs}"
mkdir -p "$dir"
cd "$dir"
openssl req -x509 -newkey rsa:3072 -nodes -days 30 -subj "/CN=Lab 08 throwaway CA" \
  -keyout ca.key -out ca.crt \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -newkey rsa:3072 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr
printf '%s\n' "subjectAltName=DNS:localhost,IP:127.0.0.1" "extendedKeyUsage=serverAuth" \
  "keyUsage=critical,digitalSignature,keyEncipherment" "basicConstraints=CA:FALSE" > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -extfile server.ext -out server.crt
chmod 600 ca.key server.key
echo "certificates written to $dir"
