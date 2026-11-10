#!/bin/sh
# Self-signed certificate for https://localhost:8443 (for providers that only accept https redirect URIs).
# Your browser will warn once; accept it for localhost.
set -eu
cd "$(dirname "$0")/.."
mkdir -p certs
if [ -f certs/localhost-cert.pem ]; then
  echo "certs/localhost-cert.pem already exists — delete it to regenerate."
  exit 0
fi
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout certs/localhost-key.pem -out certs/localhost-cert.pem \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
echo "Wrote certs/localhost-key.pem and certs/localhost-cert.pem"
echo "macOS tip (removes the browser warning): open certs/localhost-cert.pem in Keychain Access and set it to Always Trust."
