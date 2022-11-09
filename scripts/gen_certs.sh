#/usr/bin/env bash

# Clean up directories
rm -rf certs || true
mkdir -p certs

# Generate the certificate and private key
openssl req -x509 \
	-newkey rsa:4096 \
	-nodes \
	-out certs/cert.pem \
	-keyout certs/key.pem \
	-days 365 \
	-subj "/CN=secu08.itu.dk/C=DK/L=Copenhagen"
