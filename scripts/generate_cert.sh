#!/bin/bash

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <certificate_path> <privkey_path> <pubkey_path>"
    exit 1
fi
certificate="$1"
privkey="$2"
pubkey="$3"

openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
  -keyout "$privkey" -out "$certificate" -subj "/CN=example.com" \
  -addext "subjectAltName=DNS:example.com,DNS:www.example.net,IP:10.0.0.1"

openssl x509 -pubkey -noout -in "$certificate" > "$pubkey"
