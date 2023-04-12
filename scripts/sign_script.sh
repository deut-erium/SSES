#!/bin/bash

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <script_file> <private_key> <output_file>"
    exit 1
fi

script_file="$1"
key_file="$2"
output_file="$3"

signature=$(openssl dgst -sha256 -sign "$key_file" -keyform PEM  "$script_file" | openssl enc -base64 -A)
echo "#$signature" > "$output_file"
cat "$script_file" >> "$output_file"

