#!/bin/bash

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <signed_script> <public_key>"
    exit 1
fi

signed_script="$1"
pubkey="$2"
script_file=$(mktemp)

# Extract signature from output file
signature=$(head -n 1 "$signed_script")
signature=${signature:1}
# Extract signed script from output file

tail -n +2 "$signed_script" > "$script_file"

# Verify the signature using the public key from the certificate
openssl dgst -sha256 -verify "$pubkey" -signature <(echo "$signature" | openssl enc -base64 -d) "$script_file"

# Cleanup
rm "$script_file"

