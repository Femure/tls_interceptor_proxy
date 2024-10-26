#!/bin/bash

# Clean up background jobs on exit
trap 'kill $(jobs -p)' EXIT
set -e  # Exit on error

# Generate a self-signed certificate
openssl req -x509 -newkey rsa:4096 -keyout ca/ca_certs/key.pem -out ca/ca_certs/cert.pem \
    -days 365 -passout pass:"third-wheel" -subj "/C=US/ST=private/L=province/O=city/CN=hostname.example.com" &>/dev/null

# Sign a certificate for the server
cargo run --example sign_cert_for_site -- my_test_site.com -o ca/simple_server/localhost.pem -p third-wheel &>/dev/null

# Append the private key to the server certificate
cat ca/ca_certs/key.pem >> ca/simple_server/localhost.pem

# Start the Python HTTPS server in the background
(cd ca/simple_server && python3 server.py <(echo "third-wheel")) &>/dev/null &
echo "Waiting for the server to start..."
sleep 1

# Define expected output and save it to a file
echo -n "<html><head><title>Environment Test</title></head></html>" > /tmp/curl_test

# Test server output with curl
# Fetch server output without extra info and save to 'curl_output_test'
curl -s --cacert ./ca/ca_certs/cert.pem --resolve my_test_site.com:4443:127.0.0.1 https://my_test_site.com:4443 \
    -o /tmp/curl_output_test


# Compare output with expected content
if diff -u /tmp/curl_test /tmp/curl_output_test; then
    echo "Everything worked, your environment is looking good"
else
    echo "Curl received unexpected output, something is wrong"
fi
