#!/bin/bash

# Make folders for keys
mkdir -p env/keys/server/trusted_keys
mkdir -p env/keys/client/client_01
mkdir -p env/keys/client/client_02

# Generate Keys
openssl genrsa -out env/keys/server/private-key.pem 4096
openssl rsa -in env/keys/server/private-key.pem -pubout -out env/keys/server/public-key.pem

openssl genrsa -out env/keys/client/client_01/private-key.pem 4096
openssl rsa -in env/keys/client/client_01/private-key.pem -pubout -out env/keys/client/client_01/public-key.pem

openssl genrsa -out env/keys/client/client_02/private-key.pem 4096
openssl rsa -in env/keys/client/client_02/private-key.pem -pubout -out env/keys/client/client_02/public-key.pem

# One of the clients will be a trusted client, matters when server runs in restricted mode
cp env/keys/client/client_01/public-key.pem env/keys/server/trusted_keys/client_01-public-key.pem
