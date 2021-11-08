#!/usr/bin/bash

echo "Generating RSA private key ..."
openssl genrsa -out ./server/server.key 2048

echo "Genereate self-signed certificate for TLS ..."
openssl req -new -x509 -sha256 -key ./server/server.key -out ./server/server.crt -days 3650

echo "Building custom Client Binary ..."


echo "Enter the port the server shall be listening on (default 15213)"
echo -n ">> "
read server_port

if [ -z $server_port ]
    then 
    server_port="15213"
fi

echo "Enter the server ip address (default 127.0.01)"
echo -n ">> "
read server_ip

if [ -z $server_ip ]
    then 
    server_ip="127.0.0.1"
fi

# Building client binary
cd ./client
go build -ldflags "-X main.TEST_SERVER_URL=$server_ip -X main.TEST_SERVER_PORT=$server_port -X main.CHANGE_HASH_RANDOM_VALUE=$RANDOM" .

# Stripping binary to make reversing harder and decrease size
strip ./client


cd ../server
go build -ldflags "-X main.SERVER_PORT=$server_port"

strip ./server

echo "Compiling done!"
