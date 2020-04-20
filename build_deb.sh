#!/bin/bash

mkdir -p build/noderedrevpinodes-server-1.0.1/noderedrevpinodes-server
mkdir -p build/noderedrevpinodes-server-1.0.1/doc

cp revpi-server.py build/noderedrevpinodes-server-1.0.1/noderedrevpinodes-server/
cp -r websocket_server/ build/noderedrevpinodes-server-1.0.1/noderedrevpinodes-server/

touch build/noderedrevpinodes-server-1.0.1/noderedrevpinodes-server/revpi-server.log

cp bin/noderedrevpinodes-server.service build/noderedrevpinodes-server-1.0.1/debian

cp -r license/ build/noderedrevpinodes-server-1.0.1/doc/

cd build/noderedrevpinodes-server-1.0.1
dpkg-buildpackage -b -us -uc -a armhf
