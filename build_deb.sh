#!/bin/bash

mkdir -p build/noderedrevpinodes-server-1.0.3/noderedrevpinodes-server
mkdir -p build/noderedrevpinodes-server-1.0.3/doc

cp revpi-server.py build/noderedrevpinodes-server-1.0.3/noderedrevpinodes-server/

touch build/noderedrevpinodes-server-1.0.3/noderedrevpinodes-server/revpi-server.log

cp bin/noderedrevpinodes-server.service build/noderedrevpinodes-server-1.0.3/debian

cp -r license/ build/noderedrevpinodes-server-1.0.3/doc/

cd build/noderedrevpinodes-server-1.0.3
dpkg-buildpackage -b -us -uc -a armhf
