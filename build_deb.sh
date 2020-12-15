#!/bin/bash

mkdir -p build/noderedrevpinodes-server-1.0.2/noderedrevpinodes-server
mkdir -p build/noderedrevpinodes-server-1.0.2/doc

cp revpi-server.py build/noderedrevpinodes-server-1.0.2/noderedrevpinodes-server/

touch build/noderedrevpinodes-server-1.0.2/noderedrevpinodes-server/revpi-server.log

cp bin/noderedrevpinodes-server.service build/noderedrevpinodes-server-1.0.2/debian

cp -r license/ build/noderedrevpinodes-server-1.0.2/doc/

cd build/noderedrevpinodes-server-1.0.2
dpkg-buildpackage -b -us -uc -a armhf
