#!/bin/bash

mkdir -p build/noderedrevpinodes-server-1.0.4/noderedrevpinodes-server
mkdir -p build/noderedrevpinodes-server-1.0.4/doc

cp revpi-server.py build/noderedrevpinodes-server-1.0.4/noderedrevpinodes-server/

cp bin/noderedrevpinodes-server.service build/noderedrevpinodes-server-1.0.4/debian

cp -r license/ build/noderedrevpinodes-server-1.0.4/doc/

cd build/noderedrevpinodes-server-1.0.4
dpkg-buildpackage -b -us -uc -a armhf
