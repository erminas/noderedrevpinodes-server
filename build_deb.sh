#!/bin/bash

mkdir -p build/noderedrevpinodes-server-1.0.5/noderedrevpinodes-server
mkdir -p build/noderedrevpinodes-server-1.0.5/doc

cp revpi-server.py build/noderedrevpinodes-server-1.0.5/noderedrevpinodes-server/

cp bin/noderedrevpinodes-server.service build/noderedrevpinodes-server-1.0.5/debian

cp -r license/ build/noderedrevpinodes-server-1.0.5/doc/

cd build/noderedrevpinodes-server-1.0.5
dpkg-buildpackage -b -us -uc -a armhf
