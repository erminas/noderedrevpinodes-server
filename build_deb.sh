#!/bin/bash

cp revpi-server.py build/usr/share/noderedrevpinodes-server/
cp -r websocket_server/ build/usr/share/noderedrevpinodes-server/

cp -r bin/ build/usr/share/noderedrevpinodes-server/

cp copyright build/usr/share/doc/noderedrevpinodes-server/
cp -r license/ build/usr/share/doc/noderedrevpinodes-server/


sudo chown root:root -R build
sudo chmod -R 755 build
sudo find build/usr/share/doc/noderedrevpinodes-server/ -type f -exec chmod 644 -- {} +
sudo find build/usr/share/noderedrevpinodes-server/bin -type f -exec chmod 644 -- {} +

sudo dpkg -b build noderedrevpinodes-server.deb