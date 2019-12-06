# Official Revolution Pi Nodes Server

Python/Websocket based [Revolution Pi](https://revolution.kunbus.de/) Nodes for [Node-RED](https://nodered.org/).

Server
------
The server is needed to communicate between the Node-RED RevPi nodes and the I/O pins on the RevPi. 
It is a Python based websocket server which utilizes the Python library [RevPiModIO](https://revpimodio.org/) to interface between the RevPi process image and Node-RED. The associated RevPi nodes can be acquired via the [node-red-contrib-revpi-nodes package](https://flows.nodered.org/node/node-red-contrib-revpi-nodes) in the Node-RED Library or [here](https://github.com/erminas/node-red-contrib-revpi-nodes).

### Installation
1. Install the server with the following command:
```
sudo apt-get install noderedrevpinodes-server
```
Alternative (direct download from GitHub):
```
wget https://github.com/erminas/noderedrevpinodes-server/releases/download/v1.0.0/noderedrevpinodes-server_1_0_0.deb
sudo apt-get install ./noderedrevpinodes-server_1_0_0.deb
```
Please change the version "v1.0.0" and the filename "noderedrevpinodes-server_1_0_0.deb" to the respective version you want to install.

2. The server is automatically started and runs in the background as daemon.

3. The daemon can be manually started, stopped and restarted with:
```
sudo systemctl start noderedrevpinodes-server.service
sudo systemctl stop noderedrevpinodes-server.service
sudo systemctl restart noderedrevpinodes-server.service
```

### Remarks

The server uses a direct output mode, so other processes and services can concurrently write to the output pins. 
This has a negative effect on the overall performance. See also the remarks on direct_output parameter in the [RevPiModIO Documentation](https://revpimodio.org/en/doc2/).
