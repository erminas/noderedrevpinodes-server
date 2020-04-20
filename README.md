# Official Revolution Pi Nodes Server

Python/Websocket based [Revolution Pi](https://revolution.kunbus.de/) Nodes for [Node-RED](https://nodered.org/).

Server
------
The server is needed to communicate between the Node-RED RevPi nodes and the I/O pins on the RevPi. 
It is a Python based websocket server which utilizes the Python library [RevPiModIO](https://revpimodio.org/) to interface between the RevPi process image and Node-RED. The associated RevPi nodes can be acquired via the [node-red-contrib-revpi-nodes package](https://flows.nodered.org/node/node-red-contrib-revpi-nodes) in the Node-RED Library or [here](https://github.com/erminas/node-red-contrib-revpi-nodes).

### Requirements
The server requires  [Raspbian Stretch ](https://revolution.kunbus.de/shop/de/stretch) for correct function.

### Installation
1. Install the server with the following command:
```
sudo apt-get install noderedrevpinodes-server
```
Alternative (direct download from GitHub):
```
wget https://github.com/erminas/noderedrevpinodes-server/releases/download/1.0.1/noderedrevpinodes-server_1.0.1.deb
sudo apt install ./noderedrevpinodes-server_1.0.1.deb
```
Please change the version "1.0.1" and the filename "noderedrevpinodes-server_1.0.1.deb" to the respective [release](https://github.com/erminas/noderedrevpinodes-server/releases) you want to install.

2. The server is automatically started and runs in the background as daemon.

3. The daemon can be manually started, stopped and restarted with:
```
sudo systemctl start noderedrevpinodes-server.service
sudo systemctl stop noderedrevpinodes-server.service
sudo systemctl restart noderedrevpinodes-server.service
```

### Configuration (optional)

You can optionally create a configuration file to change settings under "~/.config/noderedrevpinodes-server/server_config.json" with following structure:

```
{
    "version": "noderedrevpinodes-server_config_1.0.0",
    "port": 8000,
    "block_external_connections": true
}
```

**port**: Port used by the server. Default: 8000

**block_external_connections**: Actively block external connections, therefore only allow connections from Node-RED on localhost. Recommended setting in potentially unsafe environments is true. Default: true 

Changes to the configuration file only take effect after the daemon is restarted.

### Remarks

The server uses a direct output mode, so other processes and services can concurrently write to the output pins. 
This has a negative effect on the overall performance. See also the remarks on direct_output parameter in the [RevPiModIO Documentation](https://revpimodio.org/en/doc2/).
