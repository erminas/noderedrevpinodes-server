# Official Revolution Pi Nodes Server

Python/Websocket based [Revolution Pi](https://revolution.kunbus.de/) Nodes for [Node-RED](https://nodered.org/).

Server
------
The server is needed to communicate between the Node-RED RevPi nodes and the I/O pins on the RevPi. 
It is a Python based websocket server which utilizes the Python library [RevPiModIO](https://revpimodio.org/) to interface between the RevPi process image and Node-RED. The associated RevPi nodes can be acquired via the [node-red-contrib-revpi-nodes package](https://flows.nodered.org/node/node-red-contrib-revpi-nodes) in the Node-RED Library or [here](https://github.com/erminas/node-red-contrib-revpi-nodes).

### Requirements
The server requires [Raspbian Stretch ](https://revolution.kunbus.de/shop/de/stretch) or [Raspbian Buster ](https://revolutionpi.de/shop/de/buster).

### Installation
1. Install the server with the following command:
```
sudo apt-get install noderedrevpinodes-server
```
Alternative (direct download from GitHub):
```
wget https://github.com/erminas/noderedrevpinodes-server/releases/download/1.0.3/noderedrevpinodes-server_1.0.3.deb
sudo apt install ./noderedrevpinodes-server_1.0.3.deb
```
Please change the version "1.0.3" and the filename "noderedrevpinodes-server_1.0.3.deb" to the respective [release](https://github.com/erminas/noderedrevpinodes-server/releases) you want to install.

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
    "version": "noderedrevpinodes-server_config_1.0.1",
    "port": 8000,
    "block_external_connections": true,
    "allow_all_user": true
}
```

**port**: Port used by the server. Default: 8000

**block_external_connections**: Actively block external connections, therefore only allow connections from Node-RED on localhost. Recommended setting in potentially unsafe environments is true. Default: true 

**allow_all_user**: By default all user are allowed to connect. Set to false, if only authorized users should be able to connect. Default: true

Changes to the configuration file only take effect after the daemon is restarted.

### Security 

For secure communication server certificates are needed. It is strongly recommended to ask your local network administrator to provide X.509 certificate files for the server. Using the locally provided certificate files the server can be securly identified. If only encryption is needed and no server authentification, use the following steps:

1. Generate the certificates with the following steps:

        ```
        mkdir /home/pi/revpinodered-certificates
        cd /home/pi/revpinodered-certificates
        ```

    Option A: Generate your certificate with an root-certificate (CA)

        1.1 Generate the private key for the root certificate (CA)

        ```
        openssl genrsa -aes256 -out ca-key.pem 2048
        ```

        1.2 Generate the root certificate (CA)

        OpenSSL will ask for some informations. The common name is important and has to be correct.

        ```
        openssl req -x509 -new -nodes -extensions v3_ca -key ca-key.pem -days 1024 -out ca-root.pem -sha512
        ```

        1.3 Optionally move the root certifcate to the client. 

        1.4 Generate a generate a private key for your certificate

        ```
        openssl genrsa -out private_key.pem 2048
        ```

        1.5 Generate a certificate request.

        ```
        openssl req -new -key private_key.pem -out certificate-req.csr -sha512
        ```

        1.6 Generate your certificate

        ```
        openssl x509 -req -days 365 -sha512 -in certificate-req.csr -CA ca-root.pem -CAkey ca-key.pem -CAcreateserial  \
        -extensions SAN \
        -extfile <(cat /etc/ssl/openssl.cnf \
        <(printf "\n[SAN]\nsubjectAltName=DSN:mydomain.com")) \
        -out certificate-pub.pem 
        ```

    Option B: Generate your certificate without an root-certificate. 

        ```
        openssl req -nodes -new -x509 -keyout private_key.pem -out certificate-pub.pem
        ```

2. Adjust the configuration file so it points to the generated certificate files:

```
{
    "version": "noderedrevpinodes-server_config_1.0.1",
	...
    "private_key_file": "/home/pi/revpinodered-certificates/private_key.pem",
    "cert_file": "/home/pi/revpinodered-certificates/certificate-pub.pem",
	....
}
```

3. Restart the server and change the server configuration in your flows. If Option A was chosen, Strict SSL must be checked and the path to the root-certificate has to be set.

### User Authorization

A basic user authorization can be optionally activated in the configuration file. It is advised to use it only for internal purposes and in its current implementation is not meant to provide noteworthy additonal security. 

1. Set **allow_all_user** in configuration file to false:
```
{
    "version": "noderedrevpinodes-server_config_1.0.1",
	...
    "allow_all_user": false,
	....
}
```

2. Add an authorized user:
```
cd /usr/share/noderedrevpinodes-server/
sudo python3 revpi-server.py --adduser my_user --password my_password
```

3. Optionally remove an authorized user:
```
cd /usr/share/noderedrevpinodes-server/
sudo python3 revpi-server.py --removeuser my_user
```

4. Restart server:
```
sudo systemctl restart noderedrevpinodes-server.service
```

### Remarks

The server uses a direct output mode, so other processes and services can concurrently write to the output pins. 
This has a negative effect on the overall performance. See also the remarks on direct_output parameter in the [RevPiModIO Documentation](https://revpimodio.org/en/doc2/).
