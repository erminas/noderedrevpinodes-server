#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""Server backend for RevPi-NodeRed-Nodes
   The server is needed to communicate between the nodes and the pins on the RevPi.
   It is a python based websocket server which uses the python library RevPiModIO.
"""
import os
import pathlib
import distro
import traceback
import uuid

__author__ = "erminas GmbH"
__copyright__ = "Copyright (C) 2019 erminas GmbH"
__license__ = "LGPL-3.0-only"
__email__ = "info@erminas.de"

import argparse
import time
import threading
import logging
from logging.handlers import RotatingFileHandler
import json
import signal
import sys
import bcrypt
import ssl
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

import revpimodio2

import asyncio
import websockets

# set global logger
root = logging.getLogger()
if root.handlers:
    for handler in root.handlers:
        root.removeHandler(handler)
logging.basicConfig(handlers=[RotatingFileHandler('/var/log/revpi-server.log', maxBytes=100000000, backupCount=5)],
                    level=logging.INFO,
                    format='%(asctime)s %(name)-12s: %(levelname)-8s %(message)s')

SSL_PROTOCOLS = (asyncio.sslproto.SSLProtocol,)


def ignore_aiohttp_ssl_eror(loop):
    """Ignore aiohttp #3535 / cpython #13548 issue with SSL data after close
    There is an issue in Python 3.7 up to 3.7.3 that over-reports a
    ssl.SSLError fatal error (ssl.SSLError: [SSL: KRB5_S_INIT] application data
    after close notify (_ssl.c:2609)) after we are already done with the
    connection. See GitHub issues aio-libs/aiohttp#3535 and
    python/cpython#13548.
    Given a loop, this sets up an exception handler that ignores this specific
    exception, but passes everything else on to the previous exception handler
    this one replaces.
    Checks for fixed Python versions, disabling itself when running on 3.7.4+
    or 3.8.
    """
    if sys.version_info >= (3, 7, 4):
        return

    orig_handler = loop.get_exception_handler()

    def ignore_ssl_error(loop, context):
        if context.get("message") in {
            "SSL error in data received",
            "Fatal error on transport",
        }:
            # validate we have the right exception, transport and protocol
            exception = context.get('exception')
            protocol = context.get('protocol')
            if (
                    isinstance(exception, ssl.SSLError)
                    and exception.reason == 'KRB5_S_INIT'
                    and isinstance(protocol, SSL_PROTOCOLS)
            ):
                # if loop.get_debug():
                logging.warning('Ignoring asyncio SSL KRB5_S_INIT error')
                return
        if orig_handler is not None:
            orig_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(ignore_ssl_error)


class Websocket_Client:
    def __init__(self, websocket):
        self.websocket = websocket
        self.id = uuid.uuid4()
        self.message_queue = []


class RevPiServer:
    command_list = ["commands", "list", "output"]

    def __init__(self, port, block_external_connections, loop=None):
        self.port = port
        self.block_external_connections = block_external_connections

        self.revpi = None
        self.io_list = None
        self.running = True

        self.supported_client_versions = ["1.0.9"]
        self.allow_all_user = True
        self.private_key_file = None
        self.cert_file = None

        self.config_location = "/home/pi/.config/noderedrevpinodes-server/server_config.json"
        self.supported_config_versions = ["noderedrevpinodes-server_config_1.0.0",
                                          "noderedrevpinodes-server_config_1.0.1"]

        self.load_config()  # overwrite defaults if config file is found

        # exit function to clean
        signal.signal(signal.SIGTERM, self.clean_on_exit)
        signal.signal(signal.SIGINT, self.clean_on_exit)

        self.initialize_revpimodio()
        self.get_io_list(True)
        self.register_input_callbacks()

        self.connected_clients = []
        # self.connected_clients_lock = threading.Lock()

        self.authorized_user = {}
        self.load_authorized_user()
        self.authorized_clients = []

        if self.private_key_file is None or self.cert_file is None or not os.path.isfile(
                self.private_key_file) or not os.path.isfile(self.cert_file):
            logging.warning("Can't find valid certificate files, using self signed certificate instead!")
            self.generate_self_signed_certificate()

        if loop:
            self.event_loop = loop
            asyncio.set_event_loop(loop)
        else:
            self.event_loop = asyncio.get_event_loop()

        ignore_aiohttp_ssl_eror(self.event_loop)
        self.event_loop_thread = None

        self.event_loop_thread = threading.Thread(target=self.start_websocket_loop)

        threading.Thread(target=self.watchdog_revpimodio).start()

    def initialize_revpimodio(self):
        if self.revpi:  # clean if already existent
            self.revpi.cleanup()
            self.revpi = None

        if not os.path.isfile("/etc/revpi/config.rsc") and not os.path.isfile("/opt/KUNBUS/config.rsc"):
            logging.error("No hardware configuration found. Please configure hardware in PiCtory!")

            while not os.path.isfile("/etc/revpi/config.rsc") and not os.path.isfile("/opt/KUNBUS/config.rsc"):
                time.sleep(60)

            logging.info("New hardware configuration found. Continuing..")

        # init RevPiModIO with auto refresh
        # shared_procimg set to true ist not recommended (slow speed)
        # if its too slow, either we make our own cycle_cloop where we update the reg_events on our own or
        # we change the revpimodio2 lib so outputs set by other processes are read into the buffers. currently
        # external output changes are ignored and all values are taken from the intern buffers
        self.revpi = revpimodio2.RevPiModIO(autorefresh=True, shared_procimg=True)

    def start_revpi_modio(self):
        self.revpi.mainloop(blocking=False)

    def start_websocket_loop(self):
        ip = '0.0.0.0'
        if self.block_external_connections:
            ip = '127.0.0.1'
        if distro.linux_distribution()[2] == 'stretch':
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
            localhost_pem = os.path.abspath(self.cert_file)

            ssl_context.load_cert_chain(self.cert_file, self.private_key_file)

            start_server = websockets.serve(self.handle_clients, ip, self.port, loop=self.event_loop, ssl=ssl_context)
        else:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            localhost_pem = os.path.abspath(self.cert_file)

            ssl_context.load_cert_chain(self.cert_file, self.private_key_file)

            start_server = websockets.serve(self.handle_clients, ip, self.port, loop=self.event_loop, ssl=ssl_context,
                                            ping_timeout=None, compression=None)

        self.event_loop.run_until_complete(start_server)
        self.event_loop.run_forever()

    def register_input_callbacks(self):
        # register all the input events
        list = self.io_list['inputs']
        exclude = []  # ["Core_Frequency", "RevPiIOCycle", "RevPiStatus", "Core_Temperatur", "RS485ErrorCnt"]
        for x in list:
            if x['name'] not in str(exclude):
                logging.debug("Register input " + str(x))
                self.revpi.io[x['name']].reg_event(self.pin_event_callback, prefire=True)

    def watchdog_revpimodio(self):
        while self.running:
            if self.revpi.ioerrors:
                logging.warning("Restarting revpimodio")
                self.initialize_revpimodio()
                self.get_io_list(True)
                self.register_input_callbacks()
                self.start_revpi_modio()
            time.sleep(1)

    def convert_value(self, val):
        if isinstance(val, bool):
            val = int(val)

        if isinstance(val, bytes):
            val = int.from_bytes(val, "little")
        return val

    def pin_event_callback(self, io_name, io_value):
        # workaorund for undefined behaviour in piTest. 4 byte length values are interpreted like signed values
        if self.revpi.io[io_name].length == 4:
            self.revpi.io[io_name].signed = True
            io_value = self.revpi.io[io_name].value

        val = self.convert_value(io_value)
        val = str(val)
        io_name = str(io_name)

        message = {"name": io_name, "value": val}
        # with self.connected_clients_lock:
        for client in self.connected_clients:
            if client.id in self.authorized_clients:
                self.send_websocket_message(client, "input;" + json.dumps(message))

    def get_io_list(self, force_update):
        if self.io_list and not force_update:
            return self.io_list
        elif force_update:
            io_list = {"inputs": [], "outputs": [], "mem": []}
            ios = list(self.revpi.io.__dict__.keys())
            for attr in ios:
                io = self.revpi.io[attr]
                if isinstance(io, revpimodio2.io.IntIO) or isinstance(io, revpimodio2.io.IOBase):
                    val = self.convert_value(io.value)

                    default = self.convert_value(io.defaultvalue)

                    val_type = type(io.value).__name__

                    new_attr = {"name": attr, "default": default, "value": val, "type": io.type, "valType": val_type,
                                "bmk": io.bmk, "address": io.address}
                    if io.type == 300:
                        io_list["inputs"].append(new_attr)
                    elif io.type == 301:
                        io_list["outputs"].append(new_attr)
                    else:
                        io_list["mem"].append(new_attr)
            self.io_list = io_list

            return self.io_list
        else:
            return {}

    def load_authorized_user(self):
        if os.path.isfile("user.json"):
            with open("user.json", 'r') as file:
                self.authorized_user = json.load(file)

    def check_user_credentials(self, user, password):
        authorized = False
        if user and password and user in self.authorized_user:
            authorized = bcrypt.checkpw(password.encode(), self.authorized_user[user].encode())
        return authorized

    def send_websocket_message(self, client, message):
        client.message_queue.append(message)

    # @asyncio.coroutine
    async def publish_messages_to_client(self, client, path):
        try:
            while client.message_queue:
                message = client.message_queue.pop(0)
                logging.debug(str(client.id) + "," + json.dumps(message))
                await client.websocket.send(message)
        except websockets.ConnectionClosed as e:
            logging.error("Connection to websocket client " + str(client.id) + " closed unexpected: " + str(e))

    # @asyncio.coroutine
    async def get_client_requests(self, client, path):
        try:
            while True:
                message = await client.websocket.recv()
                global revPiServer
                nmessage = message.split("#")

                command = nmessage[0]
                args = []
                if len(nmessage) > 1:
                    if nmessage[1] != "undefined":
                        args = json.loads(nmessage[1])

                if command == "login":
                    client_version = str(args[0])
                    user = str(args[1])
                    password = str(args[2])
                    getAutomaticUpdates = str(args[3])

                    if not client_version in self.supported_client_versions:
                        logging.info("Unsupported client version")
                        return_message = {"error": "ERROR_UNSUPPORTED_VERSION"}
                        self.send_websocket_message(client, message + ";" + json.dumps(return_message))
                    elif self.allow_all_user or client.id in self.authorized_clients or self.check_user_credentials(
                            user,
                            password):
                        logging.info("User is authorized")
                        self.authorized_clients.append(client.id)

                        if getAutomaticUpdates == 'True':
                            self.connected_clients.append(client)

                        return_message = {}
                        self.send_websocket_message(client, message + ";" + json.dumps(return_message))
                    else:
                        logging.warning("Unauthorized user!")

                        return_message = {"error": "ERROR_AUTH"}
                        self.send_websocket_message(client, message + ";" + json.dumps(return_message))
                else:
                    if not client.id in self.authorized_clients:
                        logging.warning("Unauthorized user!")
                        return_message = {"error": "ERROR_AUTH"}
                        self.send_websocket_message(client, message + ";" + json.dumps(return_message))
                        return

                    if command == "list":  # list io pins
                        force_update = (args[0] == 'True')
                        self.send_websocket_message(client, message + ";" + json.dumps(self.get_io_list(force_update)))
                    elif command == "output":  # write to pin
                        try:
                            io_name = str(args[0])
                            raw_val = int(args[1])
                            validInputs = True
                        except TypeError:
                            io_name = str(args[0])
                            raw_val = str(args[1])
                            logging.warning("Invalid input " + raw_val + " for setting output of pin " + io_name)
                            validInputs = False

                        if validInputs and (io_name in self.revpi.io):
                            if isinstance(self.revpi.io[io_name].value, bool):
                                try:
                                    val = bool(int(raw_val))
                                except ValueError:
                                    val = False
                            elif isinstance(self.revpi.io[io_name].value, int):
                                try:
                                    val = int(raw_val)
                                except ValueError:
                                    val = 0
                            else:
                                val = raw_val
                            try:
                                time.sleep(0.04)
                                self.revpi.io[io_name].value = val
                                self.revpi.writeprocimg()
                                return_message = {}
                                self.send_websocket_message(client, message + ";" + json.dumps(return_message))
                            except OverflowError:
                                logging.warning("Error setting " + io_name + " to " + str(val) + ", overflow!")
                                return_message = {"error": "ERROR_UNKNOWN"}
                                self.send_websocket_message(client, message + ";" + json.dumps(return_message))
                        else:
                            return_message = {"name": io_name, "value": raw_val, "error": "ERROR_PIN"}
                            self.send_websocket_message(client, message + ";" + json.dumps(return_message))

                    elif command == "getpin":  # get single pin value
                        io_name = str(args[0])
                        val = ""

                        if io_name in self.revpi.io:
                            val = self.convert_value(self.revpi.io[io_name].value)
                            val = str(val)
                            return_message = {"name": io_name, "value": val}

                            self.send_websocket_message(client, message + ";" + json.dumps(return_message))
                        else:
                            return_message = {"name": io_name, "value": val, "error": "ERROR_PIN"}
                            self.send_websocket_message(client, message + ";" + json.dumps(return_message))

                    else:  # print server commands
                        self.send_websocket_message(client, message + ";" + (','.join(revPiServer.command_list)))
        except websockets.ConnectionClosed as e:
            logging.error("Connection to websocket client " + str(client.id) + " closed unexpected: " + str(e))

    # @asyncio.coroutine
    async def handle_clients(self, websocket, path):
        if self.block_external_connections and \
                websocket.remote_address[0] != "localhost" and websocket.remote_address[0] != "127.0.0.1":
            logging.warning("Closing external connection of client with address " + str(websocket.remote_address[0]))
            websocket.close()

        client = Websocket_Client(websocket)
        logging.info("New client connected and was given id " + str(client.id))

        try:
            asyncio.ensure_future(self.get_client_requests(client, path))
            while self.running and client.websocket.open:
                asyncio.ensure_future(self.publish_messages_to_client(client, path))
                await asyncio.sleep(0.1)

        except Exception as e:
            logging.error("There was an unexpected error. " + str(e))
            logging.error("Traceback: " + traceback.format_exc())
        finally:
            if client in self.authorized_clients:
                self.authorized_clients.remove(client)
            if client in self.connected_clients:
                self.connected_clients.remove(client)
            logging.info("Client( " + str(client.id) + " ) disconnected")

    def close(self):
        self.running = False

        # exit websocket server
        self.event_loop.call_soon_threadsafe(self.event_loop.stop)

        self.revpi.cleanup()

    def clean_on_exit(self, signum, frame):
        self.close()
        sys.exit()

    def generate_self_signed_certificate(self):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.private_key_file = "self_signed_key.pem"

        with open(self.private_key_file, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"KUNBUS GmbH"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"kunbus.de"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
            # Sign our certificate with our private key
        ).sign(key, hashes.SHA256(), default_backend())
        # Write our certificate out to disk.
        self.cert_file = "self_signed_certificate.pem"
        with open(self.cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def load_config(self):
        try:
            with open(self.config_location) as json_data_file:
                json_data = json.load(json_data_file)

                if json_data:
                    config_version = json_data['version']

                    if config_version in self.supported_config_versions:
                        try:
                            self.port = json_data['port']
                            self.block_external_connections = json_data['block_external_connections']

                            if config_version == "noderedrevpinodes-server_config_1.0.1":
                                self.allow_all_user = json_data['allow_all_user']
                                self.private_key_file = json_data['private_key_file']
                                self.cert_file = json_data['cert_file']
                        except KeyError as ex:
                            logging.error("Broken configuration file, missing key: " + str(ex))
                    else:
                        logging.exception("Configuration version " + str(config_version) + " not supported!")
        except json.decoder.JSONDecodeError:
            logging.exception("Error parsing config file  " + self.config_location + ": ")
        except FileNotFoundError:
            logging.warning("No configuration file was found. Default options applied.")
        except PermissionError:
            logging.exception("Permission to open config file at " + self.config_location + " was denied.")

    def start(self, args):
        # Start revpi pin listener thread
        logging.info("Start revpi thread")

        self.start_revpi_modio()

        # Start websocket server thread
        logging.info("Start websocket server thread")
        self.event_loop_thread.start()


def add_authorized_user(user, password):
    authorized_user = {}
    if os.path.isfile("user.json"):
        with open("user.json", 'r') as file:
            authorized_user = json.load(file)
    authorized_user[user] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')

    with open('user.json', 'w', encoding='utf-8') as f:
        json.dump(authorized_user, f, ensure_ascii=False, indent=4)


def remove_authorized_user(user):
    authorized_user = {}
    if os.path.isfile("user.json"):
        with open("user.json", 'r') as file:
            authorized_user = json.load(file)
    authorized_user.pop(user, None)
    with open('user.json', 'w', encoding='utf-8') as f:
        json.dump(authorized_user, f, ensure_ascii=False, indent=4)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Revpi Node Server.')

    parser.add_argument('--adduser', help='add authorized user', nargs='?', default=False, const=True)
    parser.add_argument('--password', help='password for new user', nargs='?', default=False, const=True)
    parser.add_argument('--removeuser', help='remove authorized user', nargs='?', default=False, const=True)

    args = parser.parse_args()

    if args.removeuser:
        if len(args.removeuser) < 1 or len(args.removeuser) > 72:
            logging.error("Username has to be between 0 and 73 characters long!")
            exit()

        remove_authorized_user(args.removeuser)

        logging.info("Authorized user deleted!")
        exit()

    if args.adduser and args.password:
        if len(args.adduser) < 1 or len(args.adduser) > 72:
            logging.error("Username has to be between 0 and 73 characters long!")
            exit()

        if len(args.password) < 1 or len(args.password) > 72:
            logging.error("Password has to be between 0 and 73 characters long!")
            exit()

        add_authorized_user(args.adduser, args.password)

        logging.info("Authorized user added!")
        exit()

    port = 8000
    block_external_connections = False
    revPiServer = RevPiServer(port, block_external_connections)
    revPiServer.start(args)
