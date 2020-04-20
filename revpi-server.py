#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""Server backend for RevPi-NodeRed-Nodes
   The server is needed to communicate between the nodes and the pins on the RevPi.
   It is a python based websocket server which uses the python library RevPiModIO.
"""

__author__ = "erminas GmbH"
__copyright__ = "Copyright (C) 2019 erminas GmbH"
__license__ = "LGPL-3.0-only"
__email__ = "info@erminas.de"

import time
import threading
import logging
import json
import random
import atexit
import uuid
import subprocess
import signal
import sys

import revpimodio2

# source: https://github.com/Pithikos/python-websocket-server
from websocket_server import WebsocketServer

# set global logger
root = logging.getLogger()
if root.handlers:
    for handler in root.handlers:
        root.removeHandler(handler)
logging.basicConfig(filename='revpi-server.log', level=logging.INFO,
                    format='%(asctime)s %(name)-12s: %(levelname)-8s %(message)s')


class FirewallBlocker:

    def __init__(self, port, allowed_ip):
        self.port = port
        self.allowed_ip = allowed_ip
        self.random_id = str(uuid.uuid4()).replace('-', '')

    def block_connections(self):
        accept_rule = "iptables -A INPUT -p tcp --dport " + str(self.port) + " -s " + self.allowed_ip + " -j ACCEPT " \
                                                                                                        "-m comment --comment " + self.random_id

        process_accept_rule = subprocess.Popen(accept_rule, shell=True)
        process_accept_rule.wait()

        drop_rule = "iptables -A INPUT -p tcp --dport " + str(self.port) + " -j DROP " \
                                                                           "-m comment --comment " + self.random_id

        process_drop_rule = subprocess.Popen(drop_rule, shell=True)
        process_drop_rule.wait()

        if process_accept_rule.poll() != 0 or process_drop_rule.poll() != 0:
            logging.error("Error changing the firewall rules, please make sure to run as root.")
            sys.exit(1)

    def revert_block_connections(self):
        revert_rule = "iptables-save | grep -v " + self.random_id + " | iptables-restore"

        process_rule = subprocess.Popen(revert_rule, shell=True)
        process_rule.wait()

        if process_rule.poll() != 0:
            logging.error("Couldn't restore firewall rules, please make sure to run as root.")


class RevPiServer:
    command_list = ["commands", "list", "output"]

    def __init__(self, port, block_external_connections):
        self.port = port
        self.block_external_connections = block_external_connections

        self.revpi = None
        self.io_list = None
        self.running = True

        self.load_config()  # overwrite defaults if config file is found

        # block external connections on port
        if self.block_external_connections:
            self.firewall = FirewallBlocker(self.port, "127.0.0.1")
            self.firewall.block_connections()

        # exit function to clean
        signal.signal(signal.SIGTERM, self.clean_on_exit)
        signal.signal(signal.SIGINT, self.clean_on_exit)

        self.initialize_revpimodio()
        self.get_io_list(True)
        self.register_input_callbacks()

        # config websocket server
        self.websocketserver = WebsocketServer(self.port, host='0.0.0.0', loglevel=logging.INFO)
        self.websocketserver.set_fn_message_received(self.handle_websocket_message)
        self.websocketserver.set_fn_new_client(self.handle_websocket_connected)
        self.websocketserver.set_fn_client_left(self.handle_websocket_close)

        # init websocket server thread
        self.websocketThread = threading.Thread(target=self.websocketserver.run_forever, args=[])

        threading.Thread(target=self.watchdog_revpimodio).start()

    def initialize_revpimodio(self):
        if self.revpi:  # clean if already existent
            self.revpi.cleanup()
            self.revpi = None

        # init RevPiModIO with auto refresh
        # direct_output set to true ist not recommended (slow speed)
        # if its too slow, either we make our own cycle_cloop where we update the reg_events on our own or
        # we change the revpimodio2 lib so outputs set by other processes are read into the buffers. currently
        # external output changes are ignored and all values are taken from the intern buffers
        self.revpi = revpimodio2.RevPiModIO(autorefresh=True, direct_output=True)

    def start_revpi_modio(self):
        self.revpi.mainloop(blocking=False)

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

        logging.info("input;" + json.dumps(message))
        self.websocketserver.send_message_to_all("input;" + json.dumps(message))
        logging.debug(str(time.time()) + "," + json.dumps(message))

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

    def handle_websocket_message(self, client, server, message):
        global revPiServer
        nmessage = message.split("#")

        command = nmessage[0]
        args = []
        if len(nmessage) > 1:
            if nmessage[1] != "undefined":
                args = json.loads(nmessage[1])

        if command == "list":  # list io pins
            force_update = (args[0] == 'True')
            server.send_message(client, message + ";" + json.dumps(self.get_io_list(force_update)))
        elif command == "output":  # write to pin
            if isinstance(self.revpi.io[args[0]].value, bool):
                try:
                    val = bool(int(args[1]))
                except ValueError:
                    val = False
            elif isinstance(self.revpi.io[args[0]].value, int):
                try:
                    val = int(args[1])
                except ValueError:
                    val = 0
            else:
                val = args[1]
            try:
                self.revpi.io[args[0]].value = val
                self.revpi.writeprocimg()
                server.send_message(client, message + ";done")
            except OverflowError:
                logging.warning("Error setting " + str(args[0]) + " to " + str(val) + ", overflow!")
                server.send_message(client, message + ";ERROR_UNKNOWN")
        elif command == "getpin":  # get single pin value
            if args[0] in self.revpi.io:
                val = self.convert_value(self.revpi.io[args[0]].value)
            else:
                val = "ERROR_UNKNOWN"

            val = str(val)
            io_name = str(args[0])

            return_message = {"name": io_name, "value": val}

            logging.info(message + ";" + json.dumps(return_message))

            server.send_message(client, message + ";" + json.dumps(return_message))
        else:  # print server commands
            server.send_message(client, message + ";" + (','.join(revPiServer.command_list)))

    def handle_websocket_connected(self, client, server):
        if self.block_external_connections and \
                client['address'][0] != "localhost" and client['address'][0] != "127.0.0.1":
            logging.warning("Closing external connection of client with id " + str(client['id']))
            client['handler'].send_text("", opcode=0x8)
        else:
            logging.info("New client connected and was given id " + str(client['id']))

    def handle_websocket_close(self, client, server):
        logging.info("Client( " + str(client['id']) + " ) disconnected")

    def close(self):
        self.running = False

        # exit websocket server
        self.websocketserver.server_close()

        if self.block_external_connections:
            self.firewall.revert_block_connections()

        self.revpi.cleanup()

    def clean_on_exit(self, signum, frame):
        self.close()
        sys.exit()

    def load_config(self):
        config_location = "/home/pi/.config/noderedrevpinodes-server/server_config.json"

        supported_config_versions = ["noderedrevpinodes-server_config_1.0.0"]

        try:
            with open(config_location) as json_data_file:
                json_data = json.load(json_data_file)

                if json_data:
                    config_version = json_data['version']

                    if config_version in supported_config_versions:
                        self.port = json_data['port']
                        self.block_external_connections = json_data['block_external_connections']
                    else:
                        logging.exception("Configuration version " + str(config_version) + " not supported!")
        except json.decoder.JSONDecodeError:
            logging.exception("Error parsing config file  " + config_location + ": ")
        except FileNotFoundError:
            logging.warning("No configuration file was found. Default options applied.")
        except PermissionError:
            logging.exception("Permission to open config file at " + config_location + " was denied.")

    def start(self):
        # Start revpi pin listener thread
        logging.info("Start revpi thread")

        self.start_revpi_modio()

        # Start websocket server thread
        logging.info("Start websocket server thread")
        self.websocketThread.start()


if __name__ == "__main__":
    port = 8000
    block_external_connections = True
    revPiServer = RevPiServer(port, block_external_connections)
    revPiServer.start()
