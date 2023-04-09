"""
chat server S 
"""
import os
import json
import socket
import time
import random
import base64
import hashlib
import queue
import select
import socketserver
from threading import Thread
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor


from mbedtls import pk

from utils import *


class ChatServer(socketserver.BaseRequestHandler):
    """docstring for ChatServer"""

    def __init__(self, config_file="config.json", host="127.0.0.1", port=5005):
        self.host = host
        self.port = port
        self.all_ca_dict = read_json_to_dict(config_file)
        self.all_public_ca_dict = self.all_ca_dict.get("public_key")
        self.cookies_dict = {}
        self.sock_dict = {}
        self.sock_reply_msg_dict = {}

    def handle_client(self, client_sock):
        byte_data = client_sock.recv(RECV_LEN)
        if not byte_data:
            return None
        # print_info(byte_data)
        data_dict = bytes_to_dict(byte_data)
        # save client info  then Forward to other client
        send_source = data_dict.get("content").get("send_source")
        # print_info(f"Server recv msg from {send_source}")
        self.sock_dict[send_source] = client_sock
        # print(self.sock_dict)
        if data_dict["action"] == "login":
            self.handle_login(client_sock, data_dict["content"])
        elif data_dict["action"] == "request_ca_public_key":
            self.response_public_key(client_sock, data_dict)
        else:
            print(f"forword info {byte_data}")
            self.handle_send_msg(client_sock, data_dict)

    def response_public_key(self, client_sock, data_dict):
        cookies = data_dict.get("cookies")
        if self.check_cookies(cookies):
            print_info("cookies check OK ! has auth to use Server S")
        # print_info(data_dict)
        public_key_name = data_dict.get("content").get("ca_name")
        response_msg = {
            "reply_action": "response_ca_public_key",
            "content": {
                "ca_name": public_key_name,
                "ca_value": self.all_public_ca_dict.get(public_key_name)
            }
        }
        self.sock_reply_msg_dict[client_sock].put(dict_to_bytes(response_msg))
        # client_sock.sendall(dict_to_bytes(response_msg))
        # time.sleep(3)

    def check_cookies(self, content):
        """
        Check that the login cookies used for A/B/C and S communication are out of date
        By default, it expires if no message is sent for more than one hour
        COOKIES_EXPIRED, the value can be changed
        """
        cookies = content.get("cookies")
        current_timestamp = int(time.time())
        expired_timestamp = self.cookies_dict.get(cookies, "0")
        if current_timestamp - expired_timestamp < COOKIES_EXPIRED:
            self.cookies_dict[cookies] = current_timestamp
            return True
        return False

    def handle_login(self, client_sock, content):
        """
        client A/B/C to
        5. Each Entity must Authenticate itself to the Server S before it is allowed to use its service.
        Arguments:
            client_sock -- [client socket to Server S]
            content -- [client content to Server S]
        """
        ca_name = content["public_ca_name"]
        ca_value = content["public_ca_value"]
        sign_value = content["sign_value"]
        sign_result = RSA_verify(ca_value, ca_value, sign_value)
        if self.all_public_ca_dict.get(ca_name) == ca_value and sign_result == True:
            cookies = generate_random_hash256()
            expired_timestamp = int(time.time())
            self.cookies_dict[cookies] = expired_timestamp
            reply_dict = {
                "reply_action": "login_success",
                "content": {
                    "cookies": cookies,
                    "expired": expired_timestamp,
                    "client": ca_name.split("_")[0]
                }
            }
            self.cookies_dict["cookies"] = expired_timestamp

        else:
            reply_dict = {
                "reply_action": "login_failed",
                "content": "please use a correct ca public key"
            }
        reply_data = dict_to_bytes(reply_dict)
        self.sock_reply_msg_dict[client_sock].put(reply_data)
        # client_sock.sendall(reply_data)

    def handle_send_msg(self, client_sock, data_dict):
        send_source = data_dict.get("content").get("send_source")
        send_to = data_dict.get("content").get("send_to")
        send_to_sock = self.sock_dict.get(send_to)
        print("sock_info_other", send_to_sock)
        cookies = data_dict.get("content").get("cookies")
        if self.check_cookies(cookies) and send_to_sock:
            print_info(f"client {send_source} has auth to S \n Server S forword info to {send_to}")
            self.sock_reply_msg_dict[send_to_sock].put(dict_to_bytes(data_dict))
            # send_to_sock.sendall(dict_to_bytes(data_dict))

    def start_server(self):
        # start a server by TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            # sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            server.bind((self.host, self.port))
            server.listen(100)

            # Set the non-blocking mode
            server.setblocking(False)

            inputs = [server, ]

            # outputs store data that links need to return
            outputs = []
            # Add a while to loop the select
            while True:
                readable, writeables, exceptional = select.select(inputs, outputs, [])
                # print(readable, writeables, exceptional)
                # Receiving and processing
                for r in readable:
                    # Represents a new connection
                    if r is server:

                        # Wait for the client to generate the instance
                        conn, addr = server.accept()

                        print("client Connectiont from ", addr)
                        if conn not in inputs:
                            inputs.append(conn)
                        self.sock_reply_msg_dict[conn] = queue.Queue()

                    # Receive new connection data
                    else:
                        if r not in outputs:
                            outputs.append(r)
                        self.handle_client(r)

                # Send data: A list of links to return to the client
                for w in writeables:
                    # Retrieves the instance of the queue from the relink list
                    msg_queue = self.sock_reply_msg_dict.get(w)
                    while msg_queue and (not msg_queue.empty()):
                        data_to_client = msg_queue.get()
                        # Returns data to the client
                        w.sendall(data_to_client)
                        time.sleep(2)


if __name__ == '__main__':
    args = parse_args()
    print("ChatServer S args: ", args)
    chat_server = ChatServer(host=args.host, port=args.port)
    # start tcp server
    chat_server.start_server()
