import os
import json
import socket
import time
import random
import base64
import hashlib
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor

from mbedtls import pk

from utils import *


class ChatClient:
    """docstring for ChatClient"""

    def __init__(self, config_file="config.json", host="127.0.0.1", port=5005, client=""):
        self.host = host
        self.port = port
        self.client = client
        self.all_ca_dict = read_json_to_dict(config_file)
        self.public_ca_name = f"{client}_CA_public_key"
        self.ca_name = f"{client}_CA_key"
        self.client_public_key = self.all_ca_dict.get(
            "public_key").get(self.public_ca_name)
        self.client_key = self.all_ca_dict.get("key").get(self.ca_name)
        self.sign_name = f"{client}_CA_key_sign"
        self.sign_key = self.all_ca_dict.get("key_sign").get(self.sign_name)
        self.cookies = None
        self.Kabc = None
        self.key_dict = {
            self.client: bytes.fromhex(generate_random_hash256())
        }
        self.key_dict_temporary = {
            self.client: AES_session_key_temporary()
        }
        self.ECDHClient, self.ecdh_client_key_b64 = generate_client()
        self.ECDHServer, self.ecdh_server_key_b64 = generate_server()

        # init when client does not know others client public key
        # can request from server to get the other client public key
        self.public_ca_dict = {}

    # 3.
    # this is for each entities such as A, B, C do not know each other's public key before the first time
    # they communicate with each other, request for other's public key from server S
    # this part is for require 3 in project

    def request_for_other_public_key(self, sock, other_client):
        send_msg = {
            "action": "request_ca_public_key",
            "cookies": self.cookies,
            "content": {
                "ca_name": f"{other_client}_CA_public_key",
                "send_source": self.client
            }
        }
        send_msg_byte = dict_to_bytes(send_msg)
        sock.sendall(send_msg_byte)
        time.sleep(3)
        msg_res = sock.recv(RECV_LEN)
        msg_res_dict = bytes_to_dict(msg_res)
        print_info(f"recv public_key {msg_res_dict}")
        if msg_res_dict.get("reply_action") == "response_ca_public_key":
            return msg_res_dict.get("content")

    def login(self, sock):
        print_info(f"client {self.client} logining")
        login_msg = {
            "action": "login",
            "content": {
                "public_ca_name": f"{self.client}_CA_public_key",
                "public_ca_value": self.client_public_key,
                "sign_name": f"{self.client}_sign_key",
                "sign_value": self.sign_key,
                "send_source": self.client
            }
        }
        print("login_msg", login_msg)
        sock.sendall(dict_to_bytes(login_msg))
        time.sleep(3)
        login_res = (sock.recv(RECV_LEN))
        login_res_dict = bytes_to_dict(login_res)
        reply_action = login_res_dict.get("reply_action")
        if reply_action == "login_success":
            print_info(login_res_dict)
            self.cookies = login_res_dict.get("content")
            print(f"client : {self.client} cookies: {self.cookies}")

        else:
            print_info(login_res_dict.get("content"))
        # sock.close()

    # 6. this part include A, B, C send message to each other
    # 6. including RSA signature to authenticate the message, Integrity check, and confidentiality

    def handle_send_msg(self, sock, send_to, msg_type, message):
        msg_dict = {
            "type": msg_type,
            "value": message
        }
        send_msg = {
            "action": msg_type,
            "content": {
                "cookies": self.cookies,
                "send_source": self.client,
                "send_to": send_to,
                "source_signed": RSA_sign(self.client_key, msg_dict),
                "msg": msg_dict
            }
        }
        print_info(f"client: {self.client} to {send_to}")
        send_msg_byte = dict_to_bytes(send_msg)
        sock.sendall(send_msg_byte)
        time.sleep(3)

    def handle_recv_msg(self, sock):
        recv_msg = sock.recv(RECV_LEN)
        recv_msg_dict = bytes_to_dict(recv_msg)
        source = recv_msg_dict.get("content").get("send_source")
        print_info(f"source_public_ca_name {source}")
        source_public_ca_name = format_public_key(source)
        source_public_ca = self.public_ca_dict.get(source_public_ca_name)
        while source_public_ca is None:
            resp_pkey = (self.request_for_other_public_key(sock, source))
            self.public_ca_dict[resp_pkey["ca_name"]] = resp_pkey["ca_value"]

            source_public_ca = self.public_ca_dict.get(source_public_ca_name)
            print_info(
                f"get {source} public_key from S \n {source_public_ca }")
            time.sleep(3)

        source_signed_b64 = recv_msg_dict.get("content").get("source_signed")
        message = recv_msg_dict.get("content").get("msg")
        if RSA_verify(source_public_ca, message, source_signed_b64):
            print_info(f"message from source {source} signed OK!!!")
            return recv_msg_dict
        print_info(
            f"message from {self.client} signed failed\n  please use a correct key to signed")
        return None

    def exchange_key_random(self, ID, sock, ECDHClient, ecdh_client_key_b64, key_random):
        print_info(f"ecdh_client_key_b64 to {ID}")
        self.handle_send_msg(
            sock, ID, "ECDHClient_public_key", ecdh_client_key_b64)
        print_info(f"ecdh_client_key_b64 send to {ID} finished!")

        # revice the ECDHServer_public_key from other
        recv_B_ECDHServer = self.handle_recv_msg(sock)

        # calculate a temporary shared session key by ECDH for A and B, B and C, C and A
        # to protect the random number generated by A, B, and C
        b_ecdh_public_key = recv_B_ECDHServer.get("content").get("msg")
        print_info(f"{ID}_ecdh_public_key: \n{b_ecdh_public_key}")
        ECDHClient.import_SKE(base64_to_bytes(b_ecdh_public_key.get("value")))
        shared_key = ECDHClient.generate_secret()
        print_info(f"shared_key:\n{shared_key}")

        # send Key_random to B use AES encrpted by A_B_shared_key
        Key_random_encryted = AES_encrpted(
            shared_key.to_bytes(32, "big"), key_random)
        self.handle_send_msg(
            sock, ID, "AES_encryption_Key_random", Key_random_encryted)

    # 6. in this part exchange_key_random function is used to exchange the random number generated by A, B,
    # and C, and each entity send the random number to other entity such as A send the random number to B, B
    # send the random number to C, C send the random number to A
    # this part provide the confidentiality and integrity and authentication check
    # A , B and C use the ECDH to generate a temporary shared session key to protect the random number generated by A, B, and C

    def exchange_message_init(self, sock, sourceID, targetID1, targetID2):
        if self.client == sourceID:
            # exchange srouce to other
            time.sleep(5)
            print_info(
                " sleep 20 s waiting for  starting exchange_message_init ")
            # generate A B C session Key random
            key_random = self.key_dict.get(self.client)
            print_info(f"key_random: {key_random} \n {key_random.hex()}")
            self.exchange_key_random(
                targetID1, sock, self.ECDHClient, self.ecdh_client_key_b64, key_random)

            # ==============================================
            # exchange source to other

            self.exchange_key_random(
                targetID2, sock, self.ECDHClient, self.ecdh_client_key_b64, key_random)
            print_info(
                f"client: {self.client} send {key_random} \n {key_random.hex()} \n OK OK OK\n OKOKOKOK")

        else:
            time.sleep(5)
            client_ecdh_dict = self.handle_recv_msg(sock)
            print_info(f"client_ecdh_dict: {client_ecdh_dict}")

            if client_ecdh_dict.get("action") == "ECDHClient_public_key":
                A_ECDH_client_key = client_ecdh_dict.get("content").get("msg")
                self.ECDHServer.import_CKE(
                    base64_to_bytes(A_ECDH_client_key.get("value")))
                shared_key_client = self.ECDHServer.generate_secret()
                # reply ECDHServer_public_key to sourceID
                print_info(f"reply ECDHServer_public_key to {sourceID}")
                self.handle_send_msg(
                    sock, sourceID, "ECDHServer_public_key", self.ecdh_server_key_b64)

            client_ecdh_dict = self.handle_recv_msg(sock)
            if client_ecdh_dict.get("action") == "AES_encryption_Key_random":
                encrpted_key_random_message = client_ecdh_dict.get(
                    "content").get("msg").get("value")
                send_source = client_ecdh_dict.get(
                    "content").get("send_source")
                key_random = AES_decrpted(shared_key_client.to_bytes(
                    32, "big"), encrpted_key_random_message)
                self.key_dict[send_source] = key_random

                print_info(
                    f"client: {self.client} Get {send_source} key_random: {key_random} \n {key_random.hex()} \n  OK OK OK\n OKOKOKOK")

                if len(self.key_dict) == 3:
                    self.Kabc = combine_hash_values(
                        list(self.key_dict.values()))
                    print_info(
                        f"{self.Kabc} is \n {self.Kabc.hex()} \n  OK OK OK\n OKOKOKOK")

    def handle_server(self, sock):

        # first step login
        if self.cookies is None:
            self.login(sock)

        # second, exchange session Kabc
        if self.Kabc is None:
            self.exchange_message_init(sock, "A", "B", "C")
            time.sleep(10)
            self.exchange_message_init(sock, "B", "A", "C")
            time.sleep(10)
            self.exchange_message_init(sock, "C", "A", "B")

        else:
            time.sleep(30)
            print_info(
                f"client: {self.client} Waiting to Send and recv message")
            self.abc_message_send_recv_test(sock)

    def abc_message_send_recv_test(self, sock):
        print("self---------->", self)
        # B send message << hello A >> to A
        if self.client == "B":
            self.handle_send_msg(sock, "A", "AES_encryption_message",
                                 AES_encrpted(self.Kabc, b"hello A"))
            self.handle_send_msg(sock, "C", "AES_encryption_message",
                                 AES_encrpted(self.Kabc, b"hello C"))

        else:
            recv_dict = self.handle_recv_msg(sock)
            if recv_dict.get("action") == "AES_encryption_message":
                encrpted_message = recv_dict.get("content").get("msg")
                format_out = f"""
                {self.client} recv encryted_message from {recv_dict.get("content").get("send_source")}
                message: {encrpted_message}
                Kabc: {self.Kabc}
                decryted_message: {AES_decrpted(self.Kabc, encrpted_message.get("value"))}
                """
                print_info(format_out)

        # B send message << hello C >> to C
        # C send message << hello B >> to B

    def start_client(self):
        print("====" * 10)
        print(f"client: {self.client} starting")
        print(f"client {self.client} public_key is {self.client_public_key}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            sock.connect((self.host, self.port))
            while True:
                self.handle_server(sock)
                time.sleep(3)


if __name__ == '__main__':
    args = parse_args()
    print("ChatClinet args: ", args)
    chat_client = ChatClient(
        host=args.host, port=args.port, client=args.client)
    # start tcp server
    chat_client.start_client()
