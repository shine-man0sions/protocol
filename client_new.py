import datetime
import socket
import select
import sys
import pickle
from utils import *
import secrets
import hmac
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Random import get_random_bytes


class ChatClient:
    def __init__(self, config_file="config.json", host="127.0.0.1", port=5006, client=""):
        self.host = host
        self.port = port
        self.client = client
        self.all_ca_dict = read_json_to_dict(config_file)
        self.all_public_ca_dict = self.all_ca_dict.get("public_key")
        self.public_ca_name = f"{client}_CA_public_key"
        self.ca_name = f"{client}_CA_key"
        self.client_public_key = self.all_ca_dict.get("public_key").get(self.public_ca_name)
        self.client_key = self.all_ca_dict.get("key").get(self.ca_name)
        self.public_cas = self.all_ca_dict.get("public_key").get("S_CA_public_key")
        self.sign_name = f"{client}_CA_key_sign"
        self.sign_key = self.all_ca_dict.get("key_sign").get(self.sign_name)
        self.Kabc = None
        self.key_dict = {
            self.client: generate_random_hash256()
        }
        self.key_dict_all = {
        }
        self.key_dict_temporary = {
            self.client: generate_random_hash256()[:32]
        }

    """
        :param: sock
        :return: 1. login this is the first step, each client need to login to server to make sure 
                 the client is valid and they can communicate with S server
                 2. this part include authentication and integrity authentication: 
                 3. use rsa to encrypt the client public key and send to server 
                 4. integrity: use rsa to signature client public key and send to server
    """
    def login(self, sock):
        login_message = {
            "action": "login",
            "content": {
                "public_ca_name": f"{self.client}_CA_public_key",
                "public_ca_value": self.client_public_key,
                "sign_name": f"{self.client}_sign_key",
                "sign_value": self.sign_key,
                "send_source": self.client
            }
        }
        text = {
            "client": self.client,
            "text": f"{self.client}_CA_public_key"
        }
        message = transmit_encrypt_func(text, self.client_key, self.public_cas, login_message)

        sock.sendall(message)

        # Receive server response data, if login success,
        # print response message, if failure, print failure message reminder
        login_res_dict = pickle.loads(sock.recv(RECV_LEN))

        reply_action = login_res_dict.get("reply_action")
        if reply_action == "login_success":
            print(f"step 1 {self.client} can connect to S => {login_res_dict.get('reply_action')}")
        return None

    def exchange_message(self, sock, send_to1):

        # Obtain random numbers Na, Nb, Nc, and then forward them to other clients
        key_random = self.key_dict.get(self.client)
        self.handle_send_msg(sock, send_to1, "", key_random)

        return None

    """
        :param: sock, send_to, message, hash
        :return: Entity A, B, C send message to Entity A, B, C 
                 case 1: Entity authenticated itself to A and B, B 
                 case 2: integrity of data
    """
    def handle_send_msg(self, sock, send_to, message, hash):
        public_key = self.all_ca_dict.get("public_key").get(f"{send_to}_CA_public_key")

        new_message = message
        if self.Kabc:
            new_message = aes_encrypt(self.Kabc, message)

        send_msg = {
            "action": "change_message",
            "content": {
                "send_source": self.client,
                "send_to": send_to,
                "msg": new_message,
                "hash": hash,
            }
        }
        optional = send_msg["content"]
        text = {
            "client": self.client,
            "random": self.key_dict.get(f"{self.client}"),
            "send_to": send_to,
        }
        text_bo_bytes = pickle.dumps(text)
        print(f"Server S sent message to Client =====>> {text}")

        message = transmit_encrypt_func(text_bo_bytes, self.client_key, public_key, send_msg, optional)
        sock.sendall(message)
        time.sleep(3)
        return None

    def receive_message(self, conn, result):
        if result == "":
            return

        if isinstance(result, dict) == False:
            printMsg("==> receive from server ", result)
            return

        content = result["content"]
        msg = content["msg"]
        hash = content["hash"]
        send_source = content["send_source"]
        if hash:
            if "===" in hash:
                self.key_dict_all[send_source] = hash
            else:
                self.key_dict[send_source] = hash
                new_msg = hash + "===" + send_source
                self.handle_send_msg(conn, send_source, "", new_msg)
                printMsg("==> self.key_dict ", self.key_dict)
        else:
            try:
                dec_msg = aes_decrypt(self.Kabc, msg)
            except:
                dec_msg = msg
            printMsg("==> receive from server aes ", msg)
            printMsg("==> receive from server aes_decrypt", dec_msg)
        if len(self.key_dict) == 3:
            key_list = self.key_dict.values()
            self.Kabc = bytes_to_base64(combine_hash_values(list(key_list)))[:32]
            printMsg("===>self.Kabc", self.Kabc)

    def start_client(self):
        print("====" * 10)
        print(f"client: {self.client} starting")
        print(f"client {self.client} public_key is {self.client_public_key}")
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect((self.host, self.port))

        # Gets the current date and time
        now = datetime.datetime.now()

        # Format the output date-time string
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")

        cmd = """The commands are:
        login       Obtain login credentials
        exchange    exchange CLIENT_NAME Na, Nb, Nc random number
        send_to     send_to CLIENT_NAME msg\n"""

        print(cmd)

        while True:
            readable, writable, exceptional = select.select([client_sock, sys.stdin], [], [])
            for sock in readable:
                if sock is client_sock:
                    data = sock.recv(1024)
                    if not data:
                        print("Disconnected from server")
                        sys.exit()
                    else:
                        self.receive_message(sock, pickle.loads(data))
                else:
                    message = sys.stdin.readline().strip()
                    if message == "login":
                        self.login(client_sock)
                    elif "exchange" in message:
                        _, cli_name = message.split(" ")
                        self.exchange_message(client_sock, cli_name)
                    elif "send_to" in message:
                        _, cli_name, msg = message.split(" ")
                        self.handle_send_msg(client_sock, cli_name, msg, "")
                    else:
                        client_sock.send(pickle.dumps(message))
