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
        self.public_ca_name = f"{client}_CA_public_key"
        self.ca_name = f"{client}_CA_key"
        self.client_public_key = self.all_ca_dict.get(
            "public_key").get(self.public_ca_name)
        self.client_key = self.all_ca_dict.get("key").get(self.ca_name)
        self.public_cas = self.all_ca_dict.get(
            "public_key").get("S_CA_public_key")
        self.sign_name = f"{client}_CA_key_sign"
        self.sign_key = self.all_ca_dict.get("key_sign").get(self.sign_name)
        self.Kabc = None
        self.token = None
        self.key_dict = {
            self.client: generate_random_hash256()
        }
        self.key_dict_all = {
        }
        self.key_dict_temporary = {
            self.client: generate_random_hash256()[:32]
        }
        self.ECDHClient, self.ecdh_client_key_b64 = generate_client()
        self.ECDHServer, self.ecdh_server_key_b64 = generate_server()

        # init when client does not know others client public key
        # can request from server to get the other client public key
        self.public_ca_dict = {}

        # 1. login this is the first step, each client need to login to server to make sure the client is valid
        # and they can communicate with S server
        # this part include authentication and integrity
        # authentication: use rsa to encrypt the client public key and send to server
        # integrity: use rsa to signature client public key and send to server
        # 1. login this is the first step, each client need to login to server to make sure the client is valid
        # and they can communicate with S server
        # this part include authentication and integrity
        # authentication: use rsa to encrypt the client public key and send to server
        # integrity: use rsa to signature client public key and send to server

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
        # in this part include authentication to S and integrity
        message = transmit_encrypt_func(
            text, self.client_key, self.public_cas, login_message)

        sock.sendall(message)
        # time.sleep(3)

        # Receive server response data, if login success, print response message, if failure, print failure message reminder
        login_res_dict = pickle.loads(sock.recv(RECV_LEN))
        # printMsg("==>receive from server ", login_res_dict)

        reply_action = login_res_dict.get("reply_action")
        if reply_action == "login_success":
            self.token = login_res_dict.get("content")
            print(
                f"step 1 {self.client} can connect to S => {login_res_dict.get('reply_action')}")
        else:
            print_info(login_res_dict.get("content"))
        return None

    # Request other public keys from the server, and during the request, use your own temporary session to encrypt the whole information
    def request_for_other_public_key(self, sock, other_client):
        send_msg = {
            "action": "request_ca_public_key",
            "token": self.token,
            "content": {
                "ca_name": f"{other_client}_CA_public_key",
                "send_source": self.client
            }
        }

        text = {
            "client": self.client,
            "other_client": other_client
        }
        # in this part include authentication and integrity
        message = transmit_encrypt_func(
            text, self.client_key, self.public_cas, send_msg)
        sock.sendall(message)
        # time.sleep(3)

        # 处理向S请求返回的数据
        message_res = sock.recv(RECV_LEN)
        msg_res_dict = pickle.loads(message_res)
        # printMsg("==>receive from server ", msg_res_dict)

        print(f"step 2=====>  get public key from S{msg_res_dict.get('content').get('ca_value')}")
        if msg_res_dict.get("reply_action") == "response_ca_public_key":
            return msg_res_dict.get("content")

    # 3. using diffie-hellman to generate session key
    def generate_session_key(self, pubkey1, pubkey2):
        # Convert the public keys to long integers
        A = bytes_to_long(pubkey1)
        B = bytes_to_long(pubkey2)

        # Choose a random private key
        a = bytes_to_long(get_random_bytes(16))

        # Calculate the shared secret
        s = pow(B, a, A)

        # Convert the shared secret to bytes
        session_key = long_to_bytes(s)
        return session_key

    def exchange_message(self, sock, send_to1):

        # 获取随机数NA，NB，NC，一会转发给其他客户端
        key_random = self.key_dict.get(self.client)
        self.handle_send_msg(sock, send_to1, "", key_random)

        return None

    # 处理客户端发送给其他客户端的信息
    def handle_send_msg(self, sock, send_to, message, hash):
        public_key = self.request_for_other_public_key(sock, send_to)[
            "ca_value"]

        # Generate a random challenge
        challenge = secrets.token_bytes(16)
        # generate a session key using public key of two client such like A and B
        # used to encrypt the challenge
        key = self.generate_session_key(dict_to_bytes(self.client_public_key), dict_to_bytes(public_key))
        # Generate a response to the challenge
        response = hmac.new(key, challenge, hashlib.sha256).digest()

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

        optional = {
            "send_source": self.client,
            "send_to": send_to,

        }
        text = {
            "client": self.client,
            "send_to": send_to,
            "challenge": challenge
        }
        text_bo_bytes = pickle.dumps(text)
        # printMsg("==>send to server ", text_bo_bytes)

        print(f"step3 send challenge to other Client =====>> {text}")
        # 4. in this part include authentication between A and B, B and C, A and C, and integrity of them
        # using to transmit encrypt challenge
        message = transmit_encrypt_func(
            text_bo_bytes, self.client_key, public_key, send_msg, optional)
        sock.sendall(message)
        time.sleep(3)
        return None

    def receive_message(self, conn, result):
        if result == "":
            return

        if isinstance(result, dict) == False:
            printMsg("==> receive from server ", result)
            return

        # 加载数据
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
            printMsg("==> receive from server  aes_decrypt", dec_msg)
        if len(self.key_dict) == 3:
            key_list = self.key_dict.values()
            self.Kabc = bytes_to_base64(combine_hash_values(list(key_list)))[:32]
            # printMsg("===>len(self.key_dict) == 3", self.key_dict)
            # printMsg("===>len(self.key_dict_all) == 3", self.key_dict_all)
            printMsg("===>self.Kabc", self.Kabc)

    def start_client(self):
        print("====" * 10)
        print(f"client: {self.client} starting")
        print(f"client {self.client} public_key is {self.client_public_key}")
        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect((self.host, self.port))

        # 获取当前日期时间
        now = datetime.datetime.now()
        # 格式化输出日期时间字符串
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        cmd = """The commands are:
        login        获取登陆凭证
        publickey    获取publickey
        exchange    发送给其他客户端 exchange CLIENT_NAME
        send_to      发送给其他客户端 send_to CLIENT_NAME msg\n"""
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
                    if message == "publickey":
                        self.request_for_other_public_key(client_sock, "B")
                    elif message == "login":
                        self.login(client_sock)
                    elif "exchange" in message:
                        _, cli_name = message.split(" ")
                        self.exchange_message(client_sock, cli_name)
                    elif "send_to" in message:
                        _, cli_name, msg = message.split(" ")
                        self.handle_send_msg(client_sock, cli_name, msg, "")
                    else:
                        client_sock.send(pickle.dumps(message))
