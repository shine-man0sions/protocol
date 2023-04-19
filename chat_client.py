#
import socket
import socketserver
from utils import *
import pickle
import hmac
import hashlib
import secrets
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
        time.sleep(3)

        # Receive server response data, if login success, print response message, if failure, print failure message reminder
        login_res = (sock.recv(RECV_LEN))
        login_res_dict = bytes_to_dict(login_res)
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
        time.sleep(3)

        # 处理向S请求返回的数据
        message_res = sock.recv(RECV_LEN)
        msg_res_dict = bytes_to_dict(message_res)
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

    # 处理客户端发送给其他客户端的信息
    def handle_send_msg(self, sock, send_to, message):
        public_key = self.request_for_other_public_key(sock, send_to)[
            "ca_value"]

        # Generate a random challenge
        challenge = secrets.token_bytes(16)
        # generate a session key using public key of two client such like A and B
        # used to encrypt the challenge
        key = self.generate_session_key(dict_to_bytes(self.client_public_key), dict_to_bytes(public_key))
        # Generate a response to the challenge
        response = hmac.new(key, challenge, hashlib.sha256).digest()
        send_msg = {
            "action": "change_message",
            "content": {
                "send_source": self.client,
                "send_to": send_to,
                "msg": message
            }
        }
        optional = {
            "send_source": self.client,
            "send_to": send_to,
            "msg": message
        }
        text = {
            "client": self.client,
            "send_to": send_to,
            "challenge": challenge
        }
        text_bo_bytes = pickle.dumps(text)
        print(f"step3 send challenge to other Client =====>> {challenge}")
        # 4. in this part include authentication between A and B, B and C, A and C, and integrity of them
        # using to transmit encrypt challenge
        message = transmit_encrypt_func(
            text_bo_bytes, self.client_key, public_key, send_msg, optional)
        sock.sendall(message)
        time.sleep(3)
        return None

    def handle_recv_msg(self, sock):

        # 接收客户端发送的数据
        data = sock.recv(RECV_LEN)

        # 数据不一致退出
        if not data:
            return None

        # 加载数据
        result = pickle.loads(data)
        message = result["message"]
        # 通过rsa解密算法，使用S服务器的私钥解密出client与临时session——key
        plain_text = bytes_to_dict(
            rsa_decrypt(self.client_key, message["key"]))
        client = plain_text["client"]
        # 构造消息数据，用于验证数字签名
        hash_result = {
            "hashKey": double_hash(plain_text),
        }
        hash_result_s = message["sign"]

        # 获得客户端的公钥，用来验证数字签名
        public_key = self.all_ca_dict.get(
            "public_key").get(f"{client}_CA_public_key")

        # 验证数字签名，compare 为True为验证成功，False为验证失败
        compare = RSA_verify(public_key, hash_result, hash_result_s)

        if compare:
            # 如果验证成功，则拿session_key AES算法去解密原始消息，获得明文
            plain_text_res = bytes_to_dict(message["cipher"])
            print(f"====>>>{plain_text_res}")
            send_source = plain_text_res.get("content").get("send_source")
            public_key = self.request_for_other_public_key(sock, send_source)[
                "ca_value"]
            key = self.generate_session_key(self.client_public_key, public_key)

            # save client info  then Forward to other client
            send_source = plain_text_res.get(
                "content").get("send_source")

            self.sock_dict[send_source] = sock
            # Generate a response to the challenge
            # response = hmac.new(key, challenge, hashlib.sha256).digest()

        return plain_text_res

    def exchange_message(self, sock, source_id, send_to1, send_to2):
        if self.client == source_id:
            # 获取随机数NA，NB，NC，一会转发给其他客户端
            key_random = self.key_dict.get(self.client)
            self.handle_send_msg(sock, send_to1, key_random)
            self.handle_send_msg(sock, send_to2, key_random)

        else:
            result = self.handle_recv_msg(sock)
            self.key_dict[source_id] = result.get("content").get("msg")
            print(f"step5 =====>>>> {result}")
            if len(self.key_dict) == 3:
                key_list = self.key_dict.values()

                self.Kabc = combine_hash_values(list(key_list))
        return None

    def abc_message_send_recv_test(self, sock, message):
        if self.client == "B":
            self.handle_send_msg(sock, "A", "AES_encryption_message", AES_decryptedFunc(
                self.Kabc, dict_to_bytes(message)))
            self.handle_send_msg(sock, "C", "AES_encryption_message", AES_decryptedFunc(
                self.Kabc, dict_to_bytes(message)))
        elif self.client == "A":
            self.handle_send_msg(sock, "B", "AES_encryption_message", AES_decryptedFunc(
                self.Kabc, dict_to_bytes(message)))
            self.handle_send_msg(sock, "C", "AES_encryption_message", AES_decryptedFunc(
                self.Kabc, dict_to_bytes(message)))
        elif self.client == "C":
            self.handle_send_msg(sock, "A", "AES_encryption_message", AES_decryptedFunc(
                self.Kabc, dict_to_bytes(message)))
            self.handle_send_msg(sock, "B", "AES_encryption_message", AES_decryptedFunc(
                self.Kabc, dict_to_bytes(message)))

        else:
            recv_dict = self.handle_recv_msg(sock)
            if recv_dict.get("action") == "AES_encryption_message":
                cipher = recv_dict.get("content").get("msg")
                format_out = f"""
                {self.client} recv cipher from {recv_dict.get("content").get("send_source")}
                message: {cipher}
                Kabc: {self.Kabc}
                cipher: {AES_decryptedFunc(self.Kabc, cipher.get("value"))}
                """
                print_info(format_out)
        return None

    # 改写handle函数
    def handle_server(self, sock, message):
        print(f"{self.client} recv message from {message}")
        if message == "login":
            self.login(sock)
        elif message == "publickey":
            if self.client == "A":
                self.request_for_other_public_key(sock, "B")
                self.request_for_other_public_key(sock, "C")
            elif self.client == "B":
                self.request_for_other_public_key(sock, "A")
                self.request_for_other_public_key(sock, "C")
            elif self.client == "C":
                self.request_for_other_public_key(sock, "A")
                self.request_for_other_public_key(sock, "B")
        elif message == "change":
            if self.client == "A":
                self.exchange_message(sock, "A", "B", "C")
            elif self.client == "B":
                self.exchange_message(sock, "B", "A", "C")
            elif self.client == "C":
                self.exchange_message(sock, "C", "A", "B")

        elif message == "exchange_message_with_AES":
            self.abc_message_send_recv_test(sock, {"msg": "hello world"})

        return None

    # 开启客户端
    def start_client(self):
        print("====" * 10)
        print(f"client: {self.client} starting")
        print(f"client {self.client} public_key is {self.client_public_key}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.host, self.port))
            while True:
                message = input("请输入消息：")
                self.handle_server(sock, message)
                time.sleep(3)
