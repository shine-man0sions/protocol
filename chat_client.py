#
import socket
import socketserver
from utils import *
import pickle


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
        self.public_cas = self.all_ca_dict.get("public_key").get("S_CA_public_key")
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

    # 登陆操作
    def login(self, sock):
        session_key = self.key_dict_temporary.get(self.client)
        print_info(f"client {self.client} logining")
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

        # 这里需要服务器的公钥和私钥
        message = transmit_encrypt_func(self.client, session_key, self.client_key, self.public_cas, login_message)
        sock.sendall(message)
        time.sleep(3)

        # 接收服务端响应的数据，如果登陆成功，打印响应的消息，如果失败，打印失败消息提醒
        login_res = (sock.recv(RECV_LEN))
        login_res_dict = bytes_to_dict(login_res)
        reply_action = login_res_dict.get("reply_action")
        if reply_action == "login_success":
            print_info(login_res_dict)
            self.token = login_res_dict.get("content")
            print(f"client : {self.client} token: {self.token}")

        else:
            print_info(login_res_dict.get("content"))
        return None

    # 向服务器请求其他的公钥，请求的过程中，使用自己的临时产生的一个session可以将整体的信息加密
    def request_for_other_public_key(self, sock, other_client):
        session_key = self.key_dict_temporary.get(self.client)
        send_msg = {
            "action": "request_ca_public_key",
            "token": self.token,
            "content": {
                "ca_name": f"{other_client}_CA_public_key",
                "send_source": self.client
            }
        }

        # 这里需要服务器的公钥和私钥
        message = transmit_encrypt_func(self.client, session_key, self.client_key, self.public_cas, send_msg)
        print(f" step 3.1 request for other public key cipher message =======>>>>>, {message}")
        sock.sendall(message)
        time.sleep(3)

        # 处理向S请求返回的数据
        message_res = sock.recv(RECV_LEN)
        msg_res_dict = bytes_to_dict(message_res)
        print_info(f"step 3.3 get the public key that response from other client =======>>>>>>>> {message_res}")
        if msg_res_dict.get("reply_action") == "response_ca_public_key":
            return msg_res_dict.get("content")

    def request_for_ECDH(self, sock, other_client):
        session_key = self.key_dict_temporary.get(self.client)
        send_msg = {
            "action": "request_ECDH",
            "token": self.token,
            "content": {
                "source_id": self.client,
                "send_to": other_client
            }
        }
        # 这里需要服务器的公钥和私钥
        message = transmit_encrypt_func(self.client, session_key, self.client_key, self.public_cas, send_msg)
        print(f" step 8 request for other public key cipher message =======>>>>>, {message}")
        sock.sendall(message)
        time.sleep(3)

        # 处理向S请求返回的数据
        message_res = sock.recv(RECV_LEN)
        msg_res_dict = bytes_to_dict(message_res)
        print_info(f"step 9 get the ECDH that response from Server =======>>>>>>>> {message_res}")
        if msg_res_dict.get("reply_action") == "request_ECDH":
            return msg_res_dict.get("content")

    # 处理客户端发送给其他客户端的信息
    def handle_send_msg(self, sock, send_to, message):
        session_key = self.key_dict_temporary.get(self.client)
        public_key = self.request_for_other_public_key(sock, send_to)["ca_value"]
        send_msg = {
            "action": "change_message",
            "content": {
                "msg": message
            }
        }
        optional = {
            "send_source": self.client,
            "send_to": send_to,
            "source_signed": RSA_sign(self.client_key, message),
            "msg": message
        }
        # 这里需要服务器的公钥和私钥
        message = transmit_encrypt_func(self.client, session_key, self.client_key, public_key, send_msg, optional)
        print(f"step 5 client:{self.client} to {send_to} send cipher message to other client =======>>>>>, {message}")
        sock.sendall(message)
        time.sleep(3)
        return None

    def handle_recv_msg(self, sock):
        data = sock.recv(RECV_LEN)
        result = pickle.loads(data)
        print(f"step 77777 ===========>>>>> get message {result}")

        # 通过rsa解密算法，使用S服务器的私钥解密出client与临时session——key
        message = result["message"]
        plain_text = bytes_to_dict(rsa_decrypt(self.client_key, message["key"]))

        # 构造消息数据，用于验证数字签名
        client = plain_text["client"]
        session_key = plain_text["session_key"]
        hash_result = {
            "hashKey": double_hash(client, session_key),
        }
        hash_result_s = message["sign"]

        # 获得客户端的公钥，用来验证数字签名
        public_key = self.all_ca_dict.get("public_key").get(f"{client}_CA_public_key")
        print(f" step2.2 ===> get public key to verify signature =======>>>  {public_key}")

        # 验证数字签名，compare 为True为验证成功，False为验证失败
        compare = RSA_verify(public_key, hash_result, hash_result_s)
        print(f" step2.3 ===> verify signature =======>>>  {compare}")

        if compare:
            # 如果验证成功，则拿session_key AES算法去解密原始消息，获得明文
            plain_text_aes = bytes_to_dict(AES_decryptedFunc(session_key, message["cipher"]))
            print(f"step 8888888 =========>>>>>>>>> {hash_result}, {compare}, {plain_text_aes}")
            return plain_text_aes
        print_info(f"message from {self.client} signed failed\n  please use a correct key to signed")
        return None

    def exchange_message(self, sock, source_id, send_to1, send_to2):
        if self.client == source_id:
            time.sleep(5)
            print_info(" sleep 20 s waiting for  starting exchange_message_init")

            # 获取随机数NA，NB，NC，一会转发给其他客户端
            key_random = self.key_dict.get(self.client)
            print(f"step 9 send key_random ====>>>>{key_random}")
            self.handle_send_msg(sock, send_to1, key_random)
            self.handle_send_msg(sock, send_to2, key_random)

        else:
            time.sleep(5)
            result = self.handle_recv_msg(sock)
            self.key_dict[source_id] = result.get("content").get("msg")

            if len(self.key_dict) == 3:
                key_list = self.key_dict.values()
                print_info(f"step 12 =======>>>>>> get {self.key_dict[source_id]} \n  OK OK OK\n OKOKOKOK")

                self.Kabc = combine_hash_values(list(key_list))
                print_info(f"step 13 =======>>>>>> get {self.Kabc} is \n {self.Kabc.hex()} \n  OK OK OK\n OKOKOKOK")
        return None

    def abc_message_send_recv_test(self, sock):
        if self.client == "B":
            self.handle_send_msg(sock, "A", "AES_encryption_message", AES_encrpted(self.Kabc, b"hello A"))
            self.handle_send_msg(sock, "C", "AES_encryption_message", AES_encrpted(self.Kabc, b"hello C"))

        else:
            recv_dict = self.handle_recv_msg(sock)
            if recv_dict.get("action") == "AES_encryption_message":
                cipher = recv_dict.get("content").get("msg")
                format_out = f"""
                {self.client} recv cipher from {recv_dict.get("content").get("send_source")}
                message: {cipher}
                Kabc: {self.Kabc}
                cipher: {AES_decrpted(self.Kabc, cipher.get("value"))}
                """
                print_info(format_out)
        return None

    # 改写handle函数
    def handle_server(self, sock):
        print(f"{self}, {sock}")
        if self.token is None:
            self.login(sock)

        if self.Kabc is None:
            self.exchange_message(sock, "A", "B", "C")
            self.exchange_message(sock, "B", "A", "C")
            self.exchange_message(sock, "C", "A", "B")
        else:
            time.sleep(30)
            print_info(
                f"client: {self.client} Waiting to Send and recv message")
            self.abc_message_send_recv_test(sock)
        return None

    # 开启客户端
    def start_client(self):
        print("====" * 10)
        print(f"client: {self.client} starting")
        print(f"client {self.client} public_key is {self.client_public_key}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.host, self.port))
            while True:
                self.handle_server(sock)
                time.sleep(3)
        return None


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    args = parse_args()
    ChatClient = ChatClient(host=args.host, port=args.port, client=args.client)
    ChatClient.start_client()
