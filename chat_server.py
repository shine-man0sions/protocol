"""
chat server S
"""
import os
import json
import socket
import time
import queue
import select
import socketserver
from argparse import ArgumentParser
from mbedtls import pk

from utils import *


class ChatServer(socketserver.BaseRequestHandler):
    def __init__(self, config_file="config.json", host="127.0.0.1", port=5006):
        self.host = host
        self.port = port
        self.all_ca_dict = read_json_to_dict(config_file)
        self.all_public_ca_dict = self.all_ca_dict.get("public_key")
        self.token_dict = {}
        self.sock_dict = {}
        self.sock_reply_msg_dict = {}
        self.token_dict = {}  # 添加token_dict用于保存Token和过期时间
        self.public_ca_name = "S_CA_public_key"
        self.ca_name = "S_CA_key"
        self.client_public_key = self.all_ca_dict.get(
            "public_key").get(self.public_ca_name)
        self.client_key = self.all_ca_dict.get("key").get(self.ca_name)

    # 处理客户端的发送过来的数据
    def handle_client(self, conn):

        # 接收客户端发送的数据
        data = conn.recv(RECV_LEN)

        # 数据不一致退出
        if not data:
            return None

        # 加载数据
        result = pickle.loads(data)
        print(f"223=====>......>>>, {result}")
        optional = result["optional"]
        message = result["message"]
        try:
            if optional is not None:
                self.handle_message(conn, result)
            else:
                # 通过rsa解密算法，使用S服务器的私钥解密出client与临时session——key
                plain_text = bytes_to_dict(
                    rsa_decrypt(self.client_key, message["key"]))

                # 构造消息数据，用于验证数字签名
                client = plain_text["client"]
                session_key = plain_text["session_key"]
                hash_result = {
                    "hashKey": double_hash(client, session_key),
                }
                hash_result_s = message["sign"]

                # 获得客户端的公钥，用来验证数字签名
                public_key = self.all_ca_dict.get(
                    "public_key").get(f"{client}_CA_public_key")
                print(
                    f" step2.2 ===> get public key to verify signature =======>>>  {public_key}")

                # 验证数字签名，compare 为True为验证成功，False为验证失败
                compare = RSA_verify(public_key, hash_result, hash_result_s)
                print(f" step2.3 ===> verify signature =======>>>  {compare}")

                if compare:
                    # 如果验证成功，则拿session_key AES算法去解密原始消息，获得明文
                    plain_text_aes = bytes_to_dict(
                        AES_decryptedFunc(session_key, message["cipher"]))
                    print(hash_result, compare, plain_text_aes)
                    print(
                        f" step2.4 ===> get plain text from cipher =======>>>  {hash_result}, {compare}, {plain_text_aes}")

                    # save client info  then Forward to other client
                    send_source = plain_text_aes.get(
                        "content").get("send_source")

                    self.sock_dict[send_source] = conn

                    if plain_text_aes["action"] == "login":
                        self.handle_login(conn, plain_text_aes["content"])
                    elif plain_text_aes["action"] == "request_ca_public_key":
                        self.response_public_key(
                            conn, plain_text_aes["content"])
                    else:
                        self.response_ECDH(conn, plain_text_aes["content"])
        except Exception as e:
            print(f"Error: Failed to serialize message: {e}")
            return None

    # 验证token
    def check_token(self, content):
        """
        Check that the login token used for A/B/C and S communication are out of date
        By default, it expires if no message is sent for more than one hour
        Token_EXPIRED, the value can be changed
        """
        token = content.get("token")
        current_timestamp = int(time.time())
        expired_timestamp = self.token_dict.get(token, "0")
        if current_timestamp - expired_timestamp < TOKEN_EXPIRATION_TIME:
            self.token_dict[token] = current_timestamp
            return True
        return False

    # 处理初次登陆，A，B，S 第一次尝试与S通信的处理
    # 这里包括了AES 对传输的消息加密
    # 这里包括了数字签名验证数字的来源
    # 这里包括了S的公钥对AES的session key 进行加密
    def handle_login(self, conn, data):
        print(f" step2.5 ===> handle login message =======>>>  {data}")
        ca_name = data["public_ca_name"]
        ca_value = data["public_ca_value"]
        sign_value = data["sign_value"]
        sign_result = RSA_verify(ca_value, ca_value, sign_value)
        if self.all_public_ca_dict.get(ca_name) == ca_value and sign_result == True:
            token = generate_token()
            expired_timestamp = int(time.time())
            self.token_dict[token] = expired_timestamp
            reply_dict = {
                "reply_action": "login_success",
                "content": {
                    "token": token,
                    "expired": expired_timestamp,
                    "client": ca_name.split("_")[0]
                }
            }
            self.token_dict["token"] = expired_timestamp

        else:
            reply_dict = {
                "reply_action": "login_failed",
                "content": "please use a correct ca public key"
            }
        reply_data = dict_to_bytes(reply_dict)
        self.sock_reply_msg_dict[conn].put(reply_data)
        # time.sleep(3)
        return None

    # A， B， C 向S请求其他设备的公钥，S返回响应数据
    def response_public_key(self, conn, data):
        print(f" step 4 S send the public_CA data to client ======>>>>>{data}")

        public_key_name = data["ca_name"]
        response_msg = {
            "reply_action": "response_ca_public_key",
            "content": {
                "ca_name": public_key_name,
                "ca_value": self.all_public_ca_dict.get(public_key_name)
            }
        }
        self.sock_reply_msg_dict[conn].put(dict_to_bytes(response_msg))
        # time.sleep(3)
        return None

    def response_ECDH(self, conn, data, ECDH=None):

        source_id = data["source_id"]
        send_to = data["send_to"]

        # 生成椭圆曲线密钥对
        private_key = ECDH.generate_key('secp256r1')
        public_key = private_key.get_public()

        # 将私钥导出为字节串
        private_key_bytes = private_key.export_key(
            format=pk.MBEDTLS_ECP_PF_UNCOMPRESSED)

        # 将公钥导出为字节串
        public_key_bytes = public_key.export_key(
            format=pk.MBEDTLS_ECP_PF_UNCOMPRESSED)

        # 使用公钥和私钥生成会话密钥
        session_key = ECDH.generate_shared(private_key, public_key)

        # 将会话密钥导出为字节串
        session_key_bytes = session_key.export_key()

        # 发送公钥和会话密钥
        source_id.sendall(public_key_bytes)
        send_to.sendall(session_key_bytes)

    # 处理转发数据，A，B，C 向其他设备A，B，C发送消息时，S只负责转发，不进行解析
    def handle_message(self, conn, result):
        print(" step 6  S send unchanged message to client ======>>>>>", result)
        send_source = result.get("optional").get("send_source")
        send_to = result.get("optional").get("send_to")
        send_to_sock = self.sock_dict.get(send_to)
        print(
            f" step 6.1 {send_source} transfer unchanged message to other Client {send_to_sock}")
        self.sock_reply_msg_dict[send_to_sock].put((pickle.dumps(result)))
        return None

    # 启动一个服务器
    def start_server(self):
        # start a server by TCP
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind((self.host, self.port))
            server.listen(100)

            # Set the non-blocking mode
            server.setblocking(False)

            inputs = [server, ]

            # outputs store data that links need to return
            outputs = []
            # loop the writable
            while True:
                readable, writeable, exceptional = select.select(
                    inputs, outputs, [])
                for r in readable:
                    # Represents a new connection
                    if r is server:
                        # Wait for the client to generate the instance
                        conn, addr = server.accept()

                        print("client Connected from ", addr)
                        if conn not in inputs:
                            inputs.append(conn)
                        self.sock_reply_msg_dict[conn] = queue.Queue()

                    # Receive new connection data
                    else:
                        if r not in outputs:
                            outputs.append(r)
                        self.handle_client(r)

                # Send data: A list of links to return to the client
                for w in writeable:
                    # Retrieves the instance of the queue from the relink list
                    msg_queue = self.sock_reply_msg_dict.get(w)
                    while msg_queue and (not msg_queue.empty()):
                        data_to_client = msg_queue.get()
                        # Returns data to the client
                        w.sendall(data_to_client)
                        time.sleep(2)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    args = parse_args()
    ChatServer = ChatServer(host=args.host, port=args.port)
    ChatServer.start_server()
