import socket
import select
import queue
import pickle
from utils import *


class ChatServer():
    def __init__(self, config_file="config.json", host="127.0.0.1", port=5006):
        self.host = host
        self.port = port
        self.server_socket = None
        self.all_ca_dict = read_json_to_dict(config_file)
        self.all_public_ca_dict = self.all_ca_dict.get("public_key")
        self.token_dict = {}
        self.sock_dict = {}
        self.clients = {}
        self.sock_reply_msg_dict = {}
        self.token_dict = {}  # 添加token_dict用于保存Token和过期时间
        self.public_ca_name = "S_CA_public_key"
        self.ca_name = "S_CA_key"
        self.client_public_key = self.all_ca_dict.get(
            "public_key").get(self.public_ca_name)
        self.client_key = self.all_ca_dict.get("key").get(self.ca_name)

    def server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        print('Server is running on {}:{}'.format(*server_socket.getsockname()))
        self.server_socket = server_socket
        inputs = [server_socket]
        outputs = []
        clients = {}
        message_queues = {}

        while inputs:
            readables, writables, exceptions = select.select(inputs, outputs, inputs)
            for s in readables:
                if s is server_socket:
                    client_socket, client_address = s.accept()
                    print('Accepted connection from {}:{}'.format(*client_address))
                    client_socket.setblocking(False)
                    inputs.append(client_socket)
                    client_address_str = "{}:{}".format(client_address[0], client_address[1])

                    clients[client_address_str] = client_socket
                    message_queues[client_socket] = queue.Queue()
                else:
                    data = s.recv(4 * 1024)
                    if data:
                        msg = pickle.loads(data)
                        print('Received data from {}:{}'.format(*s.getpeername()))
                        message_queues[s].put(msg)
                        if s not in outputs:
                            outputs.append(s)
                    else:
                        print('Closed connection from {}:{}'.format(*s.getpeername()))
                        if s in outputs:
                            outputs.remove(s)
                        inputs.remove(s)
                        s.close()
                        del message_queues[s]

            for s in writables:
                try:
                    next_msg = message_queues[s].get_nowait()
                except queue.Empty:
                    outputs.remove(s)
                else:
                    self.handle_client(s, next_msg)
                    # str = next_msg["message"]
                    # if "@" in str:
                    #     ip, msg = str.split("@")
                    #     # 转发给指定ip
                    #     for key, value in clients.items():
                    #         if key == ip:
                    #             value.sendall(pickle.dumps("从服务端转发：" + msg))
                    # else:
                    #     s.send(pickle.dumps("从服务端回复：" + str))

            for s in exceptions:
                print('Handling exception for {}'.format(s.getpeername()))
                inputs.remove(s)
                if s in outputs:
                    outputs.remove(s)
                s.close()
                del message_queues[s]

    # 处理转发数据，A，B，C 向其他设备A，B，C发送消息时，S只负责转发，不进行解析
    def handle_message(self, conn, data):
        result = bytes_to_dict(data.get("message").get("cipher"))
        content = result.get("content")

        send_source = content["send_source"]
        send_to = content["send_to"]
        send_to_sock = self.sock_dict.get(send_to)
        print(" step 6  S send unchanged message to client ======>>>>>", result, send_source, send_to, send_to_sock)

        if send_to_sock is not None:
            send_to_sock.send(pickle.dumps(result))
            # self.server_socket.sendall()
            # self.sock_reply_msg_dict[send_to_sock].put(pickle.dumps(result))
        else:
            print(f"Error: Failed to find socket for client {send_to}")
        print(
            f" step 6.1 S transfer unchanged message from {send_source} to other Client {send_to_sock}")
        return None

    def handle_client(self, conn, result):



        # 加载数据
        optional = result["optional"]
        message = result["message"]
        try:
            if optional is not None:
                self.handle_message(conn, result)
            else:
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

                    # save client info  then Forward to other client
                    send_source = plain_text_res.get(
                        "content").get("send_source")

                    self.sock_dict[send_source] = conn

                    if plain_text_res["action"] == "login":
                        self.handle_login(conn, plain_text_res["content"])
                    elif plain_text_res["action"] == "request_ca_public_key":
                        self.response_public_key(
                            conn, plain_text_res["content"])
                    else:
                        self.response_ECDH(conn, plain_text_res["content"])
        except Exception as e:
            print(f"Error: Failed to serialize message: {e}")
            return None

    # A， B， C 向S请求其他设备的公钥，S返回响应数据
    def response_public_key(self, conn, data):
        public_key_name = data["ca_name"]
        response_msg = {
            "reply_action": "response_ca_public_key",
            "content": {
                "ca_name": public_key_name,
                "ca_value": self.all_public_ca_dict.get(public_key_name)
            }
        }
        reply_data = pickle.dumps(response_msg)
        conn.sendall(reply_data)
        # self.sock_reply_msg_dict[conn].put(dict_to_bytes(response_msg))
        # time.sleep(3)
        return None

    # 处理初次登陆，A，B，S 第一次尝试与S通信的处理
    # 这里包括了AES 对传输的消息加密
    # 这里包括了数字签名验证数字的来源
    # 这里包括了S的公钥对AES的session key 进行加密
    def handle_login(self, conn, data):
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
        reply_data = pickle.dumps(reply_dict)
        conn.sendall(reply_data)
        # self.sock_reply_msg_dict[conn].put(reply_data)
        # time.sleep(3)
        return None


# {'message': {
#     'cipher': b'{"action": "login", "content": {"public_ca_name": "A_CA_public_key", "public_ca_value": "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA490dF9CW5TtCV66E6Enh\\n2ydVX8pA7XWKbyvQtuqAXl2B45Xu1Vm2jKqPIdsIEt9ycofS7FwFCKs7b+H++HTw\\nlhcjjCvxMTIaTrcAfypIjjxbFNfDJH9ocERs9KAQ5Jg8jN7YTqp51QBwweRKs5gg\\nfuCqGppGRXGFpTYS3G6EuytWj+P1qsg8WXJo6qADuPLMt1XYhRzRrX2Vi9YGwGcf\\nfHpqyhwplIXDksaEHX7CLM7uOpou+ncwj50GDewiUKvquocLi754mTVgMKx8c91H\\nYuyUnU3zqsKEswVZd85p/4Ezv+IRME9V6OnhIf/ocdpfFvAO+kuX2hK0N5noM22a\\ndQIDAQAB\\n-----END PUBLIC KEY-----\\n", "sign_name": "A_sign_key", "sign_value": "ImQ4lqSZA0hTHnifDYvyST7BWYtJ9tLZV5DEFfinbfHOzJEOoY68sMwPil7620fvu6pZdiJhL1kGHSZMsAZzQNMtn6Nyri80ve+Lh7a3FUdKn88NAdLirBXOE6CLiJgzIS46zqEoH3hKf+PZwuzlKePjhYhucMxoc99wa6Zykf1ol4fwsoxZw5LFiGQPKL4JsXO5nsMxukwDNnIKEMb8X1/rTkyddqmQMPNnpTvDVUm9b5dhD9BmasREdAhr4E4T65pz3/ViLqzH9cUcBc63kPJ/Bzimy65JmktkHzRAV4MaAIzILDjI3IGlDPO/ShuEs9DhVKoGzwJCJPWi+7PhMg==", "send_source": "A"}}',
#     'sign': 'yLX3jaUUkCdSfRC0VL40PTAgYCNIpIDzjSJp1gjlvseg78ukpew4+CSqNXWaqSk2xn833NK/xxHxt4zOw70f/72DIitOAiPoYvY1w3rF7H/3mrBgFF0V5V9sFGZzoEgf4szCTSlUAbpwhVQ667eGvMdtlvUgzpmS6PHmoCz/TAFULUrkyTMnEiz2oJaDbf1mfbXAUtU2yZ6coVmHertgvMYO0EH6F5fxIN6kFh83gxVilkpfqpkxm21Nn57/LhHRUgVh2GE+ZD6b66eYZMYg19XD+C5xtNaQZOb5xH0pcFM5aXgK4ektAZ4hx/8JZJLjE1udRUsMRyWSCwu8tnnA6Q==',
#     'key': b'e\xca\xc1\xba^\x14c\tWtF\xa6\xb3\xab\xe4Pp\x93~ML\xab\x8bD\xaa\x06T\n\x0f\xfa\xa0\xfb\x05\xfe3\xc7\xd9\xe5\xe0\xf4\xcd\xf4\xbf<\xa2\xf9\x1bH\xa6j!\xe5\xc8\xces\xf0\xb0\xc3i\xb0\xcf#/\x92(*,\xd7\xa1\xe2c\xd9\xd8\xd7\x1bP\xfaF\xb8B\xd1\x05\x87\xfb?1c\xaf+\xa8\x87\x98\tL>\x8d\xf2\xa5\xbfL\xe1\xce\xa7\xc1\xff\xfb@v\xab\x9as~\r\xf7\xae\x8f\xa2F\xb0\n]D\xe0P\xd4\xbc\x87\xb2\x82\x83\\\xfd\xc4r@<\x87\xbb\xe7\x149U\xfe+\x98\xbe\xf8\xc4]\xf41=\xb6N\xf1\xb0Y\xaf$N]\t%\xf6\xc9\xd6\xe8v^\xeb7l?\x07\xf1\xcf\x08\xf7"\\\xee\xe9\xc1\x08np\xfb\x18\xcb\xcfI=\xcef\xdaTy\x04\x8e\xe7\x9a\xd5b93+{\xa1.\x9c@;=u6\xc6F\x07\xa5\x1c\xee\x1cPs\xad\x93)\xf3\xeeu\x16\xee\xf5\x97\xcc(\xd9r\xe4(7\xf4\xe4\x1c\xc1\xf9\xd9\x15\xf4\xaa\x15}\xael\xe6\xcb'},
#  'optional': None}

if __name__ == '__main__':
    server = ChatServer()
    server.server()
