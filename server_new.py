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
        self.sock_dict = {}
        self.clients = {}
        self.sock_reply_msg_dict = {}
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
        message_queues = {}

        while inputs:
            readables, writables, exceptions = select.select(inputs, outputs, inputs)
            for s in readables:
                if s is server_socket:
                    client_socket, client_address = s.accept()
                    print('Accepted connection from {}:{}'.format(*client_address))
                    client_socket.setblocking(False)
                    inputs.append(client_socket)
                    message_queues[client_socket] = queue.Queue()
                else:
                    data = s.recv(4 * 1024)
                    if data:
                        msg = pickle.loads(data)
                        print('Received data from {}:{}'.format(*s.getpeername()))
                        printMsg("receive from client <==", msg)
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

            for s in exceptions:
                print('Handling exception for {}'.format(s.getpeername()))
                inputs.remove(s)
                if s in outputs:
                    outputs.remove(s)
                s.close()
                del message_queues[s]

    """
    :param: conn, data
    :return: none Process forwarded data. When A, B, C sends A message to other devices A, B, C, 
             S only forwards the message without parsing it
    """
    def handle_message(self, conn, data):
        result = bytes_to_dict(data.get("message").get("cipher"))
        content = result.get("content")
        send_source = content["send_source"]
        send_to = content["send_to"]
        send_to_sock = self.sock_dict.get(send_to)
        if send_to_sock is not None:
            send_to_sock.send(pickle.dumps(result))
        else:
            print(f"Error: Failed to find socket for client {send_to}")
        print(f" Server S send message from {send_source} to other Client {send_to_sock}")
        return None

    def handle_client(self, conn, result):
        if isinstance(result, dict) == False:
            conn.sendall(pickle.dumps(result))
            return

        # Server S load data
        optional = result["optional"]
        message = result["message"]
        try:
            if optional is not None:
                self.handle_message(conn, result)
            else:
                # The private key of the S server is used to decrypt the client using the rsa decryption algorithm
                plain_text = bytes_to_dict(
                    rsa_decrypt(self.client_key, message["key"]))
                client = plain_text["client"]

                # Construct message data that is used to verify digital signatures
                hash_result = {"hashKey": double_hash(plain_text)}
                hash_result_s = message["sign"]

                # Obtain the client's public key, which is used to verify the digital signature
                public_key = self.all_ca_dict.get("public_key").get(f"{client}_CA_public_key")

                # Verify digital signatures. compare True indicates that the verification succeeds,
                # False indicates that the verification fails
                compare = RSA_verify(public_key, hash_result, hash_result_s)

                if compare:

                    # If the authentication is successful, the original message is decrypted and the plaintext is obtained
                    plain_text_res = bytes_to_dict(message["cipher"])

                    # save client info  then Forward to other client
                    send_source = plain_text_res.get("content").get("send_source")

                    self.sock_dict[send_source] = conn
                    if plain_text_res["action"] == "login":
                        self.handle_login(conn, plain_text_res["content"])
                    else:
                        print("error")
        except Exception as e:
            print(f"Error: Failed to serialize message: {e}")
            return None

    """
    :param: conn, data
    :return: Processing First login, A, B, S first attempt to communicate with S processing
             This includes RSA encryption of transmitted messages
             This includes the source of the digital signature verification number
    """
    def handle_login(self, conn, data):
        ca_name = data["public_ca_name"]
        ca_value = data["public_ca_value"]
        sign_value = data["sign_value"]
        sign_result = RSA_verify(ca_value, ca_value, sign_value)
        if self.all_public_ca_dict.get(ca_name) == ca_value and sign_result == True:
            expired_timestamp = int(time.time())
            reply_dict = {
                "reply_action": "login_success",
                "content": {
                    "expired": expired_timestamp,
                    "client": ca_name.split("_")[0]
                }
            }
        else:
            reply_dict = {
                "reply_action": "login_failed",
                "content": "please use a correct ca public key"
            }
        reply_data = pickle.dumps(reply_dict)
        conn.sendall(reply_data)
        return None


if __name__ == '__main__':
    server = ChatServer()
    server.server()
