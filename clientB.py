from client import ChatClient

import socket

"""
    :param host, port, client
    return a instance of class Client
"""
if __name__ == '__main__':
    ChatClient = ChatClient(host="127.0.0.1", port=5006, client="B")
    ChatClient.start_client()
