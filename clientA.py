from client_new import ChatClient

import socket

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    ChatClient = ChatClient(host="127.0.0.1", port=5006, client="A")
    ChatClient.start_client()
