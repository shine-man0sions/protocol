import socket
import select
import sys
import pickle

def client():
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect(('localhost', 5006))
    while True:
        readable, writable, exceptional = select.select([client_sock, sys.stdin], [], [])
        for sock in readable:
            if sock is client_sock:
                data = sock.recv(1024)
                if not data:
                    print("Disconnected from server")
                    sys.exit()
                else:
                    print(pickle.loads(data))
            else:
                message = sys.stdin.readline().strip()
                client_sock.send(message.encode('utf-8'))

if __name__ == '__main__':
    # import sys
    # if len(sys.argv) < 2:
    #     print('Usage: {} [server|client]'.format(sys.argv[0]))
    #     sys.exit(1)
    #
    # if sys.argv[1] == 'server':
    #     server()
    # elif sys.argv[1] == 'client':
    #     client()
    # else:
    #     print('Unknown command: {}'.format(sys.argv[1]))
    #     sys.exit(1)
    client()
