import socket
import select
import queue
import pickle


def server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('localhost', 5006))
    server_socket.listen(5)
    print('Server is running on {}:{}'.format(*server_socket.getsockname()))

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
                data = s.recv(1024)
                if data:
                    print('Received data from {}:{}'.format(*s.getpeername()))
                    message_queues[s].put(data)
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
                str = next_msg.decode()
                if "@" in str:
                    ip, msg = str.split("@")
                    # 转发给指定ip
                    for key, value in clients.items():
                        if key == ip:
                            value.sendall(pickle.dumps("从服务端转发：" + msg))
                else:
                    s.send(pickle.dumps("从服务端回复：" + str))

        for s in exceptions:
            print('Handling exception for {}'.format(s.getpeername()))
            inputs.remove(s)
            if s in outputs:
                outputs.remove(s)
            s.close()
            del message_queues[s]



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
    server()
