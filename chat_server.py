import socket
import threading
import http.cookies as cookies
import time

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
soc.bind(('127.0.0.1', 10000))

soc.listen(5)

print('Server is running, waiting for connections...')


def tcpLink(sock, addr):
    print('Accept new connection from %s:%s...' % addr)
    sock.send(b'Welcome!')
    start_time = time.time()
    while True:
        data = sock.recv(1024)
        time.sleep(1)
        if not data or data.decode('utf-8') == 'exit':
            break
        if data.startswith(b'Cookie:'):
            # Parse the cookie and check its expiration time
            cookie_str = data.decode('utf-8').split(' ', 1)[1]
            cookie = cookies.SimpleCookie(cookie_str)
            if 'timestamp' in cookie:
                timestamp = float(cookie['timestamp'].value)
                if time.time() - timestamp > 3600:
                    sock.send(b'Your session has expired. Goodbye!')
                    break
        sock.send(('Hello, %s!' % data.decode('utf-8')).encode('utf-8'))
    sock.close()
    print('Connection from %s:%s closed.' % addr)


while True:
    # Accept a new connection
    sock, addr = soc.accept()
    # Create a new thread to handle TCP connection
    t = threading.Thread(target=tcpLink, args=(sock, addr))
    t.start()
