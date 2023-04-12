import socket
import http.cookies as cookies
import time
import hashlib
import json

soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
soc.connect(('127.0.0.1', 10000))
print('Connected to server', soc.recv(1024).decode('utf-8'))
# Create a cookie with a one-hour expiration time
cookie = cookies.SimpleCookie()
cookie['timestamp'] = str(time.time())
cookie['timestamp']['max-age'] = 3600
cookie_str = cookie.output(header='', sep=';').strip()
dataSend = {
    "dataArr": [b'Bob', b'Jack', b'exit', b'exit'],
    "cookie_str": cookie_str,
    "session_key": "ssdffdsfsfsfs",
}
soc.send(json.dumps(dataSend).encode('utf-8'))
print('Server:', soc.recv(1024).decode('utf-8'))

soc.close()
