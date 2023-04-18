from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Util.strxor import strxor
import base64
import hashlib

import json
import os
import json
import socket
import time
import random
import base64
import hashlib

def AES_encrypted(key, message):
    # 使用 SHA-256 算法对密钥进行哈希，并截取前 16 字节作为 AES 密钥
    key = hashlib.sha256(key).digest()[:16]

    # 生成随机的 nonce
    nonce = get_random_bytes(16)

    # 使用 AES-GCM 模式进行加密
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    # 返回加密后的数据，包括 ciphertext, nonce 和 tag
    return {
        "cipher": bytes_to_base64(ciphertext),
        "nonce": bytes_to_base64(nonce),
        "tag": bytes_to_base64(tag)
    }


def bytes_to_base64(b):
    # 将 bytes 类型转换为 base64 字符串
    return base64.b64encode(b).decode('utf-8')


def base64_to_bytes(s):
    # 将 base64 字符串转换为 bytes 类型
    return base64.b64decode(s.encode('utf-8'))


def generate_random_hash256():
    """generate random byte hash256"""
    byte_to_hash = os.urandom(random.randrange(100, 1000))
    sha256 = hashlib.sha256(byte_to_hash)
    return sha256.hexdigest()


# 示例用法
key = hashlib.sha256(b"password").digest()  # 生成一个示例的 hash 值作为密钥
message = b"Hello, World!"  # 示例的明文消息

send_msg = {
            "action": "request_ca_public_key",
            "token": "dstdfd",
            "content": {
                "ca_name": f"B_CA_public_key",
                "send_source": generate_random_hash256()
            }
        }

def dict_to_bytes(data):
    return json.dumps(data).encode()


def bytes_to_dict(data):
    return json.loads(data.decode())





# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    encrypted = AES_encrypted(key, dict_to_bytes(send_msg))
    print("Encrypted data:", encrypted)