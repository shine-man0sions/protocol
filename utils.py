import os
import json
import time
import random
import base64
import hashlib
import pickle
import socket
from mbedtls import pk
from Crypto.Cipher import AES
from argparse import ArgumentParser
from Crypto.Random import get_random_bytes

RECV_LEN = 4 * 1024

# 定义token的过期时间
TOKEN_EXPIRATION_TIME = 3600  # 3600秒


def parse_args():
    # parse the command line arguments host and port
    args = ArgumentParser()
    args.add_argument('--host', default="127.0.0.1")
    args.add_argument('--port', default=5006, type=int)
    args.add_argument('--client', default="")
    return args.parse_args()


# 用于从一个 JSON 文件中读取内容并将其转换为 Python 字典对象
def read_json_to_dict(filename):
    with open(filename, "r") as fr:
        res_dict = json.loads(fr.read())
    return res_dict


def dict_to_bytes(data):
    return json.dumps(data).encode()


def bytes_to_dict(data):
    return json.loads(data.decode())


def bytes_to_base64(data):
    return base64.standard_b64encode(data).decode()


def base64_to_bytes(data):
    return base64.standard_b64decode(data)


def print_info(keywords):
    print("============================start-msg=====================")
    print(keywords)
    print("=============================end-msg======================")


def read_json_to_dict(filename):
    with open(filename, "r") as fr:
        res_dict = json.loads(fr.read())
    return res_dict


def generate_random_hash256():
    """generate random byte hash256"""
    byte_to_hash = os.urandom(random.randrange(100, 1000))
    sha256 = hashlib.sha256(byte_to_hash)
    return sha256.hexdigest()


def combine_hash_values(s):
    """combine multiple hash values by concatenating and hashing"""
    combined_hash = b''
    sorted_arr = sorted(s)
    for hash_value in sorted_arr:
        combined_hash += bytes.fromhex(hash_value)
    sha256 = hashlib.sha256(combined_hash)
    return bytes.fromhex(sha256.hexdigest())


def double_hash(client, data):
    hash_object = hashlib.sha256()
    hash_result = bytes_to_base64(dict_to_bytes(client)) + data
    hash_object.update(hash_result.encode('utf-8'))
    hash_binary1 = hash_object.digest()
    result = hash_binary1.hex()
    return result


def generate_token():
    # 生成Token，
    token = str(time.time())  # 使用当前时间作为 Token

    # 设置Token的过期时间
    expiration_time = time.time() + TOKEN_EXPIRATION_TIME
    return expiration_time


def generate_client():
    ecdh_key = pk.ECC(pk.Curve.CURVE25519)
    ecdh_key.generate()
    ECDHClient = pk.ECDHClient(ecdh_key)
    ecdh_client_key = ECDHClient.generate()
    return ECDHClient, bytes_to_base64(ecdh_client_key)


def generate_server():
    ecdh_key = pk.ECC(pk.Curve.CURVE25519)
    ecdh_key.generate()
    ECDHServer = pk.ECDHServer(ecdh_key)
    ecdh_server_key = ECDHServer.generate()
    return ECDHServer, bytes_to_base64(ecdh_server_key)


def format_public_key(client):
    return f"{client}_CA_public_key"


def recv_info(conn):
    try:
        data = b""
        while True:
            new = conn.recv(RECV_LEN)
            if not new:
                break
            time.sleep(0.5)
            data += new
        return data
    except Exception as e:
        print(e)


def AES_encrypted(key, message):
    aes = AES.new(key, AES.Mode.GCM, key[:16], ad=key[16:])
    encrypted, verify = aes.encrypt(message)
    print(f"------>>>>>>????? {key}, {message}, {encrypted}, {verify}")
    return {
        "cipher": bytes_to_base64(encrypted),
        "verify": bytes_to_base64(verify)
    }


def AES_decrypted(key, cipher):
    aes = AES.new(key, AES.Mode.GCM, key[:16], ad=key[16:])
    encrypted = base64_to_bytes(cipher.get("cipher"))
    verify = base64_to_bytes(cipher.get("verify"))
    return aes.decrypt(encrypted, verify)


def RSA_sign(key, message):
    """return  base64  sign result, in order to use in json format"""
    rsa = pk.RSA.from_PEM(key)
    if isinstance(message, bytes):
        sig = rsa.sign(message, "sha256")
    else:
        sig = rsa.sign(dict_to_bytes(message), "sha256")
    return bytes_to_base64(sig)


# RSA verify  signature
def RSA_verify(public_key, message, sig_base64):
    """
    Arguments:
        public_key -- [PEM format]
        message -- [dict]
        sig_base64 -- [base64 str]
    """
    rsa = pk.RSA.from_PEM(public_key)
    sig = base64_to_bytes(sig_base64)
    return rsa.verify(dict_to_bytes(message), sig, "sha256")


def rsa_encrypt(public_key, plaintext):
    rsa = pk.RSA.from_PEM(public_key)
    ciphertext = rsa.encrypt(plaintext)
    return ciphertext


def rsa_decrypt(private_key, ciphertext):
    rsa = pk.RSA.from_PEM(private_key)
    plaintext = rsa.decrypt(ciphertext)
    return plaintext


def AES_encryptedFunc(key, message):
    key = key.encode()
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


def AES_decryptedFunc(key, data):
    # 将密钥编码为 bytes
    key = key.encode()

    # 从字典中提取 ciphertext、nonce 和 tag，并进行 base64 解码
    ciphertext = base64_to_bytes(data["cipher"])
    nonce = base64_to_bytes(data["nonce"])
    tag = base64_to_bytes(data["tag"])

    # 使用 AES-GCM 模式进行解密
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    return plaintext


def AES_encrpted(key, message):
    aes = AES.new(key, AES.Mode.GCM, key[:16], ad=key[16:])
    encryted_data, verify = aes.encrypt(message)
    return {
        "encrpted_data": bytes_to_base64(encryted_data),
        "verify": bytes_to_base64(verify)
    }


def AES_decrpted(key, encryted_message):
    aes = AES.new(key, AES.Mode.GCM, key[:16], ad=key[16:])
    encrpted_data = base64_to_bytes(encryted_message.get("encrpted_data"))
    verify = base64_to_bytes(encryted_message.get("verify"))
    return aes.decrypt(encrpted_data, verify)


import pickle

def transmit_encrypt_func(client, session_key, client_key, public_cas, login_message, optional_var=None):
    send_msg_key = {
        "client": client,
        "session_key": session_key
    }
    send_msg_key_encrypt = rsa_encrypt(public_cas, dict_to_bytes(send_msg_key))
    send_msg_hash = {
        "hashKey": double_hash(client, session_key),
    }
    send_msg_byte = dict_to_bytes(login_message)
    send_msg_hash_byte = dict_to_bytes(send_msg_hash)
    try:
        if optional_var is not None:
            message = {
                "message": {
                    "cipher": AES_encryptedFunc(session_key, send_msg_byte),
                    "sign": RSA_sign(client_key, send_msg_hash_byte),
                    "key": send_msg_key_encrypt,
                },
                "optional": optional_var
            }
        else:
            message = {
                "message": {
                    "cipher": AES_encryptedFunc(session_key, send_msg_byte),
                    "sign": RSA_sign(client_key, send_msg_hash_byte),
                    "key": send_msg_key_encrypt,
                },
                "optional": None
            }
        serialized_message = pickle.dumps(message)
    except Exception as e:
        print(f"Error: Failed to serialize message: {e}")
        return None

    print(f" Step2,3,4,5 common method ===> generate AES cipher, digital signature, public key cipher encrypted by "
          f"RSA =======>>>  {serialized_message}")
    return serialized_message

