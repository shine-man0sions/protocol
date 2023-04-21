import os
import json
import time
import random
import base64
import hashlib
import pickle
import datetime
from mbedtls import pk
from argparse import ArgumentParser
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
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


def double_hash(obj):
    if isinstance(obj, bytes) is not True:
        obj_str = json.dumps(obj, sort_keys=True).encode('utf-8')
    else:
        obj_str = obj
    sha256_hash = hashlib.sha256()
    sha256_hash.update(obj_str)
    return sha256_hash.hexdigest()


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
    if isinstance(key, bytes):
        pass
    else:
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


def transmit_encrypt_func(text, client_key, public_cas, login_message, optional_var=None):
    if isinstance(text, bytes) is True:
        send_msg_key_encrypt = rsa_encrypt(public_cas, text)
    else:
        send_msg_key_encrypt = rsa_encrypt(public_cas, dict_to_bytes(text))
    send_msg_hash = {
        "hashKey": double_hash(text),
    }
    send_msg_byte = dict_to_bytes(login_message)
    send_msg_hash_byte = dict_to_bytes(send_msg_hash)
    try:
        if optional_var is not None:
            message = {
                "message": {
                    "cipher": send_msg_byte,
                    "sign": RSA_sign(client_key, send_msg_hash_byte),
                    "key": send_msg_key_encrypt,
                },
                "optional": optional_var
            }
        else:
            message = {
                "message": {
                    "cipher": send_msg_byte,
                    "sign": RSA_sign(client_key, send_msg_hash_byte),
                    "key": send_msg_key_encrypt,
                },
                "optional": None
            }
        serialized_message = pickle.dumps(message)
    except Exception as e:
        print(f"Error: Failed to serialize message: {e}")
        return None
    return serialized_message


def printMsg(msg, data):
    now = datetime.datetime.now()
    # 格式化输出日期时间字符串
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    print("==>" + now_str + " " + msg)
    print(data)



def aes_encrypt(key: str, data: str) -> str:
    """
    AES 加密方法
    :param key: 密钥，必须为 16、24、32 字节长度的字符串
    :param data: 待加密的数据，必须为字符串类型
    :return: 加密后的字符串，base64 编码
    """
    key = key.encode('utf-8')
    data = data.encode('utf-8')

    # 创建 AES 加密器
    cipher = AES.new(key, AES.MODE_CBC)

    # 加密数据并进行填充
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    # 将加密后的数据和 iv 合并，转换为 base64 编码
    return b64encode(cipher.iv + encrypted_data).decode('utf-8')


def aes_decrypt(key: str, encrypted_data: str) -> str:
    """
    AES 解密方法
    :param key: 密钥，必须为 16、24、32 字节长度的字符串
    :param encrypted_data: 待解密的数据，必须为经过 base64 编码的字符串类型
    :return: 解密后的字符串
    """
    key = key.encode('utf-8')
    encrypted_data = b64decode(encrypted_data)

    # 从密文中分离出 iv 和加密后的数据
    iv = encrypted_data[:AES.block_size]
    data = encrypted_data[AES.block_size:]

    # 创建 AES 解密器
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 解密数据并进行去填充
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)

    return decrypted_data.decode('utf-8')
