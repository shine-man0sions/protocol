import os
import json
import socket
import time
import random
import base64
import hashlib

from argparse import ArgumentParser
from mbedtls import pk
from mbedtls.cipher import AES

from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


RECV_LEN = 4 * 1024

# cookies will lost after an hour without sending message
COOKIES_EXPIRED = 3600


def parse_args():
    # parse the command line arguments host and port
    args = ArgumentParser()
    args.add_argument('--host', default="127.0.0.1")
    args.add_argument('--port', default=5005, type=int)
    args.add_argument('--client', default="")
    return args.parse_args()


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
        combined_hash += hash_value
    sha256 = hashlib.sha256(combined_hash)
    return bytes.fromhex(sha256.hexdigest())


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


def format_public_key(client):
    return f"{client}_CA_public_key"


def format_key(client):
    return f"{client}_CA_key"


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


# confidentiality
def confidentiality(key, message):
    """return  base64  encrpted result, in order to use in json format"""
    aes = AES.new(key, AES.Mode.GCM, key[:16], ad=key[16:])
    encryted_data, verify = aes.encrypt(dict_to_bytes(message))
    return {
        "encrpted_data": bytes_to_base64(encryted_data),
        "verify": bytes_to_base64(verify)
    }


# RSA signature
def RSA_sign(key, message):
    """return  base64  sign result, in order to use in json format"""
    rsa = pk.RSA.from_PEM(key)
    sig = rsa.sign(dict_to_bytes(message), "sha256")
    return bytes_to_base64(sig)


# RSA verify signature
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


# def RSA_encrypt(public_key, message):
#     """使用RSA公钥对消息进行加密"""

#     public_key = RSA.importKey(public_key)
#     cipher = PKCS1_OAEP.new(public_key)
#     ciphertext = cipher.encrypt(message)
#     print(",,,,----000<")
#     return bytes_to_base64(ciphertext)


# def RSA_decrypt(private_key, ciphertext):
#     """使用RSA私钥对密文进行解密"""
#     rsa = pk.RSA.from_PEM(private_key)
#     plaintext = rsa.decrypt(ciphertext)
#     return plaintext.decode()