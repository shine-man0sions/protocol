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

def parse_args():
    """
    :return: parse the command line arguments host and port
    """
    args = ArgumentParser()
    args.add_argument('--host', default="127.0.0.1")
    args.add_argument('--port', default=5006, type=int)
    args.add_argument('--client', default="")
    return args.parse_args()


# Used to read from a JSON file and convert it to a Python dictionary object
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


def read_json_to_dict(filename):
    with open(filename, "r") as fr:
        res_dict = json.loads(fr.read())
    return res_dict


def generate_random_hash256():
    # generate random byte hash256
    byte_to_hash = os.urandom(random.randrange(100, 1000))
    sha256 = hashlib.sha256(byte_to_hash)
    return sha256.hexdigest()

def combine_hash_values(s):
    """
    combine multiple hash values by concatenating and hashing
    generate and return Kabc
    :return: Kabc
    """
    combined_hash = b''
    sorted_arr = sorted(s)
    for hash_value in sorted_arr:
        combined_hash += bytes.fromhex(hash_value)
    sha256 = hashlib.sha256(combined_hash)
    return bytes.fromhex(sha256.hexdigest())


def double_hash(obj):
    """
    :return:  hash data used to compare with RSA digital signature
    """
    if isinstance(obj, bytes) is not True:
        obj_str = json.dumps(obj, sort_keys=True).encode('utf-8')
    else:
        obj_str = obj
    sha256_hash = hashlib.sha256()
    sha256_hash.update(obj_str)
    return sha256_hash.hexdigest()



def format_public_key(client):
    return f"{client}_CA_public_key"

def RSA_sign(key, message):
    """
    :return:  base64  sign result, in order to use in json format
    """
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
    """
    :return: cipher encrypted with RSA public key
    """
    rsa = pk.RSA.from_PEM(public_key)
    ciphertext = rsa.encrypt(plaintext)
    return ciphertext


def rsa_decrypt(private_key, ciphertext):
    """
    :return: plaintext dencrypted with RSA private key
    """
    rsa = pk.RSA.from_PEM(private_key)
    plaintext = rsa.decrypt(ciphertext)
    return plaintext


def transmit_encrypt_func(text, client_key, public_cas, login_message, optional_var=None):
    """
        :return: data include
        1. cipher encrypted by RSA public key
        2. hash data using hash function to compare with RSA digital signature
        3. RSA sign
    """
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
    # Format the output date-time string
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")
    print("==>" + now_str + " " + msg)
    print(data)


def aes_encrypt(key: str, data: str) -> str:
    """
    AES Encryption method
    :param key: The key must be a string of 16, 24, or 32 characters
    :param data: The data to be encrypted must be a string
    :return: An encrypted string, encoded in base64
    """
    key = key.encode('utf-8')
    data = data.encode('utf-8')

    # Create an AES encryptor
    cipher = AES.new(key, AES.MODE_CBC)

    # Encrypt data and populate it
    encrypted_data = cipher.encrypt(pad(data, AES.block_size))

    # The encrypted data is combined with iv and converted to base64 encoding
    return b64encode(cipher.iv + encrypted_data).decode('utf-8')


def aes_decrypt(key: str, encrypted_data: str) -> str:
    """
    AES Decryption method
    :param key: The key must be a string of 16, 24, or 32 characters
    :param encrypted_data: The data to be decrypted must be a base64 encoded string
    :return: The decrypted string
    """
    key = key.encode('utf-8')
    encrypted_data = b64decode(encrypted_data)

    # Separate iv and encrypted data from ciphertext
    iv = encrypted_data[:AES.block_size]
    data = encrypted_data[AES.block_size:]

    # Create an AES decryptor
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the data and de-populate it
    decrypted_data = unpad(cipher.decrypt(data), AES.block_size)

    return decrypted_data.decode('utf-8')
