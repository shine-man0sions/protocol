"""generate public ca key by RSA
"""
import json
from mbedtls import pk
from utils import *


def generate_key_by_RSA():
    rsa = pk.RSA()
    rsa.generate()

    public_key = rsa.export_public_key("PEM")
    key = rsa.export_key("PEM")
    key_sign = RSA_sign(key, public_key)
    return public_key, key, key_sign

# 2. Generate the public key and private key of each entity.
# Each entity has a public key and a private key.
# The public key is used to verify the signature of the message.
def write_to_config(filename='config.json'):
    S = generate_key_by_RSA()
    A = generate_key_by_RSA()
    B = generate_key_by_RSA()
    C = generate_key_by_RSA()
    res_dict = {
        "public_key": {
            "S_CA_public_key": S[0],
            "A_CA_public_key": A[0],
            "B_CA_public_key": B[0],
            "C_CA_public_key": C[0]
        },
        "key": {
            "S_CA_key": S[1],
            "A_CA_key": A[1],
            "B_CA_key": B[1],
            "C_CA_key": C[1]
        },
        "key_sign": {
            "S_CA_key_sign": S[2],
            "A_CA_key_sign": A[2],
            "B_CA_key_sign": B[2],
            "C_CA_key_sign": C[2]
        },   
    }
    with open(filename, "w") as fw:
        fw.write(json.dumps(res_dict, indent="\t"))


if __name__ == '__main__':
    filename = "config.json"
    write_to_config(filename)
