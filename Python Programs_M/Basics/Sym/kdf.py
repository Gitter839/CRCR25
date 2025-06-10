import base64
from gc import get_referents
import json
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import scrypt
from cycler import K # For KDF


if __name__ == '__main__':
    password = b'Paperino'
    key = scrypt(password,get_random_bytes(16),16,N=2**20,r=8,p=1) # type: ignore
    print(key)