from email.mime import base
from encodings.base64_codec import base64_encode
from Cryptodome.Cipher import AES , ChaCha20
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import base64
if __name__ == '__main__':

    plain_text = b'This is the secret message...'
    plaintext2 = b"This is additional text to encrypt"
    nonce = get_random_bytes(12)

    key = get_random_bytes(ChaCha20.key_size)
    cipher = ChaCha20.new(key = key, nonce= nonce)# nonce is no   
    ciphertext = cipher.encrypt(plain_text)
    ciphertext += cipher.encrypt(plaintext2) # Append second string 



    #base64 
    print("Ciphertext=" + base64.b64encode(ciphertext).decode())
    print("Nonce=" + base64.b64encode(cipher.nonce).decode()) 
