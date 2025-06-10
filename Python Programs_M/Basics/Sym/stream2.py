from email.mime import base
from encodings.base64_codec import base64_encode
import json
import sys
from Cryptodome.Cipher import AES , ChaCha20, Salsa20
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import base64

if __name__ == '__main__':

    # key = get_random_bytes(Salsa20.key_size[1]) 
    # iv = get_random_bytes(8) 

    # cipher = Salsa20.new(key= key, nonce= iv)
    # f_output = open(sys.argv[2], "wb")
    # ciphertext = b''

    # with open(sys.argv[1],"rb") as f_input: #rb :read binary __file__ is the file itself
    #     plaintext = f_input.read(1024) 
    #     while plaintext:
    #         ciphertext += cipher.encrypt(plaintext)
    #         f_output.write(ciphertext)
    #         plaintext = f_input.read(1024)
    
    # print("Nonce =" + base64.b64encode(cipher.nonce).decode())

    key = get_random_bytes(AES.key_size[0])
    iv =  get_random_bytes(AES.block_size)

    f_input = open(__file__,"rb")
    cipher = AES.new(key,AES.MODE_CBC,iv) # type: ignore

    ciphertext = cipher.encrypt(pad(f_input.read(),AES.block_size))
    f_out = open("enc.enc","wb")
    f_out.write(ciphertext)

    print(base64.b64encode(iv))

    ## PUT TOGHTER INFORMATION (NOT OFFICIAL, MESSAGE, IV .....) JSON

    result = json.dumps({'ciphertext': base64.b64encode(ciphertext).decode(), 'iv' : base64.b64encode(iv).decode()})
    print(result)


    ## the recipient has recivied the result
    ## ready to decrypt

    b64_output = json.loads(result)
    iv_rec = base64.b64decode(b64_output['iv'])
    ciphertext_rec = base64.b64decode(b64_output['ciphertext'])
    cipher_dec = AES.new(key,AES.MODE_CBC,iv_rec)
    plaintext_rec= cipher_dec.decrypt(ciphertext_rec) 
    print(plaintext_rec) 