import base64
import json
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

if __name__ == '__main__':

    header = b'this only needs authentication'
    payload =b'this also needs confidentiality'


    key = get_random_bytes(AES.key_size[2])

    cipher = AES.new(key, AES.MODE_GCM) # DON'T EXPLICT USE AN IV

    cipher.update(header) # Only for compute the tag AUTH
    ciphertext , tag = cipher.encrypt_and_digest(payload)

    json_keys = ['nonce' , 'header', 'ciphertext' ,'tag']
    json_values = [cipher.nonce, header, ciphertext, tag] 
    json_b64_values = [base64.b64encode(x).decode() for x in json_values]
    json_obj = json.dumps(dict(zip(json_keys,json_b64_values)))

    print(json_obj)


    ## at the verifier

    b64_obj = json.loads(json_obj)
    json_keys = ['nonce' , 'header', 'ciphertext' ,'tag']
    jv = {k:base64.b64decode(b64_obj[k]) for k in json_keys}


    cipher_reciever = AES.new(key,AES.MODE_GCM, nonce= jv['nonce'])

    cipher_reciever.update(jv['header'])
    

    try:
        cipher_reciever.decrypt_and_verify(jv['ciphertext'],jv['tag'])
        print("The message is authentic")
    except (ValueError,KeyError):
        print("ERrors with the TAG")
