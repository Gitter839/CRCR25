from hmac import digest
from Cryptodome.Hash import SHA3_256
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import HMAC
import base64

import json

if __name__ == '__main__':
    # hash_generator = SHA3_256.new()
    #Simple Hash
    # # Open File 
    # with open(__file__,"rb") as f_input:
    #     hash_generator.update(f_input.read().encode()) #encode() transform ASCII in to sequence of Bytes

    # print(hash_generator.hexdigest())

    #HMAC w/ secret 
    msg = b'This is the message used in the input'
    secret = get_random_bytes(32); 

    hmac_generator = HMAC.new(secret,digestmod= SHA3_256)
    hmac_generator.update(msg)
    print(hmac_generator.hexdigest())

    #Json DATA

    obj = json.dumps({'message':msg.decode(), 'MAC':base64.b64encode(hmac_generator.digest()).decode()})
    print(obj)


    b64_obj = json.loads(obj)
    hmac_verifier = HMAC.new(secret,digestmod=SHA3_256)

    hmac_verifier.update(b64_obj['message'].encode())

    ##Small modification 
    mac = bytearray(base64.b64decode(b64_obj['MAC'].encode()))
    mac[0] = 0 

    try:
        hmac_verifier.verify(mac)
        print("The message is authentic")
    except ValueError:
        print("The message is not authentic")