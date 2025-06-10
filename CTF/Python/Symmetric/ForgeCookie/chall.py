#!/usr/bin/env python3
import base64

def main():
    print("Enter the original token by the server")
    original_token = input().strip()

    nonce_b64, enc_b64 = original_token.split(".")
    nonce = base64.b64decode(nonce_b64)
    enc_orig = base64.b64decode(enc_b64)
    orig_plain = b'{"username": "AAA"}'
    #From the server code we have if user.get("admin", False) == True so a valid user is {"admin":true}
    new_plain = b'{"admin": true}      ' #add blank space for padding to get the original length 
    
    #get key steream
    keystream = bytes(o ^ c for o, c in zip(orig_plain, enc_orig)) # we have enc_orig = orig_plain xor keystream -> keystream = origin_plain xor enc_origin 
    enc_new = bytes(k ^ n for k, n in zip(keystream, new_plain)) # enc with the retrivied keystream the new plaintext that contains admin user 
    
    #the {"username": "AAA"} ASCII rapresentation is 22 B, so if the enc_orig is more length than 22 it means that
    #the server add somethinh that we don't no so we append this additional text (not modified) to the forged_cipher
    if len(enc_orig) > 22: 
        remain = enc_orig[22:]
        forged_cipher = enc_new + remain
    else:
        forged_cipher = enc_new
    forged_cipher_b64 = base64.b64encode(forged_cipher).decode() #encode in b64
    forged_token = f"{nonce_b64}.{forged_cipher_b64}" #construct the cookie
    print(forged_token)

if __name__ == "__main__":
    main()

