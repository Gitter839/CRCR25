# from Cipher import AES
# from Crypto.Random import get_random_bytes
# Old library subistutue by CryptoDome

from Cryptodome.Cipher import AES 
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad


if __name__ == '__main__':

    # Random Bytes 
    print(get_random_bytes(40))
    #IV (Get Size From Algo Class)
    IV = get_random_bytes(AES.block_size) ;

    #Generete Key And Enc

    print(AES.key_size) # VArious Size of AES ; 
    key = get_random_bytes(AES.key_size[2]) # 256 Bit Key
    plaintext = b'These are the data to encrypt !!' #b is used to specidy that are treated as BYTES (String of B)

    cipher_enc_obj = AES.new(key,AES.MODE_CBC,IV)
    cipher_text = cipher_enc_obj.encrypt(plaintext)

    

    print(cipher_text)

    #Decryption, Instatiate another obj dont use tha same of enc

    decipher_obj = AES.new(key,AES.MODE_CBC,IV)
    decrypted_message = decipher_obj.decrypt(cipher_text)

    print(decrypted_message)

    plaintext = b'Unaligned string...' # We need PADDing
    cipher_enc_obj = AES.new(key, AES.MODE_CBC,IV)
    padded_data = pad(plaintext,AES.block_size)
    print(padded_data)
    cipher_text = cipher_enc_obj.encrypt(padded_data)
    print(cipher_text)

    plaintext2 = b'AdditionalData'
    padded_data = pad(plaintext2,AES.block_size)
    cipher_text += cipher_enc_obj.encrypt(padded_data)
    print(cipher_text)

    #Decryption, Instatiate another obj dont use tha same of enc With UNPAD

    decipher_obj = AES.new(key,AES.MODE_CBC,IV)
    decrypted_data = decipher_obj.decrypt(cipher_text);
    decrypted_data_unpaddded = unpad(decrypted_data,AES.block_size)
    print(decrypted_data)
    print(decrypted_data_unpaddded)