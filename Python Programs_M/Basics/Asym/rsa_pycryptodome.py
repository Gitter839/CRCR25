from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pss
from Cryptodome.Cipher import PKCS1_OAEP


if __name__ == '__main__':
    rsa_key = RSA.generate(2048)
    print(rsa_key.export_key(format='PEM',pkcs=8))


    f = open('./Asym/myprivatekey.pem','wb')
    f.write(rsa_key.export_key(format='PEM', pkcs=8,passphrase='longpassphraseverysecure')) #passphrase encrypt the private key with a passphrase
    f.close()

    print(rsa_key.n)
    print(rsa_key.e)
    print(rsa_key.d)
    print(rsa_key.p)
    print(rsa_key.q)

    recovered_rsa_key = RSA.construct((rsa_key.n, rsa_key.e, rsa_key.d, rsa_key.p, rsa_key.q),consistency_check=True) #Consistency_check is used to verify 
    #the primes correctly formed the other parameters such as n , d , e and so on It is usueful for attacks, to understand if are correct

    public_rsa_key = rsa_key.public_key()
    print(public_rsa_key.export_key())




    ###
    message = b'This is the message to sign'
    h = SHA256.new(message)
    signature = pss.new(rsa_key).sign(h) # type: ignore #Sign the hash of the mesage using SK 


    print(signature)


    ##### Verifcation of signautre

    hv = SHA256.new(message) #Start from the digest
    verfier = pss.new(public_rsa_key) # Verify the signature

    try:
        verfier.verify(hv,signature) # type: ignore
        print("The sign is ok")
    except(ValueError, TypeError):
        print("The sign is invalid")


    #### Encypt and DEcr
    message = b'This the message to encrypt'

    #For Padding PKCS1:OEAP  generate a cipher object that work on public material
    cipher_pub = PKCS1_OAEP.new(public_rsa_key)
    cipher_text = cipher_pub.encrypt(message)


    print("Ciphertext="+str(cipher_text))

    cipher_priv = PKCS1_OAEP.new(rsa_key)
    message_dec = cipher_priv.decrypt(cipher_text)

    print("Clear="+str(message_dec))