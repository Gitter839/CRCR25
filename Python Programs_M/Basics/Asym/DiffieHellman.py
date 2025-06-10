from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.constant_time import bytes_eq
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

if __name__ == '__main__':

    #Genertate the parameters (ALice or Bob)
    parameters = dh.generate_parameters(generator= 2, key_size= 1024, backend= default_backend())

    #Alice
    private_key_alice = parameters.generate_private_key()
    #Bob
    public_key_bob = parameters.generate_private_key().public_key()

    #Alice
    shared_secret = private_key_alice.exchange(public_key_bob)

    derived_key = HKDF( # This is the obj HKDF then call derive function 
        algorithm= hashes.SHA256(),
        length=32,
        salt= None,
        info= b'just agreed data',
        backend=default_backend()
    ).derive(shared_secret)


    #EPhermal 

    private_key_alice2 = parameters.generate_private_key()
    public_key_bob2 = parameters.generate_private_key().public_key()
    shared_secret2 = private_key_alice2.exchange(public_key_bob2)


    derived_key2 = HKDF( # This is the obj HKDF then call derive function 
        algorithm= hashes.SHA256(),
        length=32,
        salt= None,
        info= b'just agreed data',
        backend=default_backend()
    ).derive(shared_secret2)



