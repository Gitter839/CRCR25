from Cryptodome.Util.number import getPrime
from Cryptodome.PublicKey import RSA
from sympy import public




if __name__ == '__main__':

    n_length = 1024

    p1 = getPrime(n_length)
    p2 = getPrime(n_length)

    print("p1="+str(p1))
    print("p1="+str(p1))


    n = p1*p2 
    print("n="+str(n))
    phi = (p1-1)*(p2-1)

    #define the public exponent
    e = 65537


    #gcd 
    from math import gcd
    g = gcd (e,phi)

    print("GCD="+str(g))

    if g != 1:
        raise ValueError 
    

    d = pow(e,-1,phi) #Inverse of e (modulus phi)
    print("d="+str(d))

    public_rsa_key = (e,n)
    private_rsa_key = (d,n)

    #Implement the enceyption 
    msg = b'this is the message to encrypt' #Require a trasformation in a integer
    msg_int = int.from_bytes(msg,byteorder='big')
    print("msg="+str(msg_int))

    if msg_int > n-1: # If the message is greater than the n (modulus) raise expection because it can be cutted, and that not ensure to recover perferctly the mesage during the decrption 
        raise ValueError

    C = pow(msg_int,e,n)
    print("Ciphertext="+str(C))


    D = pow(C,d,n)
    print("ClearText="+str(D))

    #Reconstrut the message 

    msg_dec = D.to_bytes(n_length,byteorder='big')
    print("CiphertextSTR="+str(msg_dec))