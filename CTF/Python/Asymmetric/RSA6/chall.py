from Crypto.Util.number import bytes_to_long, getPrime, inverse
from secret import flag

p, q = getPrime(512), getPrime(512)
n = p*q
e = 65537
m = bytes_to_long(flag.encode())
print(pow(m, e, n))




#Qui ho tre tentativi per fer criptare o decriptare qualcosa
#rispetto a rsa5 non abbiamo n (dio +++) ma abbiamo solo il cipher
#flag 
for _ in range(3):
    req = input()
    if req[0] == 'e':
        print(pow(int(req[1:]), e, n))
    elif req[0] == 'd':
        phi = (p-1)*(q-1)
        d = inverse(e, phi)
        dec = pow(int(req[1:]), d, n)
        assert dec != m
        print(dec)

# nc 130.192.5.212 6646 