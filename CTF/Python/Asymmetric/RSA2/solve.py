from Cryptodome.Util.number import long_to_bytes
from factordb.factordb import FactorDB


#In questo caso i fattori p e q sono su 512 , factorDB non riesce a fattorizare n , per questo si usa yafu o qualcosa simile 

# Non sono riuscito ad installare yafu su linux arm64
# ho utilizatto questa soluzione che è basata su yafu 
# per fattorizare http://qurancode.com/
# ha trovato solo due fattori quindi non ho dovuto confrontare quali erano
# piu vicini (vedi chall.py, p e q sono due numeri primi successivi)

#see the image in dir
# Known prime factors of n
p = 7778775949692774689877137137701030837749137160531234682103862892116343595007505671487155323403357898511526514286087576976722384588036226671502190374114423
q = 7778775949692774689877137137701030837749137160531234682103862892116343595007505671487155323403357898511526514286087576976722384588036226671502190374114419

# Given RSA parameters
n = p * q
c = 44695558076372490838321125335259117268430036823123326565653896322404966549742986308988778274388721345811255801305658387179978736924822440382730114598169989281210266972874387657989210875921956705640740514819089546339431934001119998309992280196600672180116219966257003764871670107271245284636072817194316693323
e = 65537

# Compute φ(n) and the private exponent d
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# Decrypt the ciphertext
m = pow(c, d, n)
flag = long_to_bytes(m)

print(f"Recovered flag: {flag.decode()}")
