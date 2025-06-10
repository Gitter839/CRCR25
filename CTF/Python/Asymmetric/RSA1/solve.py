from Cryptodome.Util.number import long_to_bytes
from factordb.factordb import FactorDB
# n i small so we can use FACTOR DB or yafu (too much for this )
# RSA parameters
n = 176278749487742942508568320862050211633
c = 46228309104141229075992607107041922411
e = 65537

# 1) Query FactorDB
f = FactorDB(n)
f.connect()
factors = f.get_factor_list()     # e.g. [14364722473065221639, 12271643243945501447]


p, q = factors
print(f"Found via FactorDB: p = {p}, q = {q}")

# 2) Compute φ(n) and private exponent d
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

# 3) Decrypt ciphertext
m = pow(c, d, n)
flag = long_to_bytes(m)
print("Recovered flag:", flag.decode())
