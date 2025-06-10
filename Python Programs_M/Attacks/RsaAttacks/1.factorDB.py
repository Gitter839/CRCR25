from Cryptodome.Util.number import getPrime
from factordb.factordb import FactorDB
n_length = 13

p1 = getPrime(n_length)
p2 = getPrime(n_length)
print(p1)
print(p2)

#n = p1 * p2
n = 2061967200227682478892466800664375981780200323053931198705407209204250941958336129844795487423453613029326452196390948676768692154173488243846139936920256794251314998112316290908934913863837212956458092446009358741194058371369097581541094913

print(n)
print("---------------------------------")
f = FactorDB(n)
f.connect()
print(f.get_factor_list())

#For better computation use yafu-1.34 that is better than FactorDB (Very Powerful)
