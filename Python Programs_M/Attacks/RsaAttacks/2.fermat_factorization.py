from gmpy2 import isqrt
from Cryptodome.Util.number import getPrime, getRandomInteger
from gmpy2 import next_prime


def fermat(n):
    print("init")
    #a^2 - b^2 = n = (a+b)(a-b)
    #a -> indpendent variable 
    #b will be dependent on n, a
    #b2 = a^2 - n 
    a = isqrt(n)
    b = a
    b2 = pow(a,2) - n

    print("a= "+str(a))
    print("b= " + str(b))

    print("b2=" + str(b2))
    print("delta-->" + str(pow(b, 2) - b2 % n)+"\n-----------")
    print("iterate")
    i = 0

    while True:
        if b2 == pow(b,2): # b2 satsifie the first equation (a-b)(a+b)
            print("found at iteration "+str(i))
            break;
        else:
            a +=1 #update a and recompute other value
            b2 = pow(a, 2) - n
            b = isqrt(b2)
        i+=1
        print("iteration="+str(i))
        print("a= " + str(a))
        print("b= " + str(b))
    print("b2 =" + str(b2))
    print("delta-->" + str(pow(b, 2) - b2 % n) + "\n-----------")

    p = a+b
    q = a-b

    return p,q

if __name__ == '__main__':

    #Construct Twe primes that are closely each other
    n = 400
    p1 = getPrime(n)
    delta = getRandomInteger(100) #more are far the number more complex is the computation of fermat. Fermat convergnce fast if delta is small
    #select prime appropiately otherwise rsa can be broken, rsa is strong only if you choose correctly the prime numbers
    # delta = getRandomInteger(100)
    p2 = next_prime(p1+delta)
    print(p1)
    print(p2)
    print(p2-p1)

    n = p1*p2
    n = 2061967200227682478892466800664375981780200323053931198705407209204250941958336129844795487423453613029326452196390948676768692154173488243846139936920256794251314998112316290908934913863837212956458092446009358741194058371369097581541094913
    #a^2 - b^2 = n = (a+b)(a-b)
    #a -> indpendent variable 
    #b will be dependent on n, a
    #b2 = a^2 - n 
    p,q = fermat(n)

    print("p = "+str(p))
    print("q = " + str(q))
