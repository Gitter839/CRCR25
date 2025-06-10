#qui l'oracle per ogni input rilascia l'ultimo bit 
#per questo possiamo implmentare l'attacco spiegato dal Prof 
# Di sotto riporto la slide in riferimento: 

# LSB Oracle attack
# c= me mod n and m < n
# we send c’ = 2ec = 2e me=(2m)e
# ◦ if 2m < n the LSB is 0 [2m is a left shift e there is no overflow]
# ◦ therefore m < n/2
# ◦ m is in [0,n/2]
# ◦ if 2m > n the LSB is 1 [2m is a left shift, overflow]
# ◦ there is an overflow
# ◦ 2m (mod n) = 2m – n (mod n)
# ◦ n is odd  2m – n is odd
# ◦ m > n/2  m is in [n/2,n]
# send 4ec, 8ec, …, 2e*nbitc and do the same interval shrinking
# ◦ n bit is the size (in bit) of the modulus
# ◦ log (n) requests to the oracle



from fractions import Fraction
from pwn import remote
from Cryptodome.Util.number import long_to_bytes

HOST, PORT = "130.192.5.212", 6647
io = remote(HOST, PORT)

n = int(io.recvline().strip())
c = int(io.recvline().strip())
e = 65537
two_e = pow(2, e, n)

# intervallo [low, high) in frazioni di n  (0 ≤ m/n < 1)
# fraction da una string o un numero da un coppia num,den o un float 
low, high = Fraction(0), Fraction(1)

c_cur = c

while high - low > Fraction(1, n):
    c_cur = (c_cur * two_e) % n # moltiplica per 2^e mod (n)
    io.sendline(str(c_cur).encode())
    lsb = int(io.recvline().strip())

    # a seconda del lsb aggiorniamo l'intervallo
    mid = (low + high) / 2
    if lsb == 0:          # 2m < n  ⇒ m/n < ½
        high = mid
    else:                    # 2m ≥ n  ⇒ m/n ≥ ½
        low = mid

# any integer between low*n and high*n is the plaintext
m = int(high * n)
m1 = int(low*n)

print(long_to_bytes(m).decode())
print(long_to_bytes(m1).decode())