from Cryptodome.Util.number import long_to_bytes
from pwn import remote

# RSA decryption oracle – exploit via multiplicative property
# Server prints only c = m^e mod n (flag encrypted) and allows 3 queries:
#   "eX" → encrypt X under e, "dY" → decrypt Y under d (asserts result ≠ m)
# Trick: use the encryption oracle to get E2 = 2^e mod n, then form c' = c * E2.
#       The decryption oracle returns (c')^d = m·2 mod n. Since 2m < n, there is
#       no wrap-around, so the returned value is exactly 2m. Recover m = dec//2.

HOST, PORT = "130.192.5.212", 6646
e = 65537

# 1) Connect and read ciphertext c
io = remote(HOST, PORT)
c = int(io.recvline().strip())

# 2) Get E2 = encrypt(2)
io.sendline(b"e2")
E2 = int(io.recvline().strip())

# 3) Form c' = c * E2
c_prime = c * E2

# 4) Decrypt c'
io.sendline(b"d" + str(c_prime).encode())
dec2m = int(io.recvline().strip())
io.close()

# 5) Recover m = dec2m // 2 and print the flag
m = dec2m // 2
print(long_to_bytes(m).decode())
