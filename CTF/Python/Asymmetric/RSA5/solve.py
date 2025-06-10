#il server stampa n e c (ciphertext of the flag)
#poi se mettiamo e (cripta) o d (decripta) il numero che segue dopo la lettera iniziale, ovviamente se 
#inserime e+c il server scatena un assert quello che possiamo fare è sfruttare la propietà delle potenze in maniera 
#tale da modificare c con c' per non far scatenere l'assert 

# c' = c*k^e mod (n) quindi sceglo k = 25 ad esempio lo moltiplico per c 
# dopdiche inviamo d+c' in modo tale da far performare al server la seguente operazione 
# dec = pow(int(req[1:]), d, n) -> in termini matematici:
# dec = c'^d mod (n) ma c' = c*k^e -> dec = (c*k^e )^d mod (n)
# dec = c^d*k^(d*e) mod (n) ma d*e = 1 e c^d = m e poi basta dividere per k 
#quindi dec = m = flag 

from Cryptodome.Util.number import inverse, long_to_bytes
from pwn import remote

HOST, PORT = "130.192.5.212", 6645
e = 65537
k = 25                # fattore scelto (coprimo con n e ≠ 1)


io = remote(HOST, PORT)
n = int(io.recvline().strip())
c = int(io.recvline().strip())

c_prime = (c * pow(k, e, n)) % n
io.sendline(b"d" + str(c_prime).encode())

dec = int(io.recvline().strip())          
m = (dec * inverse(k, n)) % n
flag = long_to_bytes(m).decode()

print("FLAG:", flag)
