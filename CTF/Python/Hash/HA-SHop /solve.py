import socket
import re
import sys
from binascii import unhexlify, hexlify # from hex to byted , from bytes to hex 
#mac e copoun devono essere esadecimali prima di essere inviati al serve 


from hashpumpy import hashpump

HOST = '130.192.5.212'
PORT = 6630
USERNAME = 'Joker'
KEY_LEN = 16          # lunghezza di SECRET nel server SECRET = os.urandom(16)
FORGE = b"&value=1000"  # nuovo valore per ottenere flag value deve essre >100

# Funzione per leggere fino a un pattern
def recv_until(sock, pattern):
    data = b""
    while pattern not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

# Connetti al server
s = socket.create_connection((HOST, PORT))

# Inserisco Username per prendere copoun e mac originali 
recv_until(s, b"Choose an option")
s.sendall(b"1\n")
recv_until(s, b"Enter your name:")
s.sendall(USERNAME.encode() + b"\n")
text = recv_until(s, b"Menu:")

# Estrai coupon e MAC
coupon_originale = re.search(rb"Coupon: ([0-9a-fA-F]+)", text) # prende la stringa che matcha con il parametro passato 
mac_originale = re.search(rb"MAC: +([0-9a-fA-F]+)", text)

#Da slides del Prof 

# A general purpose tool
# HashPump automatically implements the attack for several
# algorithms
# ◦ implemented in C++
# ◦ https://github.com/bwall/HashPump


coupon_originale_hex = coupon_originale.group(1).decode() # group(1) prende solo il valore hex non tutto il testo
mac_originale_hex = mac_originale.group(1).decode()
orig_msg = unhexlify(coupon_originale_hex)
print(f"[*] Coupon originale: {coupon_originale_hex}")
print(f"[*] MAC originale:    {mac_originale_hex}")

# 2) Length-extension attack usando hashpump
# hashpump ritorna (nuova_mac, nuovo_message)
new_mac, new_msg = hashpump(mac_originale_hex, orig_msg, FORGE, KEY_LEN)

# Convertiamo a esadecimale nuovo coupon e nuovo mac 
new_hex = hexlify(new_msg).decode()
print(f"[*] Nuovo coupon:     {new_hex}")
print(f"[*] Nuovo MAC:        {new_mac}")

# Prendo la flag 
recv_until(s, b"Choose an option")
s.sendall(b"2\n")
recv_until(s, b"Enter your coupon:")
s.sendall(new_hex.encode() + b"\n")
recv_until(s, b"Enter your MAC:")
s.sendall(new_mac.encode() + b"\n")

# Leggi il risultato finale
flag = recv_until(s, b"\n")
print(flag.decode())

s.close()
