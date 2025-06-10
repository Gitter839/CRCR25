#!/usr/bin/env python3
import sys

def xor_bytes(b1, b2):
    return bytes(x ^ y for x, y in zip(b1, b2))

def main():
    if len(sys.argv) != 4:
        print("Wrong parameters...")
        sys.exit(1)

    # After the seed , the server give us the secret(the flag)
    secret_hex = sys.argv[1]
    # We send to the server a known plain text that has the same legnth of the flag (46) for example 'A'*46
    known_plaintext = sys.argv[2]
    # the server give us the the correspondet chiper of the our plaintext 
    new_cipher_hex = sys.argv[3]

    secret_cipher = bytes.fromhex(secret_hex)
    new_cipher = bytes.fromhex(new_cipher_hex)


    #secret_message = flag xor keystream
    #mychiper = myplain xor keystream -> keystream = mychipher xor myplain 
    # flag = scret_message xor keystream 

    keystream = xor_bytes(new_cipher, known_plaintext.encode())

    # Recupera la flag: flag = secret_cipher XOR keystream
    recovered_flag = xor_bytes(secret_cipher, keystream)

    # Stampa la flag (in modo “sicuro” in caso ci siano caratteri non ASCII)
    print("Flag:", recovered_flag.decode('utf-8', errors='replace'))

if __name__ == "__main__":
    main()
