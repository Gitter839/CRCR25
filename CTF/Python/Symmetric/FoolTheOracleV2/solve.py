#!/usr/bin/env python3
from pwn import remote
from Cryptodome.Cipher import AES

SERVER = "130.192.5.212"
PORT = 6542

def oracle(r, input_bytes: bytes) -> bytes:

    #Manage the input and output of the CTF server 

    # input for the menu 
    r.recvuntil(b"> ")
    # send enc
    r.sendline(b"enc")
    # input for the plaintext 
    r.recvuntil(b"> ")
    # send the plaintext in hex 
    r.sendline(input_bytes.hex().encode())
    # get the cipher 
    ciphertext_hex = r.recvline().strip()
    # return the cipher in bytes 
    return bytes.fromhex(ciphertext_hex.decode())

def main():

    r = remote(SERVER, PORT)
    
    block_size = AES.block_size

    #The server encrypt data with AES-ECB(Forunately), so we can perfor the attack 1 Byte At time 
    #Explained by thte Professor 
    #Thannks to the assert in the server code we notice that tha flag is length 46 char
    unknown_length = 46 
    
    #In the version 2 of the oracle, a genious has added an additional padding of 5 Bytes so we must remove
    #this effect so we put a fixed part compesed by the 5 B of the server and additional 11 B so to compose an
    #entire block in order to ingore this block of extra padding
    #For this reason the flag starts form the block 1 and not from block 0
    fixed_align = b"A" * 11

    recovered = b"" 

    for i in range(unknown_length): # For each char of the flag
        
        #For each unkonw byte, the strategy is to add as needed padding to put the current unknown byte
        #as the last byte of the block, so prefix_len is block_size - 1 - many_byte_just_recovered
        prefix_len = block_size - 1 - (i % block_size)
        prefix = b"A" * prefix_len

        #in this case the message to send to the server is the first fixed part + the usal prefix
        prefix_align = fixed_align + prefix

     
        ciphertext = oracle(r, prefix_align)
        
        target_block_index = 1 + (i // block_size) # for the target block we add 1 because the first block is useless
        start = target_block_index * block_size
        end = start + block_size
        target_block = ciphertext[start:end]
        
        dictionary = {} #For each byte we define a dictionary that contains the possible candidates, 
        #for the unkonwn byte
        for candidate in range(256):
            test_input = fixed_align + prefix + recovered + bytes([candidate]) # add the fixed_allign
            ct = oracle(r, test_input)
            candidate_block = ct[start:end]
            dictionary[candidate_block] = bytes([candidate])
        
        #if the target_block is in the dict it means that we find the block and the unknown byte
        if target_block in dictionary:
            recovered += dictionary[target_block]
            print(f"Recovered {len(recovered):2d} byte(s): {recovered}")

    print("FLAG= ", recovered.decode())
    r.close()

if __name__ == '__main__':
    main()
