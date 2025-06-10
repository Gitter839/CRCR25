#!/usr/bin/env python3
from pwn import remote
from Cryptodome.Cipher import AES

SERVER = "130.192.5.212"
PORT = 6541

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
    recovered = b""

    for i in range(unknown_length): # For each char of the flag 
    
        #For each unkonw byte, the strategy is to add as needed padding to put the current unknown byte
        #as the last byte of the block, so prefix_len is block_size - 1 - many_byte_just_recovered
        prefix_len = block_size - 1 - (len(recovered) % block_size)
        prefix = b"A" * prefix_len
        
        # Determiniamo il blocco target (indice del blocco in cui si trova il byte incognito):
        # Ad esempio, se abbiamo già recuperato 0 byte (len(recovered) == 0), il byte incognito si troverà nel blocco 0
        # Se abbiamo recuperato 16 byte, il byte successivo sarà nel blocco 1, e così via.

        #Identify the block that contains the unkonwbyte , if we yet hadn't recovered the first 16 B, it means 
        #that the current unknown byte is in the first block
        target_block_index = len(recovered) // block_size
        
        # get the ciphertext by the server
        ciphertext = oracle(r, prefix)
        start = target_block_index * block_size
        end = start + block_size
        target_block = ciphertext[start:end]
        
        dictionary = {} #For each byte we define a dictionary that contains the possible candidates, 
        #for the unkonwn byte
        for candidate in range(256): # We find a possible candidate in the 256 UTF Chars 
            #input text is composed by the prefix, already recovered bytes and obviusly the candidate
            test_input = prefix + recovered + bytes([candidate])
            #get the chipertext form the server, with input the test_input
            ct = oracle(r, test_input)
            # Get the candidate block (index previous computed)
            candidate_block = ct[start:end]
            dictionary[candidate_block] = bytes([candidate])
        
        #if the target_block is in the dict it means that we find the block and the unknown byte
        if target_block in dictionary:
            recovered += dictionary[target_block] # get the bythe 
            print(f"Recovered {len(recovered):2d} byte(s): {recovered}")

    print("FLAG= ", recovered.decode())
    r.close()

if __name__ == '__main__':
    main()
