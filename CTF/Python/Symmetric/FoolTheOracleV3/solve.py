#!/usr/bin/env python3
from pwn import remote
from Cryptodome.Cipher import AES

SERVER = "130.192.5.212"
PORT = 6543

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

def detect_prefix(r, block_size=16):

    for i in range(block_size * 2):
        #we construct data until we reach due adjcent block that are identical,
        #if the two block are indetical that means the random padding is out, and
        #so we compute the number of bytes of the random padding 
        data = b"A" * (i + block_size * 2)
        ct = oracle(r, data)
        #divide the ciphertext in blocks 
        blocks = [ct[j:j+block_size] for j in range(0, len(ct), block_size)] 
        for j in range(len(blocks) - 1): # for eah block 
            if blocks[j] == blocks[j+1]: #check if two adjacent block are equal
                unknown_prefix_len = j * block_size - i
                return unknown_prefix_len, i
    return None, None

def main():
  
    r = remote(SERVER,PORT)
    block_size = AES.block_size

    
    #In the version 3, the problem is that the padding is variable, infact in the server implementation
    #we notice that the server add a random pad between 1 and 15 Bytes. For that we had implement a function
    #that detect the prefix and the pad bytes
    unknown_prefix_len, pad_bytes = detect_prefix(r, block_size)

    

    #Here we construct the blocks that are before the our blocks 
    alignment = b"A" * pad_bytes
    total_prefix = unknown_prefix_len + pad_bytes
    prefix_blocks = total_prefix // block_size  # number of block that are before the our controlled blocks
  
    unknown_length = 46
    recovered = b""
    
    for i in range(unknown_length):
        #in this way we are sure that the unknown byte occupies the last byte of the block 
        prefix_len = block_size - 1 - (i % block_size)
        prefix = b"A" * prefix_len

        
        #we have the query that is composed in this way : unknown_prefix || alignment || prefix || flag
        #so the flag starts perfectly in one block 
        query = alignment + prefix
        ct = oracle(r, query)

        
        start = (prefix_blocks + (i // block_size)) * block_size
        end = start + block_size
        target_block = ct[start:end]

        dictionary = {}
        for candidate in range(256):
            test_input = alignment + prefix + recovered + bytes([candidate])
            ct_candidate = oracle(r, test_input)
            candidate_block = ct_candidate[start:end]
            dictionary[candidate_block] = bytes([candidate])
        
        if target_block in dictionary:
            recovered += dictionary[target_block]
            print(f"Recovered {len(recovered):2d} byte(s): {recovered}")
    

    print("FLAG= ", recovered.decode())
    r.close()

if __name__ == '__main__':
    main()
