import os
os.environ['PWNLIB_NOTERM'] = 'True'
os.environ['PWNLIB_SILENT'] = 'True'
from pwn import *

from myconfig import HOST, PORT
from mydata import cbc_oracle_iv as iv
from mydata import cbc_oracle_ciphertext as ciphertext

from Cryptodome.Cipher import AES

if __name__ == '__main__':
    # server = remote(HOST,PORT) --Connect To The Server 
    # server.send(iv) 
    # server.send(ciphertext)
    # response = server. recv(1024)
    # print(response)
    # server.close()

    # server = remote(HOST,PORT)
    # server.send(iv)
    #
    # edt = bytearray(ciphertext)
    # edt[-1] = 0
    #
    # server.send(edt)
    # response = server. recv(1024)
    # print(response)
    # server.close()

#--------------------------------------------- Real Attack
    print(len(ciphertext)//AES.block_size)
    N = len(ciphertext)//AES.block_size #Needed Block 61 B -> 4 Block 64 B
    #Prepare the message for mounting the attack 
    initial_part = ciphertext[:(N-2)*AES.block_size] # Save the first N-2 Blocks 
    block_to_modify = bytearray(ciphertext[(N-2)*AES.block_size:(N-1)*AES.block_size]) # Penultimate Block (Crucial, becasus it is needed in the XOR (CBC))
    last_block = ciphertext[(N-1)*AES.block_size:] # Last Block


    byte_index = AES.block_size - 1 #Last Byte 
    c_15 = block_to_modify[byte_index] #CN-1,15

    for c_prime_15 in range(256):
        block_to_modify[byte_index] = c_prime_15
        to_send = initial_part + block_to_modify + last_block

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(to_send)
        response = server.recv(1024)
        # print(response)
        server.close()

        if response == b'OK': #Possibile multiple values , False Positive
            print("c_prime_15="+str(c_prime_15))
            p_prime_15 = c_prime_15 ^ 1 # XOR With 1 (Pad of Last Byte x/01)
            p_15 = p_prime_15 ^ c_15
            print("p_prime_15=" + str(p_prime_15))
            print("p_15=" + str(p_15))

    p_prime_15 = 191 # 1 of the values the other is 189 (Try with 189 is not work that menas the tehe correct one is 191)
    print("---------------")

    c_second_15 = p_prime_15 ^ 2
    block_to_modify[byte_index] = c_second_15

    byte_index -=1 # Second Last Byte 
    c_14 = block_to_modify[byte_index]

    for c_prime_14 in range(256):
        block_to_modify[byte_index] = c_prime_14
        to_send = initial_part + block_to_modify + last_block

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(to_send)
        response = server.recv(1024)
        server.close()

        if response == b'OK':
            print("c_prime_14="+str(c_prime_14))
            p_prime_14 = c_prime_14 ^ 2 # XOR with 2 
            p_14 = p_prime_14 ^ c_14
            print("p_prime_14=" + str(p_prime_14))
            print("p_14=" + str(p_14))

    print("---------------") # This is for the the last bytes - try to implement the generalization Get familiar with MATH operations of this algo
