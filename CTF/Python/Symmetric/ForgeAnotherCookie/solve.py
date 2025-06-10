#!/usr/bin/env python3
from pwn import remote
from Cryptodome.Util.number import long_to_bytes, bytes_to_long
from Cryptodome.Cipher import AES

BLOCK_SIZE = AES.block_size
SERVER = "130.192.5.212"
PORT = 6552



def main():

    server = remote(SERVER, PORT)
    
    
    server.recvuntil(b"Username:")#Send the username
    #The most important part is the right selection of the username, becasue the username is the only part that we control 
    #The username is constructed in this way : ABCDEFG is the first part of the username that is used to fill the first block that starts with username=
    #then with add an entire block of padding in order to put this block as the last block of the forged cookie, I have selected \x10 because the server use 
    #pkcs7 as padding, and pkcs7 add N bytes with N value as nedded, in this case the padding is 16 byte(entire block) in hex 16 is \x10
    #then we write "true" followed by 21 blank_space, that is needed for forge admin=true. We put 21 blank_space in order to have &admin= at end of the 4 block
    #so the Orginal cookie is composed:
    # username=ABCDEFG || \x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10 || true            ||          &admin= || false\xB\xB\xB\xB\xB\xB\xB\xB\xB\xB\xB
    server.sendline(b"ABCDEFG\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10true                     ")  

    
    
    original_cookie = server.recvline().strip()
    int_cookie = int(original_cookie)
    hex_cookie = long_to_bytes(int_cookie).hex()

    #the forged cookie is construct in this way 
    # username=ABCDEFG ||           &admin= || true            || \x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10
    # the server will remove the last block because is only padding and the process the cookie
    # accordinf with the server , the username us ABCDEFG+9blank_space and admin=true   , so the server believe that i are an admin and give me the flag
    forged_cookie = hex_cookie[:32] + hex_cookie[96:128] + hex_cookie[64:96] + hex_cookie[32:64]
    forged_cookie = bytes_to_long(bytes.fromhex(forged_cookie))


    server.recvlines(4)#read the menu
    server.sendlineafter(b">", b"flag") #send flag
    server.sendlineafter(b"Cookie:", str(forged_cookie).encode()) #send the forged cookie
    print(server.recvline().decode()) #retrieve and print the flag 

    
    
    



    
    
   

if __name__ == "__main__":
    main()