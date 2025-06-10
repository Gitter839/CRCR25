#!/usr/bin/env python3
from pwn import *

def main():
    #The idea is different here because the server doesen't show the otp, but there are two encryption 
    #so with the two chipertext if the latters are equal that imply ECB otherwise CBC

    r = remote("130.192.5.212", 6532)

    # We will always send 32 'A' bytes
    # 32 'A' = 0x41 repeated 32 times => 64 hex digits
    a32 = b"\x41" * 32
    for i in range(128):
        r.recvline(timeout=5) # Discard Challange # line

    
        r.sendline(a32.hex())
        input_prompt1 = r.recvline(timeout=5)
        line_str = input_prompt1.decode().strip() 

        prefix = "Input: Output: "
        if line_str.startswith(prefix):
            cipher1 = line_str[len(prefix):] 
        else:
            cipher1 = ""  # Error Manage


        r.sendline(a32.hex())
        input_prompt2 = r.recvline(timeout=5)
        line_str = input_prompt2.decode().strip() 

        prefix = "Input: Output: "
        if line_str.startswith(prefix):
            cipher2 = line_str[len(prefix):]  
        else:
            cipher2 = ""  # Error Manage
        
        r.recvline(timeout=5) #discard "What mode did I use? (ECB,CBC)""
        guess_mode = "ECB" if cipher1 == cipher2 else "CBC"
        r.sendline(guess_mode)
        r.recvline(timeout=5) #discard "Ok, next" or "Wrong, sorry"


    #
    # After 128 correct guesses, we get the flag
    #
    flag_line = r.recvline(timeout=5)
    print(flag_line)

    r.close()

if __name__ == "__main__":
    main()
