#!/usr/bin/env python3
from pwn import *

def main():
    r = remote("130.192.5.212", 6531)

    for _ in range(128):
        # 1) "Challenge #i"
        challenge_line = r.recvline().decode().strip()
        if not challenge_line.startswith("Challenge #"):
            return  # if mismatched, end

        # 2) "The otp I'm using: <otp_hex>"
        otp_line = r.recvline().decode().strip()
        if not otp_line.startswith("The otp I'm using: "):
            return
        otp_hex = otp_line[len("The otp I'm using: "):]
        otp = bytes.fromhex(otp_hex)

        # Here the trick, from the cipher is imposssibile to detect if is udes CBC so we can exploit ECB
        # Unfortunately, the professor add an OTP to make difficult out life (maybe)
        # The idea is to see the output that is composed by 2 block (32 B) and see if the frist block is equal to the second one
        # if yes ECB otherwise CBC
        # We want the final plaintext to be 32 'A's (two identical 16-byte blocks)
        desired_plaintext = b"\x41" * 32
        # user_input = desired_plaintext XOR otp so when the server performs the xor with the otp the otp will be remove
        # so we can see the encryption of the our deisdere plaintext 
        user_input = bytes(a ^ b for a, b in zip(desired_plaintext, otp))
        user_input_hex = user_input.hex()

        # Send the 64-hex input
        r.sendline(user_input_hex)

        # 3) "Input: Output: <ciphertext_hex>"
        output_line = r.recvline().decode().strip()
        if not output_line.startswith("Input: Output: "):
            return
        ciphertext_hex = output_line[len("Input: Output: "):]

        # 4) "What mode did I use? (ECB, CBC)"
        mode_prompt_line = r.recvline().decode().strip()

        # Distinguish mode by comparing the first 16 bytes vs. second 16 bytes
        block1 = ciphertext_hex[:32]
        block2 = ciphertext_hex[32:64]
        guess_mode = "ECB" if block1 == block2 else "CBC"
        r.sendline(guess_mode)

        # 5) "OK, next" or "Wrong, sorry"
        result_line = r.recvline().decode().strip()
        if "Wrong" in result_line:
            return  # stops if guess is incorrect

    # If we passed 128 rounds, read the final line (the flag)
    final_line = r.recvline(timeout=5)
    if final_line:
        print(final_line.decode().strip())

    r.close()

if __name__ == "__main__":
    main()
