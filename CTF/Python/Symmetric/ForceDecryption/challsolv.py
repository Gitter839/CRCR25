import binascii
#this program construct the ivForged 

iv0 = bytes.fromhex("39c556ce112523e8871619251bdca2ea")  # sostituisci con l'IV ricevuto
leak = b"mynamesuperadmin"         # 16 byte

forged_iv = bytes(a ^ b for a, b in zip(iv0, leak))
print(f"Forged IV: {forged_iv.hex()}")


#the idea is the following:
#encrpypt with the server this message "00000000000000000000000000000000" 16B at 0
#Encryption : Enc(Message xor IV0) due to the fact that message is 0 the 
#encryption give by the server is the encryption of the IV0, so after the command enc
#the server give us the IV and the encryption of IV 

#Now , during the decryption fortunately the serve ask us the IV, but we must give
#a forged IV in order to during the decrtpyion phase we are able to force the 
#plaintext to be the leak (mynamesuperadmin)
#the decryption is : plaintext = Dec(c0) xor IVforged 
# plaintext = IV0 xor IVforged -> IVforged = plaintext(mynamesuperadmin) xor IV0
#during the decryption wi give the encryption message generated before (enc of IV0)
#and the IVforged in order to compute that 
#plaintext = Dec(c0) xor (IV0 xor leak) = IV0 xor IV0 xor leak = leak 
#so the server give us the flag that is Good job. Your flag: CRYPTO25{096496ba-c281-42d9-84f4-af05b39cb006}