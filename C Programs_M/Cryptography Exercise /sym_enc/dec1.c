#include   <stdio.h>
#include   <string.h>
// To create a context for encryption
#include   <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0



int main()
{
    // Create a context for encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // Create a key and IV (Not the right way to create keys or ivs)
    unsigned char key[16] = "123456789abcdef"; // 16 B -> 128 bits
    unsigned char iv[16] = "abcdef123456789";// 16 B -> 128 bits
    unsigned char ciphertext[] = "6a9833f75fbc453159abb074ff41cf398b033beb92361ab7fb6bd531707c2e89e0838b7204cbb4662a118bd34b1cf986";

    // Initialize the context with the key and the iv the algorithm and the mode and the operation in this case encryption
    EVP_CipherInit(ctx, EVP_aes_128_cbc(),key,iv,DECRYPT);

    unsigned char plaintext[strlen(ciphertext)/2] ;
    unsigned char cipehertext_binary[strlen(ciphertext)/2];

    // Convert HEX to BINARY for DEC
    for(int i = 0 ; i < strlen(ciphertext)/2 ; i++){
        sscanf(&ciphertext[2*i], "%2hhx", &cipehertext_binary[i]);
    }

    int lenght ; 
    int plaintext_len = 0;

    EVP_CipherUpdate(ctx, plaintext, &lenght, cipehertext_binary, strlen(ciphertext)/2);


    printf("After update : %d\n",lenght);
    plaintext_len += lenght;
    

    //Finalize the encryption (ctx, the buffer where the last bytes will be stored, the lenght of the last bytes)
    EVP_CipherFinal(ctx,plaintext+plaintext_len,&lenght);
    printf("After final : %d\n",lenght);
    plaintext_len += lenght;

    EVP_CIPHER_CTX_free(ctx); // Free the context

    plaintext[plaintext_len] = '\0';
    printf("Plaintext = %s\n",plaintext);
    return 0;

}
