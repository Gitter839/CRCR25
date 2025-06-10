#include   <stdio.h>
#include   <string.h>
// To create a context for encryption
#include   <openssl/evp.h>
#include   <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

void error_handle(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{

    ERR_load_crypto_strings();// Load the error messagge for crypto
    OpenSSL_add_all_algorithms();


    // Create a context for encryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // Create a key and IV (Not the right way to create keys or ivs)
    unsigned char key[16] = "123456789abcdef"; // 16 B -> 128 bits
    unsigned char iv[16] = "abcdef123456789";// 16 B -> 128 bits

    // Initialize the context with the key and the iv the algorithm and the mode and the operation in this case encryption
    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(),key,iv,ENCRYPT))
        error_handle();

    unsigned char plaintext[] = "This variable contains the data to encrypt"; 
    unsigned char ciphertext[48]; // 48 B -> 3 blocks of 16 B Remembere the use of CBC

    int lenght ; 
    int ciphertext_lenght = 0;
    // The parameters are : the context, the output buffer, the length of the output buffer, the input buffer, the length of the input buffer
    // buffer , lenght is the number of bytes stored in the buffer (in this case the bythe encrypted)
    if(!EVP_CipherUpdate(ctx, ciphertext,&lenght, plaintext, strlen(plaintext)))
        error_handle();


    printf("After update : %d\n",lenght);
    ciphertext_lenght += lenght;
    

    //Finalize the encryption (ctx, the buffer where the last bytes will be stored, the lenght of the last bytes)
    if(!EVP_CipherFinal(ctx,ciphertext+ciphertext_lenght,&lenght))
        error_handle();
        
    printf("After final : %d\n",lenght);
    ciphertext_lenght += lenght;

    EVP_CIPHER_CTX_free(ctx); // Free the context

    printf("Size of the ciphertext : %d\n",ciphertext_lenght);

    for (int i = 0 ; i < ciphertext_lenght ; i++){
        printf("%02x",ciphertext[i]);
    }
    printf("\n");


    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return 0;

}
