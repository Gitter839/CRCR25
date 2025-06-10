#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>


#define ENCRYPT 1
#define DECRYPT 0

int main()
{
    

    unsigned char key[] = "0123456789ABCDEF";
    unsigned char iv[]  = "1111111111111111";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx,EVP_aes_128_cbc(), key, iv, ENCRYPT);

    /*    EVP_CIPHER_CTX_set_padding() enables or disables padding. By default encryption operations are padded using standard block padding and the padding is checked and removed when decrypting.
    If the pad parameter is zero then no padding is performed, the total amount of data encrypted or decrypted must then be a multiple of the block size or an error will occur...
    PKCS padding works by adding n padding bytes of value n to make the total length of the encrypted data a multiple of the block size.
    Padding is always added so if the data is already a multiple of the block size n will equal the block size. For example if the block size is 8 and 11 bytes are to be encrypted 
    then 5 padding bytes of value 5 will be added...

    If padding is disabled then the decryption operation will only succeed if the total amount of data decrypted is a multiple of the block size.*/
    EVP_CIPHER_CTX_set_padding(ctx,0);

    unsigned char plaintext[] = "This is the plaintext to encrypt."; //len 33
    unsigned char ciphertext[48];

    int update_len, final_len;
    int ciphertext_len=0;

    EVP_CipherUpdate(ctx,ciphertext,&update_len,plaintext,strlen(plaintext));
    ciphertext_len+=update_len;
    printf("update size: %d\n",ciphertext_len);

    EVP_CipherFinal_ex(ctx,ciphertext+ciphertext_len,&final_len);
    ciphertext_len+=final_len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext lenght = %d\n", ciphertext_len);
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    return 0;
}
