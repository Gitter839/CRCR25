#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>


#define ENCRYPT 1
#define DECRYPT 0
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv)
{

//  int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, const unsigned char *key, const unsigned char *iv, int enc);
//  int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
//  int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

// The chiper_text is the following in base-64 : 
// jyS3NIBqenyCWpDI2jkSu+z93NkDbWkUMitg2Q==
// With this command: 
//echo -n 'jyS3NIBqen2CWpDI2jkSu+z93NkDbWkUMitg2Q==' | openssl base64 -d -A | xxd -p
// I decode the encrypted message and get the HEX FORM without any additional char (\n)



    unsigned char key[] = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    unsigned char iv[]  = "11111111111111112222222222222222";
    unsigned char ciphertext_hex[] = "8f24b734806a7a7d825a90c8da3912bbecfddcd9036d6914322b60d9";

    //PAY ATTENTION - KEY IV AND CIPHER_TEXT FROM HEX TO BIN 


    // CIPHER TEXT
    int ciphertext_len = strlen(ciphertext_hex)/2;
    unsigned char ciphertext_binary[ciphertext_len];
    for(int i = 0; i < ciphertext_len;i++){
        sscanf(&ciphertext_hex[2*i],"%2hhx", &ciphertext_binary[i]);
    }

    // KEY
    int key_len = strlen(key)/2;
    unsigned char key_binary[key_len];
    for(int i = 0; i < key_len;i++){
        sscanf(&key[2*i],"%2hhx", &key_binary[i]);
    }

    // IV
    int iv_len = strlen(iv)/2;
    unsigned char iv_binary[iv_len];
    for(int i = 0; i < iv_len;i++){
        sscanf(&iv[2*i],"%2hhx", &iv_binary[i]);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx,EVP_chacha20(), key_binary, iv_binary, DECRYPT);


    unsigned char decrypted[ciphertext_len+1]; //may be larger than needed due to padding

    int update_len, final_len;
    int decrypted_len=0;
    EVP_CipherUpdate(ctx,decrypted,&update_len,ciphertext_binary,ciphertext_len);
    decrypted_len+=update_len;
    printf("update size: %d\n",decrypted_len);

    EVP_CipherFinal_ex(ctx,decrypted+decrypted_len,&final_len);
    decrypted_len+=final_len;

    EVP_CIPHER_CTX_free(ctx);

    decrypted[decrypted_len] = '\0';
    printf("Decrypted plaintext=%s", decrypted);
   


    return 0;
}

