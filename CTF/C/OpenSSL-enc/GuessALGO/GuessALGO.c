#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0
#define MAX_BUFFER 1024

/* Helper: processa la cifratura/decifratura con l'algoritmo scelto.
   Ritorna la lunghezza dell'output oppure -1 in caso di errore. */
int process_cipher(const EVP_CIPHER *cipher, int mode,
                   const unsigned char *key, const unsigned char *iv,
                   const unsigned char *input, int input_len,
                   unsigned char *output)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int out_len1 = 0, out_len2 = 0;
    if (!ctx)
        return -1;
    if (!EVP_CipherInit(ctx, cipher,key, iv, mode))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_CipherUpdate(ctx, output, &out_len1, input, input_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (!EVP_CipherFinal_ex(ctx, output + out_len1, &out_len2))
    {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctx);
    return out_len1 + out_len2;
}

void handle_errors()
{
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
    // echo -n 'jyS3NIBqen2CWpDI2jkSu+z93NkDbWkUMitg2Q==' | openssl base64 -d -A | xxd -p -c 500 (Otherwhise the output is truncated)
    // I decode the encrypted message and get the HEX FORM without any additional char (\n)

    unsigned char key[] = "0123456789ABCDEF";
    unsigned char iv[] = "0123456789ABCDEF";
    unsigned char ciphertext_hex[] = "65927e04a24d7695c0da3697f1983922d46895ad7c862f79306f1f03ff513ef8";

    // PAY ATTENTION - KEY IV AND CIPHER_TEXT FROM HEX TO BIN

    // CIPHER TEXT
    int ciphertext_len = strlen(ciphertext_hex) / 2;
    unsigned char ciphertext_binary[ciphertext_len];
    for (int i = 0; i < ciphertext_len; i++)
    {
        sscanf(&ciphertext_hex[2 * i], "%2hhx", &ciphertext_binary[i]);
    }

    /*Now we have all the ingredients, so we can use a brute force attack like this:
    1. I have the cipher_text
    2. Decrypt with Alg_i
    3. I obtain a possibile plain_text
    4. Capture the unique human readble plaintaxt and construct the flag*/

    const char *algos[] = {
        "aes-128-cbc",
        "aes-128-ctr",
        "aes-128-cfb",
        "aes-128-cfb1",
        "aes-128-cfb8",
        "aes-128-ofb",
        "camellia-128-cbc",
        "camellia-128-cfb",
        "camellia-128-ofb",
        "sm4-cbc",
        "seed-cbc",
        "aria-128-cbc",
        NULL};

    /* Buffer per decriptazione/re-cifratura.
       Assumiamo che il plaintext non superi la dimensione del ciphertext. */
    unsigned char decrypted[1024] = {0};
    unsigned char reencrypted[1024] = {0};
    int found = 0;
    char found_algo[64] = {0};

    /* Inizializza OpenSSL */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    
    for (int i = 0; algos[i] != NULL; i++)
    {
        const EVP_CIPHER *cipher = EVP_get_cipherbyname(algos[i]);
        if (!cipher)
            continue; // algoritmo non trovato
        /* Prova a decriptare */
        int decrypted_len = process_cipher(cipher, DECRYPT, key, iv,
                                           ciphertext_binary, ciphertext_len, decrypted);
        if (decrypted_len < 0)
            continue;
        char flag[2048] = {0};
        /* Costruisco la flag come:
           "CRYPTO25{" + decrypted_content + found_algo + "}" */
        decrypted[decrypted_len] = '\0';
        snprintf(flag, sizeof(flag), "CRYPTO25{%sEVP_%s}", decrypted, algos[i]);
        printf("Flag: %s\n", flag);
    }

    

    /* Pulizia */
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
