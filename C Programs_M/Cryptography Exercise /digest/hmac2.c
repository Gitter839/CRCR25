#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <openssl/hmac.h>

#define MAX_BUF 1024

/*Program that implement the computation of (digest, keyed_digest(HMAC)) for a given message and handling errors. INPUT FROM A FILE*/

void error_handle(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main (int argc , char ** argv){


    ERR_load_crypto_strings(); // Load Error Message 
    OpenSSL_add_all_algorithms();

    if (argc != 2){
        fprintf(stderr,"Invalid parameters\n");
        exit(-1);
    }

    FILE *f_in ; 

    if((f_in=fopen(argv[1],"r"))==NULL){
        printf("Error Opening File...\n");
        exit(-1);
    }

    //Create the context and initiate with the use of HMAC
    

    unsigned char key[] = "1234567887654321" ; // ASCII 16 Char
    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC,NULL,key,strlen(key));
    EVP_MD_CTX *ctx ; 

    ctx = EVP_MD_CTX_new();

    if (ctx==NULL){
        error_handle();
    }

    // DigestSignInit (The second parameter is used to compute Digital Signature)
    if(EVP_DigestSignInit(ctx, NULL, EVP_sha1(),NULL,hmac_key)!=1){
        error_handle();
    }

    //Read the file
    int n_read ; 
    unsigned char buffer[MAX_BUF];
    while((n_read = fread(buffer,1,MAX_BUF,f_in))>0){
        if(EVP_DigestSignUpdate(ctx,buffer,n_read)!=1)
            error_handle(); // Computation of the digest
    }



    // HMAC_size requires the context
    unsigned char digest[EVP_MD_size(EVP_sha1())] ; // sha1 160 bit -> 20 B

    size_t md_len ; // Data gnerated for the digest, it is used to perform controls PAY ATTENTTION : size_t not int with int ERROR

    if(EVP_DigestSignFinal(ctx,digest,&md_len)!=1)
        error_handle();

    EVP_MD_CTX_free(ctx); // Free the context


    printf("Keyed Digest HMAC-SHA1 = "); 
    for (int i = 0 ; i < md_len ; i++){
        printf("%02x",digest[i]);
    }
    printf("\n");

    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();


    return 0 ; 
}