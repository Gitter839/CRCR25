#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h> // For Digest Comparison 
#include <openssl/err.h>
#include <string.h>

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

    //Create the context and initiate with the use of SHA1(Very weak)
    
    EVP_MD_CTX *ctx ; 

    ctx = EVP_MD_CTX_new();

    if (ctx==NULL){
        error_handle();
    }

    if(EVP_DigestInit(ctx, EVP_sha1())!=1){
        error_handle();
    }



    //Read the file
    int n_read ; 
    unsigned char buffer[MAX_BUF];
    while((n_read = fread(buffer,1,MAX_BUF,f_in))>0){
        if(EVP_DigestUpdate(ctx,buffer,n_read)!=1)
            error_handle(); // Computation of the digest
    }



    unsigned char digest[EVP_MD_size(EVP_sha1())] ; // sha1 160 bit -> 20 B

    int md_len = 0; // Data gnerated for the digest, it is used to perform controls 

    if(EVP_DigestFinal(ctx,digest,&md_len)!=1)
        error_handle();

    EVP_MD_CTX_free(ctx); // Free the context


    printf("Digest = "); 
    for (int i = 0 ; i < md_len ; i++){
        printf("%02x",digest[i]);
    }
    printf("\n");

    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();


    return 0 ; 
}