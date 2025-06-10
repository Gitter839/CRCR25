#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h> // For Digest Comparison 
#include <openssl/evperr.h>
#include <string.h>


/*Program that implement the computation of (digest, keyed_digest(HMAC)) for a given message and handling errors*/

int main (int argc , char ** argv){

    char message[] = "This is the message to hash!!" ; //

    //Create the context and initiate with the use of SHA1(Very weak)
    
    EVP_MD_CTX *ctx ; 

    ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha1()); 

    // Perform the computatation
    EVP_DigestUpdate(ctx,message,strlen(message));

    unsigned char digest[20] ; // sha1 160 bit -> 20 B

    int md_len = 0; // Data gnerated for the digest, it is used to perform controls 

    EVP_DigestFinal(ctx,digest,&md_len);

    EVP_MD_CTX_free(ctx); // Free the context


    printf("Digest = "); 
    for (int i = 0 ; i < md_len ; i++){
        printf("%02x",digest[i]);
    }
    printf("\n");




    return 0 ; 
}