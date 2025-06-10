#include <stdio.h>
#include <openssl/rsa.h> // For RSA
#include <openssl/bn.h> // For Big Number 
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h> // Saving data in the file
#include <string.h>

#define MAXBUFFER 1204


// PAY ATTENTION : This exercise uses deprecated functions of OPENSSL 1.1. See the REPO WITH OPENSSL 3.0


void handle_error(){
    ERR_print_errors_fp(stderr);
    abort();
}

// argv[1] is the name of the file to sign
// argv[2] is the name of the file the private key is stored 

int main (int argc , char **argv){


    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    
    if (argc != 3){
        fprintf(stderr,"Invalid parameters\n");
        exit(-1);
    }

    FILE *f_in ; 

    if((f_in=fopen(argv[1],"r"))==NULL){
        printf("Error Opening File...\n");
        exit(-1);
    }

    FILE *f_key ; 

    if((f_key=fopen(argv[2],"r"))==NULL){
        printf("Error Opening File...\n");
        exit(-1);
    }


    // DigestSign --> EVP_PKEY *
    EVP_PKEY *private_key = PEM_read_PrivateKey(f_key,NULL,NULL,NULL); // Load the SK
    fclose(f_key);

    // Compute The DIGEST 
    // Create CTX
    EVP_MD_CTX *signContex = EVP_MD_CTX_new();
    // Init the SIgn
    if(!EVP_DigestSignInit(signContex,NULL,EVP_sha256(),NULL,private_key))
        handle_error();

    unsigned char buffer[MAXBUFFER];
    size_t n_read ; 

    while((n_read = fread(buffer,1,MAXBUFFER,f_in))>0){
        if(!EVP_DigestSignUpdate(signContex,buffer,n_read))
            handle_error();
    }
    fclose(f_in);

    unsigned char signature[EVP_PKEY_size(private_key)] ; // PrivateKEY is not a RSA DataStructure, so we ese EVP_PKEY_size

    size_t sign_len;
    size_t dig_len ; 

    // Final for the digest 
    if(!EVP_DigestSignFinal(signContex,NULL,&dig_len))
        handle_error();

     // Final for the sign 
    if(!EVP_DigestSignFinal(signContex,signature,&sign_len))
        handle_error();



    EVP_MD_CTX_free(signContex);


    FILE *f_out_sign; 

    if((f_out_sign=fopen("signature.bin","w"))==NULL){
        printf("Error Writing File...\n");
        exit(-1);
    }

    if(fwrite(signature,1,sign_len,f_out_sign)<sign_len){
        printf("Error Writing File...\n");
        exit(-1);
    }

    fclose(f_out_sign);
    
    printf("Signature written!\n");


    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();


    return 0 ; 
}
