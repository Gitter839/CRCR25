#include <stdio.h>
#include <openssl/rsa.h> // For RSA
#include <openssl/bn.h> // For Big Number 
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h> // Saving data in the file
#include <string.h>


// PAY ATTENTION : This exercise uses deprecated functions of OPENSSL 1.1. See the REPO WITH OPENSSL 3.0


void handle_error(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main (int argc , char **argv){


    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Generate RSA Keys

    RSA *rsa_keypair;
    BIGNUM *bne = BN_new();
    if(!BN_set_word(bne, RSA_F4))
        handle_error();


    rsa_keypair = RSA_new(); // Initizialaize 
    // The third parameter is the public parameter for generate the keys
    if(!RSA_generate_key_ex(rsa_keypair,2048,bne,NULL))
        handle_error();
    
    // Save the keys on a FILE 

    FILE *rsa_file ; 
    if((rsa_file = fopen("private.pem","w")) == NULL){
        fprintf(stderr,"Problems creating the file\n");
        abort();
    }

    // Write the SK on FILE (The other parameter are used to encrypt the key before saving on a file)
    if(!PEM_write_RSAPrivateKey(rsa_file,rsa_keypair,NULL,NULL,0,NULL,NULL))
        handle_error();

    fclose(rsa_file);



    // PUBLIC KEY
    if((rsa_file = fopen("public.pem","w")) == NULL){
        fprintf(stderr,"Problems creating the file\n");
        abort();
    }

    if(!PEM_write_RSAPublicKey(rsa_file,rsa_keypair))
        handle_error();



    


    //-----------------------------------------------------------------------------------------------------------------------------------
        // Noww, after the generation the keys, lets try to encrypt /sign something

    unsigned char msg[] = "This is the message to encrypt\n";
    unsigned char encrypted_message[RSA_size(rsa_keypair)]; // The enryptes messagge has the length of the keys

    int encrypted_len ;
    encrypted_len = RSA_public_encrypt(strlen(msg)+1,msg,encrypted_message,rsa_keypair,RSA_PKCS1_OAEP_PADDING); //+1 because we want to encrype also the newline

    if (encrypted_len == -1)
        handle_error();

    FILE *out;

    if((out = fopen("encrypted.enc","w")) == NULL){
        fprintf(stderr,"Problems creating the file\n");
        abort();
    }

    if(fwrite(encrypted_message,1,encrypted_len,out) < encrypted_len){
        fprintf(stderr,"Problems writing the file\n");
        abort();
    }

    fclose(out);
    printf("File Saved\n");


    //-----------------------------------------------------------------------------------------------------
    // Decrypt

    // We reuse the  var enryoted_message


    printf("Im reading the encrypted file\n");
    FILE *in;

    if((in = fopen("encrypted.enc","r")) == NULL){
        fprintf(stderr,"Problems reading the file\n");
        abort();
    }
    if((encrypted_len = fread(encrypted_message,1,RSA_size(rsa_keypair),in)) != RSA_size(rsa_keypair))
        handle_error();

    fclose(in);
    unsigned char decrypted_message[RSA_size(rsa_keypair)] ; 

    if(RSA_private_decrypt(encrypted_len,encrypted_message,decrypted_message,rsa_keypair,RSA_PKCS1_OAEP_PADDING)==-1)
        handle_error();


    printf("DEcrypted Messagge = %s\n",decrypted_message);


    RSA_free(rsa_keypair);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();


    return 0 ; 
}
