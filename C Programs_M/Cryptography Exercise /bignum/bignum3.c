#include <stdio.h>
#include <openssl/bn.h> // Import for BigNum
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


void error_handle(){
    ERR_print_errors_fp(stderr);
    abort();
}



int main (int arc, char ** argv[]){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();


    char num_string[] = "1234432489099849382493843287329834";
    char hex_string[] = "3CDCBA7E7D2D460BAD4B7C6E4C2A";

    BIGNUM *prime1 = BN_new(); // Allocato a BigNUM (DEfalut is 0)
    BIGNUM *prime2 = BN_new();

    //                                        LEN                                                      Callback (System that intercat with the prime number
    // generation, which connects the output with the process generation. Important because is usefule to generate prime numbers for crypto pourpose)
    // int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe, const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb)
    // A prime is Safe if : (p-1)/2 is also prime
    // add, rem --> p -> p % add == rem
    // if rem is null -> rem =1
    // if rem is NULL and safe is true --> rem = 3 add must be multiple of 4
    if(!BN_generate_prime_ex(prime1,1024,0,NULL,NULL,NULL))
        error_handle();

    BN_print_fp(stdout,prime1);
    puts("");


    // Check If a number is prime , to perferom a better check must provide others parameters (N_Checks)
    // BN_is_prime_ex IS DEPRECATED NOW USE BN_check_prime
    if(BN_check_prime(prime1,NULL,NULL)){
        printf("Its a prime\n");
    }else{
        printf("Not a prime\n");
    }
    //BN_check_prime(prime,ctx,cb) More simple, not N_Checks parameter 


    BN_set_word(prime2,16); // Set a non prime number
    if(BN_check_prime(prime2,NULL,NULL)){
        printf("Its a prime\n");
    }else{
        printf("Not a prime\n");
    }

    printf("N bits (1) :%d\n",BN_num_bytes(prime1)); // To check the number of bits of a BN
    printf("N bits (2) :%d\n",BN_num_bytes(prime2)); // To check the number of bits of a BN



    BN_free(prime1);
    BN_free(prime2);


    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();


    return 0;
}