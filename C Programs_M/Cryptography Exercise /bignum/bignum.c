#include <stdio.h>
#include <openssl/bn.h> // Import for BigNum



int main (int arc, char ** argv[]){

    BIGNUM *bn1 = BN_new(); // Allocato a BigNUM (DEfalut is 0)
    BIGNUM *bn2 = BN_new();

    BN_print_fp(stdout,bn1);
    printf("\n");

    BN_set_word(bn1,1230000000000);// Set a value 
    BN_print_fp(stdout,bn1); // Print in HEX
    printf("\n");

    BN_set_word(bn2,9897897);// Set a value 
    BN_print_fp(stdout,bn2); // Print in HEX
    printf("\n");

    // Add BN

    BIGNUM *res = BN_new();
    BN_add(res,bn1,bn2);
    BN_print_fp(stdout,res); // Print in HEX
    printf("\n");


    // Compute the modules, necessitate a ctx
    BN_CTX *ctx = BN_CTX_new();

    BN_mod(res,bn1,bn2,ctx);
    BN_print_fp(stdout,res); // Print in HEX
    printf("\n");

    BN_free(bn1);
    BN_free(bn2);
    BN_free(res);
    BN_CTX_free(ctx);


    return 0;
}