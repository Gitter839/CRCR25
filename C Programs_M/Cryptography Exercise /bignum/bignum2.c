#include <stdio.h>
#include <openssl/bn.h> // Import for BigNum



int main (int arc, char ** argv[]){

    char num_string[] = "1234432489099849382493843287329834";
    char hex_string[] = "3CDCBA7E7D2D460BAD4B7C6E4C2A";

    BIGNUM *bn1 = BN_new(); // Allocato a BigNUM (DEfalut is 0)
    BIGNUM *bn2 = BN_new();

    // Num to BN
    BN_dec2bn(&bn1,num_string);
    BN_print_fp(stdout,bn1);
    printf("\n");

    BN_hex2bn(&bn2,hex_string);
    BN_print_fp(stdout,bn2);
    printf("\n");


    // Comparison 2 BN
    if(BN_cmp(bn1,bn2)==0){
        printf("The Bns are equal..\n");
    }else{
        printf("The number are different...\n");
    }

    printf("bn1 = %s\n",BN_bn2hex(bn1));
    printf("bn1 = %s\n",BN_bn2dec(bn2));


    BN_free(bn1);
    BN_free(bn2);


    return 0;
}