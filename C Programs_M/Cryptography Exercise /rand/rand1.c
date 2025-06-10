#include   <stdio.h>
// Fundamental Library For Cryptography (Random Number Generation)
#include   <openssl/rand.h>
#include   <openssl/err.h> // Predefined Error Messages -- Very Helpful

#define MAX 128



void handle_error(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    
    // Generate 128 random bytes
    unsigned char random_string[MAX];

    // A way to initializate the random number generator 
    // with a seed (dev/random)
    // This can fail for example if the file does not exist or the device is 
    // not available
    //RAND_load_file("/dev/random", 64); // Read 64 bytes from /dev/random

    if(RAND_load_file("/dev/random", 64)!=64){
        handle_error();
        //ERR_print_errors_fp(stderr);
        //fprintf(stderr,"Error loading random seed\n");
        //return -1;
    }


    if(RAND_bytes(random_string,MAX)!=1){
        handle_error();
        //fprintf(stderr,"Error generating random bytes\n");
        //return -1;
    }   

    printf("Random String: ");
    for (int i = 0; i < MAX; i++){
        // Print in Hexadecimal Format 
        printf("%02x-", random_string[i]);
    }
    printf("\n");

    return 0;
}