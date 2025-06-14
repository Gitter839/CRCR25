#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}


int main(int argc, char **argv){
       
       
        unsigned char key[] = "keykeykeykeykeykey";
        if(argc != 3){
            fprintf(stderr,"Invalid parameters. Usage: %s filename\n",argv[0]);
            exit(1);
        }


        FILE *f_in1;
        if((f_in1 = fopen(argv[1],"r")) == NULL) {
                fprintf(stderr,"Couldn't open the input file1, try again\n");
                exit(1);
        }
        FILE *f_in2;
        if((f_in2 = fopen(argv[2],"r")) == NULL) {
                fprintf(stderr,"Couldn't open the input file2, try again\n");
                exit(1);
        }



       //EVP_MD_CTX *EVP_MD_CTX_new(void);
       //pedantic mode? Check if md == NULL
		EVP_MD_CTX  *hmac_ctx = EVP_MD_CTX_new();

        //int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
        // int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
        // Returns 1 for success and 0 for failure.
        EVP_PKEY *hkey;
        hkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, 18); // 18 is the key length
 
        if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hkey))
            handle_errors();

        size_t n;
        unsigned char buffer[MAXBUF];

        //File1
        while((n = fread(buffer,1,MAXBUF,f_in1)) > 0){
        // Returns 1 for success and 0 for failure.
            if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n))
                handle_errors();
        }

        //File2
        while((n = fread(buffer,1,MAXBUF,f_in2)) > 0){
            // Returns 1 for success and 0 for failure.
                if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n))
                    handle_errors();
            }


        unsigned char hmac_value[EVP_MD_size(EVP_sha256())];
        size_t hmac_len = EVP_MD_size(EVP_sha256());

        //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned size_t *s);
        // EVP_DigestSignFinal(hmac_ctx, NULL, &hmac_len);
        if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
            handle_errors();

        // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
		EVP_MD_CTX_free(hmac_ctx);

        printf("The HMAC is: ");
        for(int i = 0; i < hmac_len; i++)
			     printf("%02x", hmac_value[i]);
        printf("\n");


	return 0;

}