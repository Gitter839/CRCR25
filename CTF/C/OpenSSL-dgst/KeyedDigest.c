#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#define MAXBUF 1024

// Starting FROM hash3.c

int main(int argc, char **argv){
       
      
        if(argc != 2){
            fprintf(stderr,"Invalid parameters. Usage: %s filename\n",argv[0]);
            exit(1);
        }


        FILE *f_in;
        if((f_in = fopen(argv[1],"r")) == NULL) {
                fprintf(stderr,"Couldn't open the input file, try again\n");
                exit(1);
        }

        // Determina la dimensione del file
        fseek(f_in, 0, SEEK_END);
        long file_size = ftell(f_in);
        fseek(f_in, 0, SEEK_SET);


        unsigned char *file_buffer = malloc(file_size);
        unsigned char secret[] = "this_is_my_secret";

        if(file_buffer == NULL){
            fprintf(stderr,"Allocation Buffer Error\n");
            abort();
        }

        if (fread(file_buffer, 1, file_size, f_in) != (size_t)file_size) {
            fprintf(stderr, "Errore nella lettura del file\n");
            free(file_buffer);
            fclose(f_in);
            return 1;
        }
        fclose(f_in);

        // Now in file_buffer we have the entire text of the file

        size_t total_len = file_size + strlen(secret)*2;
        unsigned char *conc = malloc(total_len);

        if(conc == NULL){
            fprintf(stderr,"Allocation Buffer Error\n");
            abort();
        }

        // For the concatenation we need memcpy, because we must copy all the bits 
        memcpy(conc, secret, strlen(secret));
        memcpy(conc + strlen(secret), file_buffer, file_size);
        memcpy(conc + strlen(secret) + file_size, secret, strlen(secret));


        //EVP_MD_CTX *EVP_MD_CTX_new(void);
		EVP_MD_CTX *md = EVP_MD_CTX_new();

        //int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);
        // int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
        EVP_DigestInit(md, EVP_sha512());

        EVP_DigestUpdate(md,conc,total_len);
  

        unsigned char kd[EVP_MD_size(EVP_sha512())];
        int kd_len;

        //int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
        EVP_DigestFinal_ex(md, kd, &kd_len);

        // void EVP_MD_CTX_free(EVP_MD_CTX *ctx);
		EVP_MD_CTX_free(md);

        printf("The digest is: ");
        for(int i = 0; i < kd_len; i++)
			     printf("%02x", kd[i]); // Print IN HEX
        printf("\n");

	return 0;

}