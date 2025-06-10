#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>  // for OPENSSL_str2hexnum or alternative
// If your OpenSSL doesn't have OPENSSL_str2hexnum, just use strtol.

int main(void) {
    // The two input strings
    const char *rand1_str = "ed-8a-3b-e8-17-68-38-78-f6-b1-77-3e-73-b3-f7-97-f3-00-47-76-54-ee-8d-51-0a-2f-10-79-17-f8-ea-d8-81-83-6e-0f-0c-b8-49-5a-77-ef-2d-62-b6-5e-e2-10-69-d6-cc-d6-a0-77-a2-0a-d3-f7-9f-a7-9e-a7-c9-08";
    const char *rand2_str = "4c-75-82-ca-02-07-bd-1d-8d-52-f0-6c-7a-d6-b7-87-83-95-06-2f-e0-f7-d4-24-f8-03-68-97-41-4c-85-29-e5-0d-b0-e4-3c-ee-74-dc-18-8a-aa-26-f0-46-94-e8-52-91-4a-43-8f-dd-ea-bb-a8-cf-51-14-79-ec-17-c2";

    // Copy the strings so we can strtok them (they're literals).
    char *r1_copy = strdup(rand1_str);
    char *r2_copy = strdup(rand2_str);

    if (!r1_copy || !r2_copy) {
        fprintf(stderr, "Memory allocation error.\n");
        return 1;
    }

    // We'll split each string by '-' to get the hex bytes.
    // Let's count how many bytes there are. The number is the count of '-' + 1.
    // Or we can do it on the fly.
    int count1 = 0;
    for (int i = 0; rand1_str[i]; i++) {
        if (rand1_str[i] == '-') count1++;
    }
    count1++; // number of bytes in rand1
    
    int count2 = 0;
    for (int i = 0; rand2_str[i]; i++) {
        if (rand2_str[i] == '-') count2++;
    }
    count2++; // number of bytes in rand2

    if (count1 != count2) {
        fprintf(stderr, "Mismatch in number of bytes!\n");
        free(r1_copy);
        free(r2_copy);
        return 1;
    }
    int num_bytes = count1; // same as count2

    unsigned char *rand1_bytes = malloc(num_bytes);
    unsigned char *rand2_bytes = malloc(num_bytes);

    if (!rand1_bytes || !rand2_bytes) {
        fprintf(stderr, "Memory allocation error.\n");
        free(r1_copy);
        free(r2_copy);
        return 1;
    }

    // Parse the dash-delimited hex from rand1
    {
        int idx = 0;
        char *token = strtok(r1_copy, "-");
        while (token && idx < num_bytes) {
            // We can use strtol or an OpenSSL function. Example with strtol:
            unsigned long val = strtoul(token, NULL, 16);
            // or: unsigned long val = OPENSSL_str2hexnum(token);
            rand1_bytes[idx++] = (unsigned char) val;
            token = strtok(NULL, "-");
        }
    }

    // Parse the dash-delimited hex from rand2
    {
        int idx = 0;
        char *token = strtok(r2_copy, "-");
        while (token && idx < num_bytes) {
            unsigned long val = strtoul(token, NULL, 16);
            rand2_bytes[idx++] = (unsigned char) val;
            token = strtok(NULL, "-");
        }
    }

    // Now compute k1 = rand1 OR rand2, k2 = rand1 AND rand2, key = k1 XOR k2
    unsigned char *k1 = malloc(num_bytes);
    unsigned char *k2 = malloc(num_bytes);
    unsigned char *key = malloc(num_bytes);

    if (!k1 || !k2 || !key) {
        fprintf(stderr, "Memory allocation error.\n");
        free(r1_copy);
        free(r2_copy);
        free(rand1_bytes);
        free(rand2_bytes);
        return 1;
    }

    for (int i = 0; i < num_bytes; i++) {
        k1[i] = rand1_bytes[i] | rand2_bytes[i];
        k2[i] = rand1_bytes[i] & rand2_bytes[i];
        key[i] = k1[i] ^ k2[i];
    }

    // Print the result in dash-separated hex, wrapped in CRYPTO25{...}
    printf("CRYPTO25{");
    for (int i = 0; i < num_bytes; i++) {
        if (i > 0) {
            printf("-");
        }
        printf("%02x", key[i]);
    }
    printf("}\n");

    // Cleanup
    free(r1_copy);
    free(r2_copy);
    free(rand1_bytes);
    free(rand2_bytes);
    free(k1);
    free(k2);
    free(key);

    return 0;
}
