#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/bn.h>


/*
Detailed Explanation:

We received two colon-separated hex strings. The first, being much longer, is interpreted as the RSA modulus n (n = p * q), and the second, being shorter, is assumed to be the smaller prime factor p (since p < q by convention of RSA).

Using OpenSSL BIGNUM functions, we remove the colons and convert the strings to BIGNUMs. Then we compute the missing factor q by dividing n by p (q = n / p). Finally, we convert q back to a colon-separated hex string (adding leading zeros if necessary)
*/


/* Rimuove i due punti dalla stringa es. "00:ab:cd:..." → "00abcd..." */
char *remove_colons(const char *str) {
    size_t len = strlen(str);
    char *res = malloc(len + 1);
    if (!res) exit(1);
    int j = 0;
    for (size_t i = 0; i < len; i++) {
        if (str[i] != ':')
            res[j++] = str[i];
    }
    res[j] = '\0';
    return res;
}

/* Inserisce un ':' ogni 2 caratteri in una stringa hex. */
char *insert_colons(const char *hex) {
    size_t len = strlen(hex);
    size_t out_len = len + (len/2 - 1) + 1; // aggiunge i due punti e il terminatore
    char *res = malloc(out_len);
    if (!res) exit(1);
    int j = 0;
    for (size_t i = 0; i < len; i++) {
        res[j++] = hex[i];
        if ((i % 2 == 1) && (i < len - 1))
            res[j++] = ':';
    }
    res[j] = '\0';
    return res;
}

void to_lowercase(char *str) {
    for (; *str; str++) {
        *str = tolower(*str);
    }
}

int main(void) {
    /* I dati forniti (in formato colon separated hex) */
    const char *n_colon = "00:9e:ee:82:dc:2c:d4:a0:0c:4f:5a:7b:86:63:b0:c1:ed:06:77:fc:eb:de:1a:23:5d:f4:c3:ff:87:6a:7d:ad:c6:07:fa:a8:35:f6:ae:05:03:57:3e:22:36:76:d5:0d:57:4f:99:f9:58:ad:63:7a:e7:45:a6:aa:fa:02:34:23:b6:9d:34:15:7b:11:41:b6:b1:ca:b9:1a:cd:29:55:bd:42:f5:04:ab:df:45:4a:9d:4e:ca:4e:01:f9:f8:74:59:67:ee:b6:a9:fb:96:b7:c0:94:00:17:8a:53:0e:b6:d8:31:c9:68:e6:64:38:d3:63:3a:04:d7:88:6b:f0:e1:ad:60:7f:41:bd:85:7b:d9:04:e1:97:5b:1f:9b:05:ce:ac:2c:c4:55:3f:b4:8b:89:4d:0a:50:9a:09:4e:5e:8f:5b:5f:55:69:72:5f:04:9b:3a:8a:09:b4:7f:8d:b2:ca:52:0e:5e:bf:f4:b0:ee:c9:ba:dc:93:4f:6d:d3:1f:82:1a:d9:fc:2c:a7:3f:18:23:0d:d7:44:c7:28:54:67:84:ee:73:92:65:f0:1c:e8:1e:6d:4d:95:65:b4:c8:4f:b8:04:62:58:2b:ee:32:64:a0:a7:dc:99:25:0e:50:53:76:bc:30:db:71:5e:93:d6:9f:1f:88:1c:76:5d:82:c8:59:39:51";
    const char *p_colon = "00:d2:c6:01:32:6b:4c:4b:85:5f:52:7b:b7:8e:d6:8a:e4:c8:76:7e:6b:c9:24:9a:3e:ca:cd:2f:c9:b8:75:d4:f9:71:11:e1:cf:be:62:d3:2c:5f:f9:fd:9b:fa:ed:62:f3:df:44:c7:57:fb:ee:9b:b2:32:cb:54:49:29:6c:69:2e:30:1d:8c:1f:fa:b1:8e:e4:49:66:c1:fb:92:7c:82:ca:60:c9:40:a4:0a:b2:db:50:ec:f6:ff:98:a7:16:23:38:8d:06:d2:7c:a9:85:8a:c2:2b:4d:d4:e6:f1:89:e5:b0:42:54:a0:5f:3c:dd:c7:64:33:05:11:fb:ee:8b:26:07";

    /* Rimuovi i due punti */
    char *n_hex = remove_colons(n_colon);
    char *p_hex = remove_colons(p_colon);

    /* Converti le stringhe esadecimali in BIGNUM */
    BIGNUM *n = NULL, *p = NULL, *q = BN_new();
    BN_hex2bn(&n, n_hex);
    BN_hex2bn(&p, p_hex);

    /* Crea un contesto BN */
    BN_CTX *ctx = BN_CTX_new();

    /* Calcola q = n / p (ignora il resto) */
    if(!BN_div(q, NULL, n, p, ctx)) {
        fprintf(stderr, "BN_div fallita\n");
        exit(1);
    }

    /* Converti q in una stringa hex (in uppercase) */
    char *q_hex = BN_bn2hex(q);
    /* Convertila in lowercase */
    to_lowercase(q_hex);

    /* Equalizza la lunghezza: p_hex ha una lunghezza (numero di cifre) che dovrebbe corrispondere al numero di byte * 2.
       Se q_hex è più corta, aggiungi zeri a sinistra. */
    size_t p_len = strlen(p_hex);  // lunghezza di p_hex (es. 258 cifre se p è 129 byte)
    size_t q_len = strlen(q_hex);
    if(q_len < p_len) {
        size_t diff = p_len - q_len;
        char *new_q_hex = malloc(p_len + 1);
        memset(new_q_hex, '0', diff);
        strcpy(new_q_hex + diff, q_hex);
        new_q_hex[p_len] = '\0';
        OPENSSL_free(q_hex);
        q_hex = new_q_hex;
    }

    /* Inserisci i due punti ogni 2 cifre */
    char *q_colon = insert_colons(q_hex);

    /* Costruisci la flag nel formato richiesto */
    char flag[4096];
    snprintf(flag, sizeof(flag), "CRYPTO25{%s}", q_colon);
    printf("Flag: %s\n", flag);

    /* Libera le risorse */
    BN_free(n);
    BN_free(p);
    BN_free(q);
    BN_CTX_free(ctx);
    free(n_hex);
    free(p_hex);
    OPENSSL_free(q_hex);
    free(q_colon);
    return 0;
}
