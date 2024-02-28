#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>

#include "apr.h"
#include "apr_pools.h"
#include "apr_strings.h"
#include "apr_tables.h"

char* ns_jwt_base64_encode(const unsigned char *input, int length)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    return bufferPtr->data;
}

const char* ns_jwt_token_create(apr_pool_t *mp, apr_table_t *clm, const char *key)
{
    char *result = NULL;

    json_object *claims = json_object_new_object();
    json_object_object_add(claims, "sub", json_object_new_string(apr_table_get(clm, "sub")));
    json_object_object_add(claims, "exp", json_object_new_int(atoi(apr_table_get(clm, "exp"))));

    const char *claims_str = json_object_to_json_string(claims);

    // Calcola la firma HMAC utilizzando la chiave segreta
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    HMAC(EVP_sha256(), key, strlen(key), (const unsigned char *)claims_str, strlen(claims_str), hmac, &hmac_len);

    // Codifica la firma HMAC in base64
    char *encoded_hmac = base64_encode(hmac, hmac_len);

    result = apr_psprintf(mp, "%s.%s", claims_str, encoded_hmac);

    // Libera la memoria
    json_object_put(claims);
    free(encoded_hmac);

    return (const char*)result;
}

int main()
{
    apr_status_t rv;
    apr_pool_t *mp;

    rv  = apr_initialize();
    if (rv != APR_SUCCESS) {
        exit(EXIT_FAILURE);
    }

    rv = apr_pool_create(&mp, NULL);
    if (rv != APR_SUCCESS) {
        exit(EXIT_FAILURE);
    }

    apr_table_t *claims = apr_table_make(mp, 0);
    apr_table_add(claims, "sub", "bob");
    int timestamp = time(NULL) + 3600;
    const char *exp = apr_psprintf(mp, "%d", timestamp);
    apr_table_add(claims, "exp", exp);

    const char *token = ns_jwt_token_create(mp, claims, "my_secret_key");
    printf("%s\n", token);

    apr_pool_destroy(mp);
    apr_terminate();

    return 0;
}
