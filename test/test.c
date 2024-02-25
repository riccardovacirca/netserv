#include <stdio.h>
#include <string.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>

char* base64_encode(const unsigned char *input, int length) {
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

int main() {
    // Crea un oggetto JSON per i claims
    json_object *claims = json_object_new_object();
    json_object_object_add(claims, "sub", json_object_new_string("user123"));
    json_object_object_add(claims, "exp", json_object_new_int(time(NULL) + 3600)); // Scadenza del token (1 ora)

    // Converti l'oggetto JSON in una stringa
    const char *claims_str = json_object_to_json_string(claims);

    // Calcola la firma HMAC utilizzando la chiave segreta
    const char *key = "your_secret_key";
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    HMAC(EVP_sha256(), key, strlen(key), (const unsigned char *)claims_str, strlen(claims_str), hmac, &hmac_len);

    // Codifica la firma HMAC in base64
    char *encoded_hmac = base64_encode(hmac, hmac_len);

    // Concatena i segmenti del token JWT
    char *token = malloc(strlen(claims_str) + strlen(encoded_hmac) + 2); // +2 per il '.' e il terminatore null
    sprintf(token, "%s.%s", claims_str, encoded_hmac);

    printf("Token JWT generato: %s\n", token);

    // Libera la memoria
    json_object_put(claims);
    free(token);
    free(encoded_hmac);

    return 0;
}
