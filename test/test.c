#include <stdio.h>
#include <stdlib.h>
#include <apr-1.0/apr.h>
#include <apr-1.0/apr_pools.h>
#include <apr-1.0/apr_random.h>
#include <apr-1.0/apr_strings.h>
#include <errno.h>


int ns_is_int(const char *str, char **endptr, int base) {
  apr_int64_t result = apr_strtoi64(str, endptr, base);
  return errno == 0;
}

int random_in_range(int min, int max) {
    int result;
    apr_size_t int_size = sizeof(int);
    apr_generate_random_bytes((unsigned char*)&result, int_size);
    int range = max - min + 1;
    return (result % range) + min;
}

int main() {
    int min = 1;
    int max = 100;
    int random_number = random_in_range(min, max);

    printf("Numero casuale nell'intervallo [%d, %d]: %d\n", min, max, random_number);

    return 0;
}