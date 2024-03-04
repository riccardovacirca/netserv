#include <stdio.h>
#include <stdlib.h>
#include <apr-1.0/apr.h>
#include <apr-1.0/apr_pools.h>
#include <apr-1.0/apr_random.h>
#include <apr-1.0/apr_strings.h>
#include <errno.h>

#include "ns_runtime.h"

int ns_is_int2(const char *s) {
  char *endptr;
  apr_int64_t result = apr_strtoi64(s, &endptr, 10);
  printf("%ld\n", result);
  return errno == 0;
}

int ns_rand2(int min, int max) {
  int result;
  apr_generate_random_bytes((unsigned char*)&result, sizeof(int));
  result *= result < 0 ? -1 : 1;
  return (result % (max - min + 1)) + min;
}

int main() {

  apr_status_t rv;
  rv = apr_initialize();
  if (rv != APR_SUCCESS) {
    exit(EXIT_FAILURE);
  }
  apr_pool_t *mp;
  rv = apr_pool_create(&mp, NULL);
  if (rv != APR_SUCCESS) {
    exit(EXIT_FAILURE);
  }


  // printf("ns_is_int(100): %d\n", ns_is_int("100"));
  // printf("ns_is_int(-100): %d\n", ns_is_int("-100"));
  // printf("ns_is_int(10.0): %d\n", ns_is_int("10.0"));
  // printf("ns_is_int(10.1): %d\n", ns_is_int("10.1"));
  // printf("ns_is_int(10.8): %d\n", ns_is_int("10.8"));
  
  //printf("ns_rand(1, 100): %d\n", ns_rand(1, 100));

  printf("%s\n", ns_trim(mp, " hello "));

  printf("\n");

  apr_pool_destroy(mp);
  apr_terminate();
  return 0;
}
