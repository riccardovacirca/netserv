
#include "ns_runtime.h"

#ifndef DEBUG
#define DEBUG 1
#endif

#define true 1
#define false 0

/**
 * @brief Pattern of the response string
 */
#define JSON_RESPONSE "{\"err\":%s,\"log\":%s,\"out\":%s}"

// Controllers

/**
 * @brief Returns an HelloWorld message
 * 
 * @param s Service state
 * @return int HTTP status code
 */
int HelloWorldController(ns_service_t *s) {
  struct state_t {
    int error;
    struct flag_t { int msg; } flag;
  } st = {
    .flag.msg = false, .error = false
  };
  
  do {
    const char ctype[] = "application/json";
    ns_http_response_hd_set(s->response, "Content-Type", ctype);
    const char *msg = ns_json_encode(s->pool, "Hello, World!", NS_JSON_T_STRING);
    st.flag.msg = msg != NULL;
    if ((st.error = !st.flag.msg)) {
      break;
    }
    ns_printf(s, JSON_RESPONSE, "false", "null", msg);
  } while (0);

  if (st.error) {
    const char *er = NULL;
    if (!st.flag.msg) {
      er = ns_json_encode(s->pool, "HelloWorld message error", NS_JSON_T_STRING);
    } else {
      er = ns_json_encode(s->pool, "General error", NS_JSON_T_STRING);
    }
    if (er != NULL) {
      ns_printf(s, JSON_RESPONSE, "true", er, "null");
    } else {
      ns_printf(s, "%s\r\n", "An error occurred.");
    }
  }
  return 200;
}

void ns_handler(ns_service_t *s) {
  ns_route(s, "GET", "/api/hello", HelloWorldController);
}
