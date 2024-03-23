#include "libnetsrv.h"
int HelloWorldController(ns_service_t *s) {
  ns_http_response_hd_set(s->response, "Content-Type", "application/json");
  const char *msg = ns_json_encode(s->pool, "Hello, World!", NS_JSON_T_STRING);
  ns_printf(s, "{\"err\":%s,\"log\":%s,\"out\":%s}", "false", "null", msg);
  return 200;
}
void ns_handler(ns_service_t *s) {
  ns_route(s, "GET", "/api/hello", HelloWorldController);
}