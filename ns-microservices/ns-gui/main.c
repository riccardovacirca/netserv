
#include "mt.h"

void mt_service_monitor(apr_pool_t *mp, mt_dbd_t *dbd, const char **data, size_t *sz)
{
  (*data) = apr_pstrdup(mp, "Hello, World!");
  (*sz) = strlen(*data);
}

void mt_service_api_async(apr_pool_t *mp, mt_http_request_t *req, mt_dbd_t *dbd)
{
  printf("Async Hello, World!\n");
}

void mt_service_api(apr_pool_t *mp, mt_http_request_t *req, mt_http_response_t *res, mt_dbd_t *dbd)
{
  const char *buff = NULL;
  if (mt_http_request_uri_match(req, "/api/hello"))
  {
    buff = mt_json_pstr(mp, "Hola, mundo!");
  } else {
    buff = apr_psprintf(mp, "%s", mt_json_pstr(mp, "Hola, mundo!"));
  }
  mt_http_response_buffer_set(mp, res, (void*)buff, strlen(buff));
  mt_http_response_content_type_set(mp, res, "application/json");
  mt_http_response_status_set(res, MT_HTTP_OK);
}

int main(int argc, char *argv[])
{
  if (argc < 2) return -1;
  mt_http_serve(argv[1], 1000, 2000, MT_ENV_NS);
  return 0;
}
