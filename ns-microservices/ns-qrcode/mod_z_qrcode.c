
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "qrencode.h"
#include "zet.h"

module AP_MODULE_DECLARE_DATA z_qrcode_module;

const char* z_qr_map(apr_pool_t *m, QRcode *qr) {
  int width, len;
  char *bin, *p;
  unsigned char *data, value;
  if (qr == NULL) {
    return NULL;
  }
  width = qr->width;
  data = qr->data;
  len = width * width;
  bin = (char*)apr_palloc(m, len + (width-1) + 1);
  if (bin == NULL) {
    return NULL;
  }
  memset(bin, 0, len + 1);
  p = bin;
  for (int i = 0; i < width; i++) {
    for (int j = 0; j < width; j++) {
      value = data[i * width + j];
      *p++ = (value & 1) ? '1' : '0';
    }
    if (i < (width-1))
      *p++ = '-';
  }
  return bin;
}

static int z_qrcode_request_handler(request_rec *r) {
  QRcode *qr;
  const char *buf, *bin, q[] = "HELLO";
  if (strcmp(r->handler, "qr")) return DECLINED;
  Z_APACHE_INITIALIZE(r);
  Z_APACHE_AUTHORIZE(r, &z_qrcode_module);
  qr = QRcode_encodeString(q, 0, QR_ECLEVEL_L, QR_MODE_8, 1);
  bin = z_qr_map(r->pool, qr);
  buf = apr_psprintf(r->pool, "{\"code\":\"%s\",\"width\":%d}", bin, qr->width);
  Z_APACHE_RESPONSE_JSON(r, 0, NULL, buf, Z_T_JSON);
  return OK;
}

static void z_qrcode_register_hooks(apr_pool_t *mp) {
  ap_hook_handler(z_qrcode_request_handler, NULL, NULL, APR_HOOK_LAST);
}

static void* z_qrcode_serv_config_make(apr_pool_t *m, server_rec *s) {
  return (void*)apr_table_make(m, 1);
}

static const char* z_qrcode_param_set(cmd_parms *p, void *c, const char *v) {
  void *cfg = ap_get_module_config(p->server->module_config, &z_qrcode_module);
  apr_table_setn((apr_table_t*)cfg, p->cmd->name, v);
  return NULL;
}

static const command_rec z_qrcode_directives[] = {
  AP_INIT_TAKE1("ZAuthType", z_qrcode_param_set, NULL, OR_OPTIONS, ""),
  AP_INIT_TAKE1("ZAuthFile", z_qrcode_param_set, NULL, OR_OPTIONS, ""),
  {NULL}
};

module AP_MODULE_DECLARE_DATA z_qrcode_module = {
  STANDARD20_MODULE_STUFF,
  NULL,
  NULL,
  z_qrcode_serv_config_make,
  NULL,
  z_qrcode_directives,
  z_qrcode_register_hooks
};
