#include <cbor.h>

#include <sys/stat.h>
#include <sys/file.h>

#include <apr-1.0/apr_file_info.h>
#include <apr-1.0/apr_file_io.h>
#include <apr-1.0/apr_md5.h>
#include <apr-1.0/apr_base64.h>
#include <apr-1.0/apr_dbd.h>
#include <apr-1.0/apr_escape.h>

#include <openssl/engine.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <json-c/json.h>

#include "mongoose.h"
#include "mt.h"

#ifndef DEBUG
#define MT_DEBUG              0
#else
#define MT_DEBUG              1
#endif

#define MT_TYPE_TABLE         0x001

#define MT_HTTP_SUCCESS       "HTTP/1.1 200 OK\r\n"\
                              "%s"\
                              "Content-Length: %d\r\n"\
                              "Content-Type: %s\r\n\r\n"

#define MT_NO_CHDIR           01
#define MT_NO_CLOSE_FILES     02
#define MT_NO_REOPEN_STD_FDS  04
#define MT_NO_UMASK0          010
#define MT_MAX_CLOSE          8192

#define MT_HMAC_DIGEST_SIZE   (256/8)
#define MT_ENV_SIZE_MAX       256

#define MT_CS_UTF8            "charset=UTF-8"

#define MT_CT_JPEG            "image/jpeg"
#define MT_CT_JPEG_UTF8       MT_CT_JPEG ";" MT_CS_UTF8
#define MT_CT_WEBP            "image/webp"
#define MT_CT_WEBP_UTF8       MT_CT_WEBP ";" MT_CS_UTF8
#define MT_CT_PNG             "image/png"
#define MT_CT_PNG_UTF8        MT_CT_PNG  ";" MT_CS_UTF8
#define MT_CT_TEXT            "text/plain"
#define MT_CT_TEXT_UTF8       MT_CT_TEXT ";" MT_CS_UTF8
#define MT_CT_JSON            "application/json"
#define MT_CT_JSON_UTF8       MT_CT_JSON ";" MT_CS_UTF8
#define MT_CT_FORM            "application/x-www-form-urlencoded"
#define MT_CT_FORM_UTF8       MT_CT_FORM ";" MT_CS_UTF8
#define MT_CT_CBOR            "application/cbor"

#define MT_ASYNC_WD_SECOND    1000000

#define MT_LOG_FILE           "/tmp/mt.log"

#define MT_LOG_MSG            "{"\
                              "\"type\":\"%s\","\
                              "\"msg\":\"%s\","\
                              "\"time\":%lu"\
                              "}"

#define MT_JSON_MSG           "{"\
                              "\"error\":%d,"\
                              "\"log\":%s,"\
                              "\"data\":%s"\
                              "}"

#define MT_ASYNC_FNAME        "/tmp/mt/_async_%s.txt"

#ifndef DEBUG
#define mt_log()
#define mt_daemonize() do {\
  if(mt_service_demonize(0)) exit(EXIT_FAILURE);\
} while (0)
#else
#define mt_log(msg) do {printf("%s\n", msg)} while(0)
#define mt_daemonize()
#endif

#define MT_EMPTY_REPLY(c) do {\
  mg_http_reply(c, 200,\
                "Content-Type: application/json\r\n",\
                "{\"err\":0,\"log\":null,\"res\":null}");\
} while(0)

#define MT_ERROR_REPLY(c, st, ms) do {\
  mg_http_reply(c, 200,\
    "Content-Type: application/json\r\n",\
    "{\"err\":%d,\"log\":\"%s\",\"res\":null}",\
    st, ms);\
} while(0)

#define MT_MESSAGE_REPLY(c, ms) do {\
  mg_http_reply(c, 200,\
    "Content-Type: application/json\r\n",\
    "{\"err\":0,\"log\":null,\"res\":%s}", ms);\
} while(0)

typedef struct mt_config_t {
  int enabled;
  int timer;
  int validate_request;
  int authorize;
  char *allow_ips;
  char *working_dir;
  char *auth_token;
  char *db_serv;
  char *db_conn;
  char *serv_url;
} mt_config_t;

typedef struct mt_file_uploaded_t {
  size_t size;
  const char *name;
  const char *path;
  const char *origin;
  unsigned long *body;
} mt_file_uploaded_t;

typedef struct mt_http_request_t {
  const struct mg_http_message *hm;
  int method_number;
  const char *message;
  const char *proto;
  const char *method;
  const char *uri;
  const char *query;
  const char *body;
  apr_pool_t *pool;
  apr_table_t *headers;
  apr_table_t *args; 
  apr_array_header_t *uploaded_files;
} mt_http_request_t;

typedef struct mt_http_response_t {
  int status;
  size_t len;
  const char *message;
  const char *content_type;
  apr_array_header_t *headers;
  void *buffer;
} mt_http_response_t;

typedef struct mt_dbd_t {
  const char *error;
  const apr_dbd_driver_t *driver;
  apr_dbd_t *handle;
} mt_dbd_t;

typedef struct mt_timer_t {
  apr_pool_t *pool;
} mt_timer_t;

typedef struct mt_t {
  apr_pool_t *pool;
  mt_config_t *config;
  mt_timer_t *timer;
  struct mg_mgr *mgr;
} mt_t;

typedef struct mt_async_data_t {
  apr_pool_t *pool;
  mt_http_request_t *request;
  mt_http_response_t *response;
  mt_dbd_t *dbd;
  const char *async_id;
} mt_async_data_t;

/*  --------------
    MISC functions
    --------------
*/

/**
 * @brief Restituisce un intero pseudorandom nel range specificato
 * 
 * @param l (int) Estremo inferiore
 * @param h (int) Estremo superiore
 */
int mt_random(int l, int h)
{
  srand(time(NULL));
  return (rand() % (h - l + 1)) + l;
}

/*  ----------------
    STRING functions
    ----------------
*/

int mt_is_empty(const char *s)
{
  return (int)((s == NULL) || (strlen(s) <= 0) || (
               (strlen(s) == 1) && ((strncmp(s, " ",  1) == 0) ||
                                    (strncmp(s, "\n", 1) == 0) ||
                                    (strncmp(s, "\r", 1) == 0) ||
                                    (strncmp(s, "\t", 1) == 0))));
}

int mt_is_null(const char *s) {
  return (int)(s == NULL || (strncasecmp(s, "null", 4)) == 0 ||
                            (strncasecmp(s, "NULL", 4)) == 0);
}

int mt_is_integer(const char *v) {
  char tmp[16] = {0};
  if (v == NULL) return 0;
  sprintf(tmp, "%d", atoi(v));
  return (int)(atoi(v) && (int)strlen(tmp) == (int)strlen(v));
}

int mt_is_float(const char *v) {
  int len;
  float dummy = 0.0;
  return (int)(sscanf(v, "%f %n", &dummy, &len)==1 && len==(int)strlen(v));
}

int mt_str_contains_char(const char *s, char v) {
  for (int i = 0; i < strlen(s); i++)
    if (s[i] == v) return 1;
  return 0;
}

char* mt_ltrim(char *s) {
  while (isspace(*s)) s++;
  return s;
}

char* mt_rtrim(char *s) {
  char *back = s + strlen(s);
  while (isspace(*--back));
  *(back + 1) = '\0';
  return s;
}

char* mt_trim(char *s) {
  return mt_rtrim(mt_ltrim(s));
}

void mt_strip_char(char *s, char c) {
  const char *d = s;
  do {while (*d == c) ++d;} while (*s++ = *d++);
}

const char* mt_slice(apr_pool_t *mp, const char *s, int start, int l) {
  int len = strlen(s);
  if (len > 0 && start >= 0 && start <= len-1) {
    if (l > 0 && l <= len-start) {
      char *res = (char*)apr_palloc(mp, sizeof(char)*(l+1));
      strncpy(res, s + start, l);
      res[l+1] = '\0';
      return res;
    }
  }
  return NULL;
}

char* mt_chr_replace(apr_pool_t *mp, const char *s, char src, char rep) {
  size_t len = strlen(s);
  char *tmp = apr_palloc(mp, len+1);
  if (!tmp) return NULL;
  for (int i = 0; i < len; i ++) tmp[i] = (s[i] != src) ? s[i] : rep;
  tmp[len] = '\0';
  return tmp;
}

char* mt_str_replace(apr_pool_t *mp, const char* s, const char *src, const char *rep) {
  char *res;
  int i, cnt = 0;
  int rep_len = strlen(rep);
  int src_len = strlen(src);
  // Conta il numero di volte in cui compare la stringa da sostituire
  for (i = 0; s[i] != '\0'; i++) {
    if (strstr(&s[i], src) == &s[i]) {
      cnt++;
      // Salta all'indice successiovo alla vecchia parola
      i += src_len - 1;
    }
  }
  res = (char*)apr_palloc(mp, i + cnt * (rep_len - src_len) + 1);
  i = 0;
  while (*s) {
    // Confronta la sottostringa con res
    if (strstr(s, src) == s) {
      strcpy(&res[i], rep);
      i += rep_len;
      s += src_len;
    }
    else
      res[i++] = *s++;
  }
  res[i] = '\0';
  return res;
}

const char* mt_pstr(apr_pool_t *mp, const char *s, size_t l) {
  char *ret = NULL;
  if (!mp || !s || !l) return NULL;
  if (!(ret = (char*)apr_palloc(mp, l))) return NULL;
  memcpy(ret, s, l);
  ret[l] = '\0';
  return (const char*)ret;
}

// -----------------------------------------------------------------------------
// ARRAY
// -----------------------------------------------------------------------------

apr_array_header_t* mt_psplit(apr_pool_t *mp, const char *s, const char *sep) {
  apr_array_header_t *a;
  char *tok, *last, *str_c;
  if ((str_c = apr_pstrdup(mp, s)) == NULL) return NULL;
  if ((a = apr_array_make(mp, 0, sizeof(char*))) == NULL) return NULL;
  last = NULL;
  tok = apr_strtok(str_c, sep, &last); // first token
  while (*last) {
    APR_ARRAY_PUSH(a, char*) = apr_pstrdup(mp, tok); // curr token
    tok = apr_strtok(last, sep, &last); // next token
  }
  APR_ARRAY_PUSH(a, char*) = apr_pstrdup(mp, tok); // last token
  return a;
}

char* mt_pjoin(apr_pool_t *mp, apr_array_header_t *arr, const char *sep) {
  char *item = NULL;
  apr_array_header_t *tmp = NULL;
  if (mp == NULL || arr == NULL || arr->nelts <= 0) return NULL;
  for (int i = 0; i < arr->nelts; i ++) {
    item = APR_ARRAY_IDX(arr, i, char*);
    if (item != NULL) {
      if (tmp == NULL) {
        tmp = apr_array_make(mp, arr->nelts, sizeof(char*));
        if (tmp == NULL) return NULL;
      }
      APR_ARRAY_PUSH(tmp, char*) = apr_pstrdup(mp, item);
      if ((sep != NULL) && (i < (arr->nelts - 1)))
        APR_ARRAY_PUSH(tmp, char*) = apr_pstrdup(mp, sep);
    }
  }
  return apr_array_pstrcat(mp, tmp, 0);
}

// -----------------------------------------------------------------------------
// DIRECTORY
// -----------------------------------------------------------------------------

int mt_dir_exists(apr_pool_t *mp, const char *dir) {
  apr_status_t rv;
  apr_finfo_t finfo;
  rv = apr_stat(&finfo, dir, APR_FINFO_TYPE, mp);
  return rv == APR_SUCCESS && finfo.filetype == APR_DIR;
}

// -----------------------------------------------------------------------------
// FILE
// -----------------------------------------------------------------------------

int mt_file_exists(apr_pool_t *mp, const char *fn) {
  apr_finfo_t finfo;
  return (apr_stat(&finfo, fn, APR_FINFO_NORM, mp) == APR_SUCCESS);
}

static apr_size_t mt_file_write_full(apr_pool_t *mp, const char *fn, int md, const void *dt, apr_size_t sz, int lk) {
  int rv;
  apr_size_t sw;
  apr_file_t *fh;
  if (!mt_file_exists(mp, fn)) md = APR_FOPEN_CREATE|md;
  rv = apr_file_open(&fh, fn, md, APR_OS_DEFAULT, mp);
  if (rv != APR_SUCCESS) return 0;
  if (lk) rv = apr_file_lock(fh, APR_FLOCK_EXCLUSIVE);
  if (rv == APR_SUCCESS) {
    rv = apr_file_write_full(fh, dt, sz, &sw);
    if (lk) apr_file_unlock(fh);
  }
  apr_file_close(fh);
  return sw;
}

size_t mt_file_write(apr_pool_t *mp, const char *fn, const void *dt, size_t sz) {
  return (size_t)mt_file_write_full(mp, fn, APR_FOPEN_WRITE, dt, sz, 0);
}

size_t mt_file_write_lock(apr_pool_t *mp, const char *fn, const void *dt, size_t sz) {
  return (size_t)mt_file_write_full(mp, fn, APR_FOPEN_WRITE, dt, sz, 1);
}

size_t mt_file_append(apr_pool_t *mp, const char *fn, const void *dt, size_t sz) {
  if (!mt_file_exists(mp, fn)) return 0;
  return (size_t)mt_file_write_full(mp, fn, APR_FOPEN_WRITE|APR_FOPEN_APPEND, dt, sz, 0);
}

apr_size_t mt_file_append_lock(apr_pool_t *mp, const char *fn, const void *dt, size_t sz) {
  if (!mt_file_exists(mp, fn)) return 0;
  return mt_file_write_full(mp, fn, APR_FOPEN_WRITE|APR_FOPEN_APPEND, dt, sz, 1);
}

apr_size_t mt_file_read_full(apr_pool_t *mp, const char *fn, void **bf, int lk) {
  int rv;
  apr_size_t sz, sr;
  apr_file_t *fh;
  apr_finfo_t finfo;
  int er = 0;
  if (!mt_file_exists(mp, fn)) return 0;
  rv = apr_file_open(&fh, fn, APR_FOPEN_READ, APR_OS_DEFAULT, mp);
  if (rv != APR_SUCCESS) return 0;
  if (lk) rv = apr_file_lock(fh, APR_FLOCK_EXCLUSIVE);
  if (rv == APR_SUCCESS) {
    rv = apr_file_info_get(&finfo, APR_FINFO_NORM, fh);
    if (rv == APR_SUCCESS) {
      sz = (apr_size_t)finfo.size;
      *bf = (void*)apr_palloc(mp, sz);
      rv = apr_file_read_full(fh, *bf, sz, &sr);
      if (rv != APR_SUCCESS) er = 1;
      if (lk) apr_file_unlock(fh);
    }
    apr_file_close(fh);
  }
  return er ? 0 : sr;
}

size_t mt_file_read(apr_pool_t *mp, const char *fn, void **bf) {
  return (size_t)mt_file_read_full(mp, fn, bf, 0);
}

apr_size_t mt_file_read_lock(apr_pool_t *mp, const char *fn, void **bf) {
  return mt_file_read_full(mp, fn, bf, 1);
}

// -----------------------------------------------------------------------------
// DATABASE
// -----------------------------------------------------------------------------

mt_dbd_t* mt_dbd(apr_pool_t *mp, mt_config_t *cf) {
  mt_dbd_t *dbd = (mt_dbd_t*)apr_palloc(mp, sizeof(mt_dbd_t));
  if (dbd == NULL) return NULL;
  dbd->driver = NULL;
  dbd->handle = NULL;
  dbd->error = NULL;
  return dbd;
}

const char* mt_dbd_name(mt_dbd_t *dbd) {
  return apr_dbd_name(dbd->driver);
}

const apr_dbd_driver_t* mt_dbd_driver_get(mt_dbd_t *dbd) {
  return dbd->driver;
}

apr_dbd_t* mt_dbd_handle_get(mt_dbd_t *dbd) {
  return dbd->handle;
}

int mt_dbd_open(apr_pool_t *mp, mt_dbd_t *dbd, mt_config_t *cf) {
  int rv;
  dbd->error = NULL;
  rv = apr_dbd_init(mp);
  if (rv == APR_SUCCESS) {
    rv = apr_dbd_get_driver(mp, cf->db_serv, &(dbd->driver));
    if (rv == APR_SUCCESS) {
      rv = apr_dbd_open_ex(dbd->driver, mp, cf->db_conn, &(dbd->handle), &(dbd->error));
      if (rv == APR_SUCCESS)
        return rv;
    }
  }
  dbd->driver = NULL;
  dbd->handle = NULL;
  return rv;
}

int mt_dbd_query(apr_pool_t *mp, mt_dbd_t *dbd, const char *sql) {
  int aff_rows = 0, err;
  if (sql == NULL) return -1;
  err = apr_dbd_query(dbd->driver, dbd->handle, &aff_rows, sql);
  if (err) {
    dbd->error = apr_pstrdup(mp, apr_dbd_error(dbd->driver,dbd->handle, err));
    return -1;
  }
  return aff_rows;
}

apr_array_header_t* mt_dbd_select(apr_pool_t *mp, mt_dbd_t *dbd, const char *sql) {
  int rv, err;
  apr_dbd_results_t *res = NULL;
  apr_dbd_row_t *row = NULL;
  apr_array_header_t *rset;
  apr_table_t *rec;
  int first_rec, num_fields;
  if ((err = apr_dbd_select(dbd->driver, mp, dbd->handle, &res, sql, 0))) {
    dbd->error = apr_pstrdup(mp, apr_dbd_error(dbd->driver,dbd->handle, err));
    return NULL;
  }
  if (res == NULL) return NULL;
  if ((rv = apr_dbd_get_row(dbd->driver, mp, res, &row, -1)) == -1) return NULL;
  rset = NULL;
  first_rec = 1;
  while (rv != -1) {
    if (first_rec) {
      num_fields = apr_dbd_num_cols(dbd->driver, res);
      rset = apr_array_make(mp, num_fields, sizeof(apr_table_t*));
      first_rec = 0;
    }
    rec = apr_table_make(mp, num_fields);
    for (int i = 0; i < num_fields; i++) {
      const char *k = apr_dbd_get_name(dbd->driver, res, i);
      const char *v = apr_dbd_get_entry(dbd->driver, row, i);
      apr_table_setn(rec, apr_pstrdup(mp, k),
                     apr_pstrdup(mp, mt_is_empty(v) ? "NULL" : v));
    }
    APR_ARRAY_PUSH(rset, apr_table_t*) = rec;
    rv = apr_dbd_get_row(dbd->driver, mp, res, &row, -1);
  }
  return rset;
}

const char* mt_dbd_get_value(apr_array_header_t *r, int i, const char *k) {
  if (r == NULL || r->nelts <= 0 || i > (r->nelts-1)) return NULL;
  apr_table_t* t = APR_ARRAY_IDX(r, i, apr_table_t*);
  return apr_table_get(t, k);
}

int mt_dbd_set_value(apr_array_header_t *r, int i, const char *k, const char *v) {
  if (r == NULL || r->nelts <= 0 || i > (r->nelts-1)) return 1;
  apr_table_t* t = APR_ARRAY_IDX(r, i, apr_table_t*);
  apr_table_setn(t, k, v);
  return 0;
}

apr_table_t* mt_dbd_get_entry(apr_array_header_t *r, int i) {
  if (r == NULL || r->nelts <= 0 || i > (r->nelts-1)) return NULL;
  return APR_ARRAY_IDX(r, i, apr_table_t*);
}

const char* mt_dbd_get_first(apr_array_header_t *rset) {
  if (rset == NULL || rset->nelts <= 0) return NULL;
  apr_table_t* t = APR_ARRAY_IDX(rset, 0, apr_table_t*);
  if (t == NULL) return NULL;
  if ((apr_table_elts(t))->nelts <= 0) return NULL;
  apr_table_entry_t *e = &((apr_table_entry_t*)((apr_table_elts(t))->elts))[0];
  return e->val;
}

int mt_dbd_close(mt_dbd_t *dbd) {
  return apr_dbd_close(dbd->driver, dbd->handle);
}

// -----------------------------------------------------------------------------
// HASH
// -----------------------------------------------------------------------------

const char* mt_md5_encode(apr_pool_t *mp, const char *s) {
  const char *str = "";
  union {unsigned char chr[16]; uint32_t num[4];} digest;
  apr_md5_ctx_t md5;
  apr_md5_init(&md5);
  apr_md5_update(&md5, s, strlen(s));
  apr_md5_final(digest.chr, &md5);
  for (int i = 0; i < APR_MD5_DIGESTSIZE/4; i++) {
    str = apr_pstrcat(mp, str, apr_psprintf(mp, "%08x", digest.num[i]), NULL);
  }
  return str;
}

char* mt_base64_encode(apr_pool_t *mp, const char *str, size_t len) {
  int b64_len = apr_base64_encode_len((int)len);
  char *b64_str = (char*)apr_palloc(mp, sizeof(char)*b64_len);
  if (b64_str == NULL) return NULL;
  apr_base64_encode(b64_str, str, (int)len);
  return b64_str;
}

// -> alg = "MD5", "SHA256", ...
// -> str = hash("MD5", "Hello, World!")
// -> str = "65a8e27d8879283831b664bd8b7f0ad4"
const char* mt_hash_encode(apr_pool_t *mp, const char *alg, const char *str)
{
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  unsigned char md_value[EVP_MAX_MD_SIZE];
  unsigned int md_len, i;
  apr_array_header_t *ar;
  if (!str) return NULL;
  md = EVP_get_digestbyname(alg);
  if (!md) return NULL;
  mdctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, str, strlen(str));
  EVP_DigestFinal_ex(mdctx, md_value, &md_len);
  EVP_MD_CTX_free(mdctx);
  ar = apr_array_make(mp, md_len, sizeof(const char*));
  for (i = 0; i < md_len; i++)
    APR_ARRAY_PUSH(ar, const char*) = apr_psprintf(mp, "%02x", md_value[i]);
  return mt_pjoin(mp, ar, "");
}

// -----------------------------------------------------------------------------
// JSON
// -----------------------------------------------------------------------------

const char* mt_json_pstr(apr_pool_t *mp, const char *s)
{
    if (s == NULL) return NULL;
    switch (*s)
    {
    case '\0':
        return NULL;
    case '-':
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        return mt_is_float(s)
            ? s
            : apr_psprintf(mp, "\"%s\"", apr_pescape_echo(mp, s, 1));
    case 't':
    case 'T':
        if (!strncmp(s, "true", 4))
            return apr_pstrdup(mp, "true");
    case 'f':
    case 'F':
        if (!strncmp(s, "false", 5))
            return apr_pstrdup(mp, "false");
    case 'n':
    case 'N':
        if (!strncmp(s, "null", 4) || !strncmp(s, "NULL", 4))
            return apr_pstrdup(mp, "null");
    default:
        return apr_psprintf(mp, "\"%s\"", apr_pescape_echo(mp, s, 1));
    }
    return NULL;
}

const char* mt_json_ptable(apr_pool_t *mp, apr_table_t *t)
{
  int len;
  apr_array_header_t *arr;
  if (t == NULL) return NULL;
  if ((len = (apr_table_elts(t))->nelts) <= 0) return NULL;
  if ((arr = apr_array_make(mp, len, sizeof(const char*))) == NULL)
      return NULL;
  for (int i = 0; i < len; i++) {
    apr_table_entry_t *e = &((apr_table_entry_t*)((apr_table_elts(t))->elts))[i];
    APR_ARRAY_PUSH(arr, const char*) =
      apr_psprintf(mp, "\"%s\":%s", (const char*)e->key,
                   mt_json_pstr(mp, (const char*)e->val));
  }
  return apr_pstrcat(mp, "{", apr_array_pstrcat(mp, arr, ','), "}", NULL);
}

const char* mt_json_parray(apr_pool_t *mp, apr_array_header_t *a, int tp)
{
  apr_array_header_t *arr = NULL;
  void *v = NULL;
  if (a == NULL || a->nelts <= 0) return NULL;
  arr = apr_array_make(mp, a->nelts, sizeof(const char*));
  for (int i = 0; i < a->nelts; i++) {
    v = APR_ARRAY_IDX(a, i, void*);
    switch (tp)
    {
    case MT_TYPE_TABLE:
      APR_ARRAY_PUSH(arr, const char*) =
        mt_json_ptable(mp, (apr_table_t*)v);
      break;
    default:
      APR_ARRAY_PUSH(arr, const char*) =
        mt_json_pstr(mp, (const char*)v);
      break;
    }
  }
  return apr_pstrcat(mp, "[", apr_array_pstrcat(mp, arr, ','), "]", NULL);
}

// -----------------------------------------------------------------------------
// ENV
// -----------------------------------------------------------------------------

static char* mt_env_get(apr_pool_t *mp, const char *e) {
  char v[MT_ENV_SIZE_MAX];
  if (!getenv(e)) return NULL;
  if (snprintf(v, MT_ENV_SIZE_MAX, "%s", getenv(e)) >= MT_ENV_SIZE_MAX)
    return NULL;
  return apr_pstrdup(mp, v);
}

// -----------------------------------------------------------------------------
// CONFIG
// -----------------------------------------------------------------------------

static int mt_config(mt_t *mt, const char *env_ns)
{
  char *fname;
  json_object *root, *obj;
  fname = mt_env_get(mt->pool, apr_psprintf(mt->pool, "MT_%s_CONF_FILE", env_ns));
  if (!fname) return 0;
  if (!(root = json_object_from_file(fname))) return 0;
  mt->config = (mt_config_t*)apr_palloc(mt->pool, sizeof(mt_config_t));
  if (!mt->config) return 0;
  mt->config->serv_url = NULL;
  obj = json_object_object_get(root, "enabled");
  mt->config->enabled = obj ? json_object_get_boolean(obj) : 0;
  obj = json_object_object_get(root, "timer");
  mt->config->timer = obj ? json_object_get_boolean(obj) : 0;
  obj = json_object_object_get(root, "authorize");
  mt->config->authorize = obj ? json_object_get_boolean(obj) : 0;
  obj = json_object_object_get(root, "validate_request");
  mt->config->validate_request = obj ? json_object_get_boolean(obj) : 0;
  obj = json_object_object_get(root, "working_dir");
  mt->config->working_dir = obj ? (char*)json_object_get_string(obj) : NULL;
  obj = json_object_object_get(root, "allow_ips");
  mt->config->allow_ips = obj ? (char*)json_object_get_string(obj) : NULL;
  obj = json_object_object_get(root, "auth_token");
  mt->config->auth_token = obj ? (char*)json_object_get_string(obj) : NULL;
  obj = json_object_object_get(root, "db_serv");
  mt->config->db_serv = obj ? (char*)json_object_get_string(obj) : NULL;
  obj = json_object_object_get(root, "db_conn");
  mt->config->db_conn = obj ? (char*)json_object_get_string(obj) : NULL;
  if (mt->config->db_serv && mt->config->db_conn) {
    if (strcmp(mt->config->db_serv, "pgsql") == 0) {
      for (int i = 0; i < strlen(mt->config->db_conn); i++) {
        if (mt->config->db_conn[i] == ',') {
          mt->config->db_conn[i] = ' ';
        }
      }
    }
  }
  return 1;
}

int mt_config_enabled_get(mt_t *mt) {
  return mt->config->enabled;
}

int mt_config_timer_get(mt_t *mt) {
  return mt->config->timer;
}

int mt_config_validate_request_get(mt_t *mt) {
  return mt->config->validate_request;
}

int mt_config_authorize_get(mt_t *mt) {
  return mt->config->authorize;
}

int mt_config_has_working_dir(mt_t *mt) {
  return mt->config->working_dir != NULL;
}

int mt_config_has_allow_ips(mt_t *mt) {
  return mt->config->allow_ips != NULL;
}

int mt_config_has_auth_token(mt_t *mt) {
  return mt->config->auth_token != NULL;
}

int mt_config_has_db_conn(mt_t *mt) {
  return mt->config->db_conn != NULL;
}

char* mt_config_working_dir_get(mt_t *mt) {
  return mt->config->working_dir;
}

char* mt_config_allow_ips_get(mt_t *mt) {
  return mt->config->allow_ips;
}

char* mt_config_auth_token_get(mt_t *mt) {
  return mt->config->auth_token;
}

char* mt_config_db_conn_get(mt_t *mt) {
  return mt->config->db_conn;
}

// -----------------------------------------------------------------------------
// LOG
// -----------------------------------------------------------------------------

int mt_log_is_enabled(apr_pool_t *mp) {
  return mt_file_exists(mp, MT_LOG_FILE);
}

/**
 * @brief 
 * 
 * @param mp  (apr_pool_t*) Memory pool
 * @param t   (const char*) Type
 * @param m   (const char*) Message 
 */
void mt_log_enable(apr_pool_t *mp, const char *t, const char *m) {
  if (!mt_log_is_enabled(mp)) {
    const char *msg = apr_psprintf(mp, MT_LOG_MSG, t ? t : "WS_EV_MSG", m ? m : "Log enabled", (unsigned long)time(NULL));
    mt_file_write_lock(mp, MT_LOG_FILE, (const void*)msg, strlen(msg));
  }
}

void mt_log_disable(apr_pool_t *mp) {
  if (mt_log_is_enabled(mp)) apr_file_remove(MT_LOG_FILE, mp);
}

apr_size_t mt_log_read(apr_pool_t *mp, const char **m) {
  if (!mt_log_is_enabled(mp)) return 0;
  return mt_file_read_lock(mp, MT_LOG_FILE, (void**)m);
}

apr_size_t mt_log_write(apr_pool_t *mp, const char *t, const char *m) {
  if (!mt_log_is_enabled(mp)) return 0;
  const char *msg = apr_psprintf(mp, ","MT_LOG_MSG, t, m, (unsigned long)time(NULL));
  size_t sz = mt_file_append_lock(mp, MT_LOG_FILE, (const void*)msg, strlen(msg));
  return sz;
}

// -----------------------------------------------------------------------------
// MT OBJECT
// -----------------------------------------------------------------------------

static mt_t* mt_(apr_pool_t *mp, struct mg_mgr *mgr) {
  mt_t *mt = (mt_t*)apr_palloc(mp, sizeof(mt_t));
  if (!mt) return NULL;
  mt->timer = apr_palloc(mp, sizeof(mt_timer_t));
  if (!mt->timer) return NULL;
  if (apr_pool_create(&(mt->timer->pool), mp) != APR_SUCCESS) return NULL;
  mt->pool = mp;
  mt->mgr = mgr;
  mt->config = NULL;
  return mt;
}

// -----------------------------------------------------------------------------
// REQUEST
// -----------------------------------------------------------------------------

static void mt_header_to_table(apr_pool_t *mp, struct mg_http_message *hm, apr_table_t *t, const char *hd) {
  struct mg_str *mg_h = mg_http_get_header(hm, hd);
  if (mg_h != NULL) apr_table_setn(t, hd, mt_pstr(mp, mg_h->ptr, mg_h->len));
}

static apr_table_t* mt_args_to_table(apr_pool_t *mp, const char *q) {
  apr_table_t *map;
  apr_array_header_t *args, *elts;
  args = mt_psplit(mp, q, "&");
  if (args && args->nelts) {
    map = apr_table_make(mp, args->nelts);
    for (int i = 0; i < args->nelts; i++) {
      const char *arg = APR_ARRAY_IDX(args, i, const char*);
      elts = mt_psplit(mp, arg, "=");
      if (elts && elts->nelts == 2) {
        apr_table_set(
          map,
          APR_ARRAY_IDX(elts, 0, const char*),
          APR_ARRAY_IDX(elts, 1, const char*)
        );
      }
    }
    return map;
  }
  return NULL;
}

static mt_http_request_t* mt_http_request(apr_pool_t *mp, struct mg_http_message *hm) {
  mt_http_request_t *r = apr_palloc(mp, sizeof(mt_http_request_t));
  if (!r) return NULL;
  r->hm = hm;
  r->method_number = 0;
  r->query = NULL;
  r->body = NULL;
  r->args = NULL;
  r->uploaded_files = NULL;
  r->headers = apr_table_make(mp, 6);
  if (!r->headers) return NULL;
  mt_header_to_table(mp, hm, r->headers, MT_HTTP_ACCEPT);
  mt_header_to_table(mp, hm, r->headers, MT_HTTP_CONTENT_TYPE);
  mt_header_to_table(mp, hm, r->headers, MT_HTTP_AUTHORIZE);
  mt_header_to_table(mp, hm, r->headers, MT_HTTP_DATE);
  mt_header_to_table(mp, hm, r->headers, MT_HTTP_ASYNC);
  mt_header_to_table(mp, hm, r->headers, MT_HTTP_MULTIPART);
  r->message = mt_pstr(mp, hm->message.ptr, hm->message.len);
  if (!r->message) return NULL;
  r->proto = mt_pstr(mp, hm->proto.ptr, hm->proto.len);
  if (!r->proto) return NULL;
  r->method = mt_pstr(mp, hm->method.ptr, hm->method.len);
  if (!r->method) return NULL;
  r->uri = mt_pstr(mp, hm->uri.ptr, hm->uri.len);
  if (!r->uri) return NULL;
  r->query = mt_pstr(mp, hm->query.ptr, hm->query.len);
  r->body = mt_pstr(mp, hm->body.ptr, hm->body.len);
  if (strcmp(r->method, "GET") == 0) r->method_number = MT_HTTP_GET;
  if (strcmp(r->method, "POST") == 0) r->method_number = MT_HTTP_POST;
  if (strcmp(r->method, "PUT") == 0) r->method_number = MT_HTTP_PUT;
  if (strcmp(r->method, "PATCH") == 0) r->method_number = MT_HTTP_PATCH;
  if (strcmp(r->method, "DELETE") == 0) r->method_number = MT_HTTP_DELETE;
  if (r->method_number == MT_HTTP_GET && r->query != NULL) {
    r->args = mt_args_to_table(mp, r->query);
  } else if (r->method_number == MT_HTTP_POST) {
    if (apr_table_get(r->headers, MT_HTTP_MULTIPART) != NULL) {
      struct mg_http_part part;
      size_t ofs = 0;
      while ((ofs = mg_http_next_multipart(hm->body, ofs, &part)) > 0) {
        if ((int)part.filename.len > 0) { // multipart file
          if (r->uploaded_files == NULL)
            r->uploaded_files = apr_array_make(mp,1, sizeof(mt_file_uploaded_t));
          if (r->uploaded_files != NULL) {
            mt_file_uploaded_t *f;
            unsigned char *fbuff;
            size_t wsize;
            f = (mt_file_uploaded_t*)apr_palloc(mp, sizeof(mt_file_uploaded_t));
            f->name = apr_psprintf(mp, "%.*s", (int)part.name.len, part.name.ptr);
            f->origin = apr_psprintf(mp, "%.*s", (int)part.filename.len, part.filename.ptr);
            f->size = (size_t)part.body.len;
            f->path = apr_psprintf(mp, "/tmp/%s", f->origin);
            fbuff = (unsigned char*)apr_palloc(mp, (unsigned long)part.body.len);
            memcpy(fbuff, part.body.ptr, (int)part.body.len);
            wsize = mt_file_write(mp, f->path, (const void*)fbuff, (size_t)f->size);
            APR_ARRAY_PUSH(r->uploaded_files, mt_file_uploaded_t*) = f;
          }
        } else { // multipart argument
          if (r->args == NULL)
            r->args = apr_table_make(mp, 1);
          if (r->args != NULL) {
            apr_table_set(r->args,
              apr_psprintf(mp, "%.*s", (int)part.name.len, part.name.ptr),
              apr_psprintf(mp, "%.*s", (int)part.body.len, part.body.ptr)
            );
          }
        }
      }
    }
  }
  return r;
}

const char* mt_http_request_message_get(mt_http_request_t *r) {return r->message;}
const char* mt_http_request_proto_get(mt_http_request_t *r) {return r->proto;}
const char* mt_http_request_method_get(mt_http_request_t *r) {return r->method;}
const char* mt_http_request_uri_get(mt_http_request_t *r) {return r->uri;}
const char* mt_http_request_query_get(mt_http_request_t *r) {return r->query;}
const char* mt_http_request_body_get(mt_http_request_t *r) {return r->body;}
apr_table_t* mt_http_request_headers_get(mt_http_request_t *r) {return r->headers;}
apr_table_t* mt_http_request_args_get(mt_http_request_t *r) {return r->args;}

int mt_request_args_num(mt_http_request_t *r) {return apr_table_elts(r->args)->nelts;}
int mt_request_uploaded_file_num(mt_http_request_t *r) {return r->uploaded_files->nelts;}

mt_file_uploaded_t* mt_http_request_uploaded_file_next(mt_http_request_t *r, int i) {
  return APR_ARRAY_IDX(r->uploaded_files, i, mt_file_uploaded_t*);
}

int mt_http_request_uri_match(mt_http_request_t *r, const char *uri) {
  return mg_http_match_uri(r->hm, uri);
}

// -----------------------------------------------------------------------------
// RESPONSE
// -----------------------------------------------------------------------------

mt_http_response_t* mt_http_response(apr_pool_t *mp) {
  mt_http_response_t *r;
  r = (mt_http_response_t*)apr_palloc(mp, sizeof(mt_http_response_t));
  if (!r) return NULL;
  r->buffer = NULL;
  r->len = 0;
  r->content_type = NULL;
  r->headers = NULL;
  r->message = NULL;
  r->status = 0;
  return r;
}

void mt_http_response_status_set(mt_http_response_t *r, int s) {
  if (r) r->status = s;
}

static const char* mt_http_response_status_msg_get(int status) {
  if (status == MT_HTTP_NOT_FOUND) return "Not Found";
  if (status == MT_HTTP_BAD_REQUEST) return "Bad Request";
  if (status == MT_HTTP_UNAUTHORIZED) return "Unauthorized";
  if (status == MT_HTTP_FORBIDDEN) return "Forbidden";
  if (status == MT_HTTP_METHOD_NOT_ALLOWED) return "Method Not Allowed";
  if (status == MT_HTTP_NOT_ACCEPTABLE) return "Not Acceptable";
  if (status == MT_HTTP_UNSUPPORTED_MEDIA_TYPE) return "Unsupported Media Type";
  return "Internal Server Error";
}

void mt_http_response_content_type_set(apr_pool_t *mp, mt_http_response_t *r, const char *ct) {
  if (r) r->content_type = apr_pstrdup(mp, ct);
}

void mt_http_response_message_set(apr_pool_t *mp, mt_http_response_t *r, const char *msg) {
  if (r) r->message = apr_pstrdup(mp, msg);
}

void mt_http_response_buffer_set(apr_pool_t *mp, mt_http_response_t *r, void *b, size_t l) {
  if (r) {
    r->len = l;
    r->buffer = apr_palloc(mp, l);
    memcpy(r->buffer, b, l);
  }
}

void mt_http_response_header_set(apr_pool_t *mp, mt_http_response_t *r, const char *k, const char *v) {
  if (r->headers == NULL) r->headers = apr_array_make(mp, 1, sizeof(apr_table_t*));
  const char *h = apr_psprintf(mp, "%s: %s\r\n", k, v);
  APR_ARRAY_PUSH(r->headers, const char*) = h;
}

const char* mt_http_response_headers_get(apr_pool_t *mp, mt_http_response_t *r) {
  if (!r->headers && r->headers->nelts) {
    return mt_pjoin(mp, r->headers, "");
  }
}

// -----------------------------------------------------------------------------
// HMAC AUTHORIZATION
// -----------------------------------------------------------------------------

static const char* mt_hmac_hash_make(apr_pool_t *mp, const uint8_t *k, uint32_t k_len, const uint8_t *s, uint32_t s_len) {
  apr_array_header_t *hash_ar;
  uint32_t hash_len = MT_HMAC_DIGEST_SIZE;
  uint8_t hash[hash_len];
  unsigned char* res;
  res = HMAC(EVP_sha256(), k, k_len, s, s_len, hash, &hash_len);
  hash_ar = apr_array_make(mp, MT_HMAC_DIGEST_SIZE, sizeof(const char*));
  for (int i = 0; i < hash_len; i++) {
    APR_ARRAY_PUSH(hash_ar, const char*) = apr_psprintf(mp, "%02x", res[i]);
  }
  return mt_pjoin(mp, hash_ar, "");
}

static const char* mt_hmac_digest_make(mt_t *mt, apr_pool_t *mp, mt_http_request_t *req, const char *date, const char *nonce) {
  const uint8_t *str;
  const char *hmac;
  const char *digest;

  str = (const uint8_t*)apr_psprintf(mp, "%s+%s+%s+%s",
                                     req->method, req->uri,
                                     date, nonce);
  if (str == NULL) return NULL;
  hmac = mt_hmac_hash_make(mp, mt->config->auth_token,
                           strlen((const char*)mt->config->auth_token),
                           str, strlen((const char*)str));
  if (hmac == NULL) return NULL;
  return mt_base64_encode(mp, hmac, strlen(hmac));
}

static int mt_hmac_auth(mt_t *mt, apr_pool_t *mp, mt_http_request_t *req, char *h_auth, char *h_date) {
  apr_array_header_t *aut_ar;
  apr_array_header_t *aut_dgs_ar;
  const char *usr, *nonce, *aut_dgs, *dgs, *digest;
  mt_strip_char(h_date, ' ');
  aut_ar = mt_psplit(mp, h_auth, " ");
  if (aut_ar == NULL || aut_ar->nelts < 2) return 0;
  aut_dgs = APR_ARRAY_IDX(aut_ar, 1, const char*);
  if (aut_dgs == NULL) return 0;
  aut_dgs_ar = mt_psplit(mp, aut_dgs, ":");
  if (aut_dgs_ar == NULL || aut_dgs_ar->nelts < 3) return 0;
  usr = APR_ARRAY_IDX(aut_dgs_ar, 0, const char*);
  nonce = APR_ARRAY_IDX(aut_dgs_ar, 1, const char*);
  dgs = APR_ARRAY_IDX(aut_dgs_ar, 2, const char*);
  if ((digest = mt_hmac_digest_make(mt, mp, req, h_date, nonce)) == NULL) return 0;
  return strcmp(digest, dgs) == 0;
}

static int mt_authorized(mt_t *mt, apr_pool_t *mp, mt_http_request_t *req) {
  int rv;
  const char *date, *auth;
  date = apr_table_get(req->headers, MT_HTTP_DATE);
  auth = apr_table_get(req->headers, MT_HTTP_AUTHORIZE);
  if (auth == NULL || date == NULL) return 0;
  return mt_hmac_auth(mt, mp, req, (char*)auth, (char*)date);
}

// -----------------------------------------------------------------------------
// HTTP REQUEST VALIDATION
// -----------------------------------------------------------------------------

static int mt_valid_method(mt_http_request_t* req) {
  return (req->method_number == MT_HTTP_GET ||
          req->method_number == MT_HTTP_POST ||
          req->method_number == MT_HTTP_PUT ||
          req->method_number == MT_HTTP_PATCH ||
          req->method_number == MT_HTTP_DELETE);
}

static int mt_valid_accept(mt_http_request_t* req) {
  const char *h = apr_table_get(req->headers, MT_HTTP_ACCEPT);
  return (h != NULL && (
          strcasecmp(h, MT_CT_TEXT) == 0 ||
          strcasecmp(h, MT_CT_TEXT_UTF8) == 0 ||
          strcasecmp(h, MT_CT_PNG) == 0 ||
          strcasecmp(h, MT_CT_PNG_UTF8) == 0 ||
          strcasecmp(h, MT_CT_JPEG) == 0 ||
          strcasecmp(h, MT_CT_JPEG_UTF8) == 0 ||
          strcasecmp(h, MT_CT_WEBP) == 0 ||
          strcasecmp(h, MT_CT_WEBP_UTF8) == 0 ||
          strcasecmp(h, MT_CT_JSON) == 0 ||
          strcasecmp(h, MT_CT_JSON_UTF8) == 0));
}

static int mt_valid_content_type(mt_http_request_t* req) {
  const char *h = apr_table_get(req->headers, MT_HTTP_CONTENT_TYPE);
  return (h != NULL && (
          strcasecmp(h, MT_CT_TEXT) == 0 ||
          strcasecmp(h, MT_CT_TEXT_UTF8) == 0 ||
          strcasecmp(h, MT_CT_JSON) == 0 ||
          strcasecmp(h, MT_CT_JSON_UTF8) == 0 ||
          strcasecmp(h, MT_CT_FORM) == 0 ||
          strcasecmp(h, MT_CT_FORM_UTF8) == 0));
}

static int mt_valid_request(mt_t *mt, mt_http_request_t*req, int *st) {
  *st = 0;
  if (mt->config == NULL) {
    *st = MT_HTTP_INTERNAL_SERVER_ERROR;
  } else if (mt->config->validate_request && !mt_valid_method(req)) {
    *st = MT_HTTP_METHOD_NOT_ALLOWED;
  } else if (mt->config->validate_request && !mt_valid_content_type(req)) {
    *st = MT_HTTP_UNSUPPORTED_MEDIA_TYPE;
  } else if (mt->config->validate_request && !mt_valid_accept(req)) {
    *st = MT_HTTP_NOT_ACCEPTABLE;
  }
  return ((*st) == 0);
}

static void mt_ws_cb(void *mt) {
  size_t sz;
  const char *data;
  mt_dbd_t *dbd = NULL;

  apr_pool_t *mp = ((mt_t*)mt)->timer->pool;
  
  int rv = APR_SUCCESS;
  int enable_dbd = ((mt_t*)mt)->config->db_serv && ((mt_t*)mt)->config->db_conn;
  if (enable_dbd) {
    dbd = mt_dbd(mp, ((mt_t*)mt)->config);
    if (dbd) {
      rv = mt_dbd_open(mp, dbd, ((mt_t*)mt)->config);
    }
  }
  if (enable_dbd && (!dbd || rv != APR_SUCCESS)) {
    for (struct mg_connection *c = ((struct mg_mgr*)(((mt_t*)mt)->mgr))->conns; c != NULL; c = c->next) {
      if (c->label[0] == 'W') {
        if (dbd->error) {
          mg_ws_send(c, dbd->error, strlen(dbd->error), WEBSOCKET_OP_TEXT);
        } else {
          const char msg[] = "mt_dbd_open() error";
          mg_ws_send(c, msg, strlen(msg), WEBSOCKET_OP_TEXT);
        }
      }
    }
  } else {
    mt_service_monitor(((mt_t*)mt)->timer->pool, dbd, &data, &sz);
    const char *log;
    sz = mt_log_read(mp, &log);
    const char *buffer = apr_psprintf(mp, MT_JSON_MSG, 0, log ? log : "null", data ? data: "null");
    for (struct mg_connection *c = ((struct mg_mgr*)(((mt_t*)mt)->mgr))->conns; c != NULL; c = c->next) {
      if (c->label[0] == 'W') {
        mg_ws_send(c, buffer, strlen(buffer), WEBSOCKET_OP_TEXT);
      }
    }
  }
  if (dbd && dbd->driver && dbd->handle) {
    mt_dbd_close(dbd);
  }
  apr_pool_clear(((mt_t*)mt)->timer->pool);
}



/*******************************************************************************
 * @brief Funzione invocata dal thread.
 * 
 * Invoca la funzione utente da eseguire in modo asincrono.
 * Scrive il proprio stato in un file temporaneo cui è possibile accedere
 * mediante l'URL restituito al client dopo la creazione del thread.
 * 
 * @note  Si può inserire un ritardo per testare la funzione 
 *        mediante apr_sleep(30 * MT_ASYNC_WD_SECOND)
 * 
 * @param t_data  (void*) Dati passati al thread
 */
static void* mt_async_exec(void *t_data)
{
  apr_status_t rv;
  mt_async_data_t *d;
  const char *f;
  apr_time_t inizio = apr_time_now();
  d = (mt_async_data_t *)t_data;
  f = apr_psprintf(d->pool, MT_ASYNC_FNAME, d->async_id);
  mt_file_write_lock(d->pool, f, "1", 1);
  mt_service_api_async(d->pool, d->request, d->dbd);
  mt_file_write_lock(d->pool, f, "2", 1);
  apr_time_t fine = apr_time_now();
end:
  if (d->dbd && d->dbd->driver && d->dbd->handle) mt_dbd_close(d->dbd);
  apr_pool_destroy(d->pool);
  pthread_exit(0);
}

static const char* mt_async_status_create(apr_pool_t *mp,
                                          struct mg_http_message *hm)
{
  apr_status_t rv;
  const char *m, *s, *h, *f;

  if (!mt_dir_exists(mp, "/tmp/mt")) {
    rv = apr_dir_make("/tmp/mt", APR_UREAD | APR_UWRITE | APR_UEXECUTE, mp);
    if (rv != APR_SUCCESS) {
      printf("Error creating /tmp/mt directory\n");
      return NULL;
    }
  }

  m = mt_pstr(mp, hm->message.ptr, hm->message.len);
  s = apr_psprintf(mp, "%s+%lu", m, (unsigned long)time(NULL));
  h = mt_hash_encode(mp, "MD5", s);
  f = apr_psprintf(mp, MT_ASYNC_FNAME, h);
  mt_file_write(mp, f, "0", 1);
  return h;
}

static void mt_http_api(struct mg_connection *c,
                        struct mg_http_message *hm,
                        void *fn_data,
                        apr_pool_t *mp)
{
  mt_t *mt;
  apr_pool_t *cbmp;
  int rv, async, st, auth, enable_dbd;
  mt_dbd_t *dbd;
  const char *hd, *async_id;
  mt_http_request_t *req;
  mt_http_response_t *res;
  pthread_t tid;
  mt_async_data_t *t_data;

  /*  Controllo dei dati della funzione di callback
  */
  if (fn_data == NULL) {

    MT_ERROR_REPLY(c, MT_HTTP_INTERNAL_SERVER_ERROR, "Callback data empty");

  } else {

    /*  Dati della funzione di callback
    */
    mt = (mt_t*)fn_data;

    /*  Memory pool locale
    */
    if ((async = (int)(mg_http_get_header(hm, "x-mt-async") != NULL))) {
      apr_pool_create(&cbmp, NULL);
    } else {
      cbmp = mp;
    }

    /*  Apertura della connessione DBD
    */
    dbd = NULL;
    rv = APR_SUCCESS;
    if ((enable_dbd = mt->config->db_serv && mt->config->db_conn)) {
      dbd = mt_dbd(cbmp, mt->config);
      if (dbd) {
        rv = mt_dbd_open(cbmp, dbd, mt->config);
      }
    }

    /*  Controllo della connessione DBD
    */
    if (enable_dbd && (!dbd || rv != APR_SUCCESS)) {

      MT_ERROR_REPLY(c, MT_HTTP_INTERNAL_SERVER_ERROR,
                     dbd && dbd->error ? dbd->error : "DBD connection error");

    } else {

      /*  Inizializzazione della REQUEST HTTP
      */
      if (!(req = mt_http_request(cbmp, hm))) {

        MT_ERROR_REPLY(c, MT_HTTP_INTERNAL_SERVER_ERROR,
                       "mt_http_request() error");

      } else {

        /*  Validazione della REQUEST HTTP
            Se richiesta dalla configurazione del servizio
        */
        if (mt->config->validate_request && !mt_valid_request(mt, req, &st)) {

          MT_ERROR_REPLY(c, st, mt_http_response_status_msg_get(st));

        } else {

          /*  Autenticazione della REQUEST HTTP
              Se richiesta dalla configurazione del servizio
          */
          auth = 1;
          if (mt->config->authorize && mt->config->auth_token)
            auth = mt_authorized(mt, mp, req);
          if (!auth) {
            MT_ERROR_REPLY(c, MT_HTTP_UNAUTHORIZED,
                           mt_http_response_status_msg_get(MT_HTTP_UNAUTHORIZED));
          } else {

            /*  Inizializzazione della RESPONSE HTTP
            */
            if (!(res = mt_http_response(cbmp))) {

              MT_ERROR_REPLY(c, MT_HTTP_INTERNAL_SERVER_ERROR,
                             "mt_http_response() error");

            } else {

              if (async) {

                /*  -----------------------
                    Procedura API asincrona
                    -----------------------
                */
                /*  ASYNC ID
                    Permette il monitoraggio dello stato
                    della procedura asincrona
                */
                if (async_id = mt_async_status_create(cbmp, hm)) {

                  /*  Inizializzazione dei dati del thread
                  */
                  t_data = apr_palloc(cbmp, sizeof(mt_async_data_t));
                  t_data->pool = cbmp;
                  t_data->async_id = async_id;
                  t_data->request = req;
                  t_data->response = res;
                  t_data->dbd = dbd;

                  /*  Thread asincrono
                      TODO: Valutare il valore di ritorno
                  */
                  rv = pthread_create(&tid, NULL,
                                      mt_async_exec,
                                      (void*)t_data);

                  /*  Response sincrona
                  */
                  mg_http_reply(c, 200,
                                "Content-Type: application/json\r\n",
                                "{"
                                "\"err\":0,"
                                "\"log\":null,"
                                "\"res\":{\"uri\":\"/async/%s\"}"
                                "}",
                                async_id);
                
                } else {

                  MT_ERROR_REPLY(c, MT_HTTP_INTERNAL_SERVER_ERROR,
                                 "mt_async_status_create() error");

                }
              
              } else {
                
                /*  ----------------------
                    Procedura API sincrona
                    ----------------------
                */
                
                mt_service_api(cbmp, req, res, dbd);
                
                if (res->len && res->buffer) {

                  /*  Invio degli header della RESPONSE HTTP
                      MT_HTTP_SUCCESS = Headers HTTP predefiniti
                      res->headers = Headers HTTP aggiuntivi
                  */
                  hd = NULL;
                  if (res->headers && res->headers->nelts)
                    hd = mt_pjoin(mp, res->headers, "\r\n");
                  mg_printf(c, MT_HTTP_SUCCESS,
                            hd ? hd : "", res->len, res->content_type);

                  /*  Invio del body header della RESPONSE HTTP
                  */
                  mg_send(c, res->buffer, res->len);
                
                } else {
                
                  MT_EMPTY_REPLY(c);
                
                }
              }
            }
          }
        }
      }
    }

    /*  Chiusura della connessione DBD
    */
    if (!async && dbd && dbd->driver && dbd->handle) {
      mt_dbd_close(dbd);
    }
  }
}

/*******************************************************************************
 * @brief Restituisce un file dal file system integrato.
 * 
 * @note  mt_http_file()
 *        `---> Configura l'accesso al filesystem integrato
 *        `---> Invoca mg_http_serve_file() per restituire il file predefinito
 *        `---> Invoca mg_http_serve_dir() per restituire il file spacificato
 * 
 * Prima di ritornare è possibile intraprendere azioni dipendenti dallo
 * stato della RESPONSE che è stato settato in seguito alla chiamata a
 * mg_http_serve_file() oppure a mg_http_serve_dir().
 * 
 * Esempio:
 * 
 *    Inizializzo una struttura dati per i parametri della RESPONSE
 *    struct mg_http_message res = {0};
 *
 *    Eseguo il parsing del buffer
 *    mg_http_parse((char*)c->send.buf,   Buffer
 *                  c->send.len,          Dimensione del buffer
 *                  &res                  Parametri
 *                  );
 *
 *    Uso i parametri del buffer
 *    if ((int)mg_http_status(&res) == 404) {
 *      ...
 *    }
 * 
 * @param c   (struct mg_connection*)   Connessione aperta
 * @param hm  (struct mg_http_message*) Messaggio HTTP
 */
static void mt_http_file(struct mg_connection *c, struct mg_http_message *hm)
{
  struct mg_http_serve_opts opts = {0};
  opts.root_dir = "/mtfs";
  opts.mime_types = "html=text/html";
  opts.extra_headers = "Content-Type: text/html\r\n";
  opts.page404 = "/mtfs/404.html";
  opts.fs = &mg_fs_packed;
  if (mg_http_match_uri(hm, "/")) {
    mg_http_serve_file(c, hm, "/mtfs/main.html", &opts);
  } else {
    mg_http_serve_dir(c, hm, &opts);
  }
}

/*******************************************************************************
 * @brief Restituisce lo stato di una procedura asincrona.
 *        
 * Lo stato è un oggetto JSON con il formato {"status": 0|1|2}.
 * (0: non avviato, 1: in corso, 2: completato).
 * 
 * @param mp  (apr_pool_t*)             Pool di memoria
 * @param c   (struct mg_connection*)   Connessione corrente
 * @param hm  (struct mg_http_message*) Messaggio HTTP
 */
static void mt_http_async_status(apr_pool_t *mp,
                                 struct mg_connection *c,
                                 struct mg_http_message *hm)
{
  apr_array_header_t *uri_ar;
  const char *uri, *async_id, *fname, *msg;
  void *buff;
  size_t sz;
  uri = mt_pstr(mp, hm->uri.ptr, hm->uri.len);
  uri_ar = mt_psplit(mp, uri, "/");
  async_id = APR_ARRAY_IDX(uri_ar, 1, const char*);
  fname = apr_psprintf(mp, "/tmp/mt/_async_%s.txt", async_id);
  msg = NULL;
  if (mt_file_exists(mp, fname)) {
    sz = mt_file_read(mp, fname, &buff);
    if (sz && buff) msg = apr_psprintf(mp, "{\"status\": %s}", buff);
  }
  if (msg) MT_MESSAGE_REPLY(c, msg);
  else MT_EMPTY_REPLY(c);
}

/*******************************************************************************
 * @brief Esegue l'upgrade della connessione web socket.
 *        
 * Contrassegna la connessione corrente come connessione web socket settando
 * il primo byte dell'array c->label. Inizializza il registro dei log.
 * 
 * @param c   (struct mg_connection*)     Connessione
 * @param hm  (struct mg_http_message*)   Messaggio HTTP
 */
static void mt_http_ws_upgrade(apr_pool_t*mp,
                               struct mg_connection *c,
                               struct mg_http_message *hm)
{
  mg_ws_upgrade(c, hm, NULL);
  c->label[0] = 'W';
  if (mt_log_is_enabled(mp)) mt_log_disable(mp);
  mt_log_enable(mp, NULL, NULL);
}

/*******************************************************************************
 * @brief Callback di una richiesta HTTP.
 * 
 * Inizializza le strutture dati APR e alloca il pool di memoria.
 * Invoca il gestore corretto della REQUEST in base al formato dello URI.
 * Le strutture dati allocate sono limitate al contesto della callback e non
 * sono condivise con altri threads.
 * 
 * @note  mt_http_cb()
 *        `---> Inizializza le strutture dati APR
 *        `---> Alloca il pool di memoria
 *        `---> In presenza di un evento di tipo MG_EV_HTTP_MSG
 *            `---> Invoca mt_http_ws_upgrade() se lo URI è /ws...
 *            `---> Invoca mt_http_async_status() se lo URI è /async...
 *            `---> Invoca mt_http_api() se lo URI è /api...
 *            `---> Invoca mt_http_file() se lo URI non è nessuno dei precedenti
 *        `---> Dealloca il pool di memoria e le strutture dati APR
 * 
 * @param c       (struct mg_connection *)  Connessione aperta
 * @param ev      (int)                     Evento
 * @param ev_data (void*)                   Dati dell'evento
 * @param fn_data (void*)                   Parametri della funzione
 */
static void mt_http_cb(struct mg_connection *c,
                       int ev,
                       void *ev_data,
                       void *fn_data)
{
  int rv;
  apr_pool_t *mp;
  struct mg_http_message *hm;
  struct mg_ws_message *wm;
  if (ev == MG_EV_HTTP_MSG || ev == MG_EV_WS_MSG) {
    if ((rv = apr_initialize()) == APR_SUCCESS) {
      if ((rv = apr_pool_create(&mp, NULL)) == APR_SUCCESS) {
        if (ev == MG_EV_HTTP_MSG) {
          hm = (struct mg_http_message*)ev_data;
          if (mg_http_match_uri(hm, "/ws")) {
            mt_http_ws_upgrade(mp, c, hm);
          } else if (mg_http_match_uri(hm, "/async/*")) {
            mt_http_async_status(mp, c, hm);
          } else if (mg_http_match_uri(hm, "/api/*") ||
                     mg_http_match_uri(hm, "/api/*/*")) {
            mt_http_api(c, hm, fn_data, mp);
          } else {
            mt_http_file(c, hm);
          }
        }
        apr_pool_destroy(mp);
      }
      apr_terminate();
    }
  }
  (void)fn_data;
}

/*******************************************************************************
 * @brief Determina l'esecuzione del servizio in background
 * 
 * @param flags (int)
 */
static int mt_service_demonize(int flags)
{
  int maxfd, fd;
  switch (fork()) {
    case -1: return -1;
    case 0: break;
    default: _exit(EXIT_SUCCESS);
  }
  if (setsid() == -1) return -1;
  switch(fork()) {
    case -1: return -1;
    case 0: break;
    default: _exit(EXIT_SUCCESS);
  }
  if (!(flags & MT_NO_UMASK0)) umask(0);
  if (!(flags & MT_NO_CHDIR)) chdir("/");
  if (!(flags & MT_NO_CLOSE_FILES)) {
    maxfd = sysconf(_SC_OPEN_MAX);
    if(maxfd == -1) maxfd = MT_MAX_CLOSE;
    for(fd = 0; fd < maxfd; fd++) close(fd);
  }
  if (!(flags & MT_NO_REOPEN_STD_FDS)) {
    close(STDIN_FILENO);
    fd = open("/dev/null", O_RDWR);
    if (fd != STDIN_FILENO) return -1;
    if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO) return -2;
    if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) return -3;
  }
  return 0;
}

/*******************************************************************************
 * @brief Mette il servizio in ascolto su ip/porta specificata.
 * 
 * Inizializza le strutture dati APR e alloca il pool di memoria.
 * Avvia il listener delle richieste HTTP e un thread di monitoraggio
 * proattivo separato.
 * Le strutture dati allocate sono limitate al solo oggetto mt condiviso
 * in sola lettura tra le richieste del client.
 * 
 * @note  mt_http_serve()
 *        `---> Inizializza la configurazione
 *        `---> Invoca mg_http_listen() per accettare richieste HTTP
 *              mg_http_listen() invoca la callback mt_http_cb() per ogni
 *              richiesta HTTP in ingresso
 *        `---> Invoca mg_timer_add() per la notifica degli aggiornamenti
 *              di stato sulle connessioni attive
 *              mg_timer_add() invoca la callback mt_ws_cb() per ogni
 *              richiesta WS in ingresso
 *
 * @param c       (struct mg_connection *)  Connessione aperta
 * @param ev      (int)                     Evento
 * @param ev_data (void*)                   Dati dell'evento
 * @param fn_data (void*)                   Parametri della funzione
 */
void mt_http_serve(const char *url,
                   int ht_time,
                   int ws_time,
                   const char *env_ns)
{
  int rv;
  apr_pool_t *mp;
  struct mg_mgr mgr;
  mt_daemonize();
  rv = apr_initialize();
  if (rv != APR_SUCCESS) exit(EXIT_FAILURE);
  rv = apr_pool_create(&mp, NULL);
  if (rv != APR_SUCCESS) exit(EXIT_FAILURE);
  mg_mgr_init(&mgr);
  mt_t *mt = mt_(mp, &mgr);
  if (!mt) exit(EXIT_FAILURE);
  if (!mt_config(mt, env_ns)) exit(EXIT_FAILURE);
  mt->config->serv_url = apr_pstrdup(mp, url);
  if (mt->config->timer)
    mg_timer_add(&mgr, ws_time, MG_TIMER_REPEAT, mt_ws_cb, (void*)mt);
  mg_http_listen(&mgr, url, mt_http_cb, (void*)mt);
  for (;;) mg_mgr_poll(&mgr, ht_time);
  mg_mgr_free(&mgr);
  apr_pool_destroy(mp);
  apr_terminate();
}

/*
main()
`---> Invoca mt_service_demonize() per eseguire il servizio in background
`---> Invoca mt_http_serve() per avviare il servizio
*/
