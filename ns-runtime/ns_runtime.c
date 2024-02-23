// MIT License
// Copyright (c) 2024 Riccardo Vacirca <rvacirca23@gmail.com>

#include "ns_runtime.h"

/*
 * COMMON
 */

int ns_rand(int l, int h)
{
  srand(time(NULL));
  return l < h ? (rand() % (h - l + 1)) + l : 0;
}

int ns_is_empty(const char *s)
{
  int rv = 1;
  if (s && (*s != '\0')) {
    apr_size_t l = strlen(s);
    for (apr_size_t i = 0; i < l; i ++) {
      // La stringa non è vuota se contiene almeno un carattere non vuoto
      if (!apr_isspace(s[i])) {
        rv = 0;
        break;
      }
    }
  }
  return rv;
}

int ns_is_int(const char *s)
{
  int rv = 0;
  if (s && (*s != '\0')) {
    // Puntatore alla fine della stringa
    char *endp;
    // Converto la stringa in intero (in base 10)
    (void)strtol(s, &endp, 10);
    // Verifico se il puntatore di fine stringa è valido
    rv = (endp != s) && (*endp == '\0');
  }
  return rv;
}

int ns_is_double(const char *s)
{
  int rv = 0;
  if (s && (*s != '\0')) {
    // Puntatore alla fine della stringa
    char *endp;
    // Converto la stringa in double
    (void)strtod(s, &endp);
    // Verifico se il puntatore di fine stringa è valido
    rv = (endp != s) && (*endp == '\0');
  }
  return rv;
}

int ns_in_string(const char *s, const char *sub)
{
  int rv = 0;
  if (s && sub) {
    apr_size_t ls, lsub;
    rv = ((ls = strlen(s)) > 0) && ((lsub = strlen(sub)) > 0) &&
         (lsub <= ls) && (strstr(s, sub) != NULL);
  }
  return rv;
}

/** Allocates a string to a buffer of specified size
  * @param p Memory pool
  * @param s The string to allocate
  * @param bf_size The size of the buffer
  * @return The pointer to the buffer
  * @note The returned string always has a NULL terminator
  *       and a size of at most bf_size-1 bytes
*/
char* ns_buffer(apr_pool_t *mp, const char *s, apr_size_t *bf_size)
{
  char *rv = NULL, *ends = NULL, str[(*bf_size)+1];
  if (mp && s && *bf_size > 0) {
    ends = apr_cpystrn(str, s, (*bf_size)+1);
  }
  if (ends) {
    *bf_size = ends - str;
    if ((*bf_size) > 0) {
      rv = (char*) apr_palloc(mp, sizeof(char)*(*bf_size) + 1);
      if (rv) {
        ends = apr_cpystrn(rv, s, (*bf_size) + 1);
      }
    }
  }
  if (!rv) {
    *bf_size = 0;
  }
  return rv;
}

char* ns_str(apr_pool_t *mp, const char *s, apr_size_t sz)
{
  char *rv;
  apr_size_t bf_size = sz;
  rv = ns_buffer(mp, s, &bf_size);
  return rv && bf_size > 0 ? rv : NULL;
}

char* ns_trim(apr_pool_t *mp, const char *s)
{
  char *rv = NULL;
  int start = 0, end = strlen(s) - 1;
  while (isspace((unsigned char)s[start])) {
    start ++;
  }
  while ((end >= start) && isspace((unsigned char)s[end])) {
    end --;
  }
  rv = apr_palloc(mp, end - start + 2);
  memcpy(rv, s + start, end - start + 1);
  rv[end - start + 1] = '\0';
  return rv;
}

// char* ns_trim(apr_pool_t *pool, const char *str) {
//   int start = 0, end = strlen(str) - 1;
//   // Trova il primo carattere non vuoto dall'inizio della stringa
//   while (isspace((unsigned char)str[start])) {
//     start++;
//   }
//   // Trova l'ultimo carattere non vuoto dalla fine della stringa
//   while (end >= start && isspace((unsigned char)str[end])) {
//     end--;
//   }
//   // Alloca la memoria per la stringa trimmata
//   char *trimmed_str = apr_palloc(pool, end - start + 2);
//   // Copia i caratteri non vuoti nella nuova stringa
//   memcpy(trimmed_str, str + start, end - start + 1);
//   trimmed_str[end - start + 1] = '\0';
//   return trimmed_str;
// }



const char* ns_strip_char(apr_pool_t *mp, const char *s, char c)
{
  char *rv = NULL;
  apr_size_t l, j = 0;
  if (mp && s) {
    l = (apr_size_t)strlen(s);
    if (l > 0) {
      rv = (char*)apr_palloc(mp, sizeof(char) * (l + 1));
    }
  }
  if (rv) {
    // Ricostruisco la stringa con ogni elemento diverso da c
    for (apr_size_t i = 0; i < l; i ++) {
      if (s[i] != c) {
        rv[j] = s[i];
        j ++;
      }
    }
    // Aggiungo il terminatore alla fine
    rv[j] = '\0';
  }
  return !rv ? s : (const char*)rv;
}

char* ns_slice(apr_pool_t *mp, const char *s, apr_size_t i, apr_size_t l)
{
  char *rv = NULL;
  apr_size_t len = 0;
  if (mp && s && (i >= 0) && (l > 0)) {
    len = (apr_size_t)strlen(s);
  }
  if ((len > 0) && (i <= (len - 1)) && (l <= (len - i))) {
    rv = (char*)apr_palloc(mp, sizeof(char) * (l + 1));
  }
  if (rv) {
    for (apr_size_t j = 0; j < l; j ++) {
      rv[j] = s[i + j];
    }
    rv[l] = '\0';
  }
  return rv;
}

const char* ns_str_replace(apr_pool_t *mp, const char *s, const char *f,
                           const char *r)
{
  char *rv = NULL;
  int i = 0, cnt = 0, r_len = 0, f_len = 0;
  if (mp && s && f && r) {
    if ((*s != '\0') && (*f != '\0') && (*r != '\0')) {
      if (strcmp(f, r) != 0) {
        f_len = strlen(f);
        r_len = strlen(r);
      }
    }
  }
  if (f_len > 0 && r_len > 0) {
    for (i = 0; s[i] != '\0'; i++) {
      if (strstr(&s[i], f) == &s[i]) {
        cnt ++;
        i += f_len - 1;
      }
    }
  }
  if (cnt > 0) {
    rv = (char*)apr_palloc(mp, i + cnt * (r_len-f_len) + 1);
  }
  if (rv) {
    i = 0;
    while (*s) {
      if (strstr(s, f) == s) {
        strcpy(&rv[i], r);
        i += r_len;
        s += f_len;
      } else {
        rv[i++] = *s++;
      }
    }
    rv[i] = '\0';
  }
  return !rv ? s : (const char*)rv;
}

const char* ns_replace_char(apr_pool_t *mp, const char *s, char f, char r)
{
  char *rv = NULL;
  if (mp && s && f && r) {
    if((*s != '\0') && (f != r)) {
      rv = apr_pstrdup(mp, s);
    }
  }
  if (rv) {
    for (int i = 0; i < strlen(rv); i++) {
      if (rv[i] == f) {
        rv[i] = r;
      }
    }
  }
  return !rv ? s : (const char*)rv;
}

char* ns_empty_string_make(apr_pool_t *mp)
{
  char *rv = NULL;
  if (mp) {
    rv = (char*)apr_palloc(mp, 1);
    if (rv) {
      rv[0] = '\0';
    }
  }
  return rv;
}

apr_array_header_t* ns_split(apr_pool_t *mp, const char *s, const char *sp)
{
  apr_array_header_t *rv = NULL;
  char *str = NULL;
  const char *tmp = NULL;
  apr_size_t l_sp = 0;
  if (mp && s && sp) {
    if (strlen(s) > 0) {
      l_sp = (apr_size_t)strlen(sp);
    }
  }
  if(l_sp > 0) {
    rv = apr_array_make(mp, 0, sizeof(const char*));
  }
  if (rv) {
    str = apr_pstrdup(mp, s);
  }
  if (str) {
    char *ptr = strstr(str, sp);
    while (ptr) {
      *ptr = '\0';
      if (strlen(str) <= 0) {
        tmp = (const char*)ns_empty_string_make(mp);
        if (tmp) {
          APR_ARRAY_PUSH(rv, const char*) = tmp;
        }
      } else {
        tmp = apr_pstrdup(mp, str);
        if (tmp) {
          APR_ARRAY_PUSH(rv, const char*) = tmp;
        }
      }
      str = ptr + l_sp;
      ptr = strstr(str, sp);
    }
  }
  if (strlen(str) <= 0) {
    tmp = (const char*)ns_empty_string_make(mp);
    if (tmp) {
      APR_ARRAY_PUSH(rv, const char*) = tmp;
    }
  } else {
    tmp = apr_pstrdup(mp, str);
    if (tmp) {
      APR_ARRAY_PUSH(rv, const char*) = tmp;
    }
  }
  return rv;
}

char* ns_join(apr_pool_t *mp, apr_array_header_t *a, const char *sp)
{
  int valid_input = 0, valid_array = 0;
  apr_size_t sp_l;
  char *item, *rv = NULL;
  apr_array_header_t *tmp = NULL;
  valid_input = mp && a;
  if (valid_input) {
    valid_array = a->nelts > 0;
  }
  if (valid_array) {
    if (!sp) {
      rv = apr_array_pstrcat(mp, a, 0);
    } else {
      sp_l = (apr_size_t)strlen(sp);
      if (sp_l > 0) {
        for (int i = 0; i < a->nelts; i ++) {
          item = APR_ARRAY_IDX(a, i, char*);
          if (item) {
            if (!tmp) {
              tmp = apr_array_make(mp, a->nelts, sizeof(char*));
            }
          }
          if (tmp) {
            APR_ARRAY_PUSH(tmp, char*) = apr_pstrdup(mp, item);
            if (i < (a->nelts - 1)) {
              APR_ARRAY_PUSH(tmp, char*) = apr_pstrdup(mp, sp);
            }
          }
        }
      }
      if (tmp && (tmp->nelts > 0)) {
        rv = apr_array_pstrcat(mp, tmp, 0);
      }
    }
  }
  return rv;
}

char* ns_md5(apr_pool_t *mp, const char *s)
{
  char *rv = NULL;
  apr_size_t l = 0;
  unsigned char digest[APR_MD5_DIGESTSIZE];
  if (mp && s) { 
    l = strlen(s);
  }
  if(l > 0) {
    apr_md5_ctx_t ctx;
    apr_md5_init(&ctx);
    apr_md5_update(&ctx, s, l);
    apr_md5_final(digest, &ctx);
    rv = (char*)apr_pcalloc(mp, 32 + 1);
  }
  if (rv) {
    for (int i = 0; i < APR_MD5_DIGESTSIZE; i ++) {
      sprintf(&rv[i * 2], "%02x", digest[i]);
    }
  }
  return rv;
}

char* ns_base64_encode(apr_pool_t *mp, const char *s)
{
  char *rv = NULL;
  apr_size_t l = 0;
  if (mp && s) {
    l = (apr_size_t)strlen(s);
  }
  if (l > 0) {
    rv = (char*)apr_pcalloc(mp, apr_base64_encode_len(l));
  }
  if (rv != NULL) {
    apr_base64_encode(rv, s, l);
  }
  return rv;
}

char* ns_base64_decode(apr_pool_t* mp, const char* s)
{
  char* rv = NULL;
  apr_size_t s_len = 0, max_rv_len = 0, rv_len = 0;
  if (mp && s) {
    s_len = strlen(s);
  }
  if (s_len > 0) {
    max_rv_len = apr_base64_decode_len(s);
  }
  if (max_rv_len > 0) {
    rv = (char*)apr_palloc(mp, max_rv_len);
  }
  if (rv) {
    rv_len = apr_base64_decode(rv, s);
  }
  if (rv_len >= 0) {
    rv[rv_len] = '\0';
  }
  return rv;
}

apr_table_t* ns_args_to_table(apr_pool_t *mp, const char *q)
{
  apr_table_t *rv = NULL;
  apr_array_header_t *args, *elts;
  args = ns_split(mp, q, "&");
  if (args && args->nelts) {
    rv = apr_table_make(mp, args->nelts);
    for (int i = 0; i < args->nelts; i++) {
      const char *arg = APR_ARRAY_IDX(args, i, const char*);
      elts = ns_split(mp, arg, "=");
      if (elts && elts->nelts == 2) {
        apr_table_set(
          rv,
          APR_ARRAY_IDX(elts, 0, const char*),
          APR_ARRAY_IDX(elts, 1, const char*)
        );
      }
    }
  }
  return rv;
}

int ns_table_nelts(apr_table_t *t)
{
  return t ? (apr_table_elts(t))->nelts : -1;
}

apr_table_entry_t* ns_table_elt(apr_table_t *t, int i)
{
  apr_table_entry_t *rv = NULL;
  if (t && (i >= 0)) {
    if (i < (apr_table_elts(t))->nelts) {
      rv = &((apr_table_entry_t*)((apr_table_elts(t))->elts))[i];
    }
  }
  return rv;
}

char* ns_datetime(apr_pool_t *mp, apr_time_t t, const char *f)
{
  char *rv = NULL;
  apr_time_exp_t tm;
  apr_size_t size = 100;
  const char *fm = NULL;
  char tmp[100] = {0};
  if (mp && t && f) {
    if (apr_time_exp_lt(&tm, t) == APR_SUCCESS) {
      fm = apr_pstrdup(mp, f);
      if (fm) {
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "Y", "%Y"), "y", "%y");
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "m", "%m"), "d", "%d");
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "H", "%H"), "h", "%I");
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "s", "%S"), "i", "%M");
      }
    }
  }
  if (fm) {
    if (apr_strftime(tmp, &size, 100, fm, &tm) == APR_SUCCESS) {
      rv = apr_pstrdup(mp, tmp);
    }
  }
  return rv;
}

char* ns_datetime_local(apr_pool_t *mp, apr_time_t t, const char *f)
{
  char *rv = NULL;
  apr_time_exp_t tm;
  apr_size_t size = 100;
  const char *fm = NULL;
  char tmp[100] = {0};
  if (mp && t && f) {
    if (apr_time_exp_lt(&tm, t) == APR_SUCCESS) {
      fm = apr_pstrdup(mp, f);
      if (fm) {
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "Y", "%Y"), "y", "%y");
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "m", "%m"), "d", "%d");
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "H", "%H"), "h", "%I");
        fm = ns_str_replace(mp, ns_str_replace(mp, fm, "s", "%S"), "i", "%M");
        fm = apr_pstrcat(mp, fm, "%z", NULL);
      }
    }
  }
  if (fm) {
    if (apr_strftime(tmp, &size, 100, fm, &tm) == APR_SUCCESS) {
      rv = apr_pstrdup(mp, tmp);
    }
  }
  return rv;
}

char* ns_datetime_utc(apr_pool_t *mp, apr_time_t t, const char *f)
{
  apr_time_exp_t tm;
  apr_size_t size = 100;
  char tmp[100] = {0}, *rv = NULL;
  if (mp && t) {
    // Usa apr_time_exp_gmt invece di apr_time_exp_lt
    if (apr_time_exp_gmt(&tm, t) == APR_SUCCESS) {
      // Formato desiderato
      const char *fm = "%Y-%m-%d %H:%M:%S";
      if (apr_strftime(tmp, &size, 100, fm, &tm) == APR_SUCCESS) {
        rv = apr_pstrdup(mp, tmp);
      }
    }
  }
  return rv;
}

int ns_is_dir(const char *d, apr_pool_t *mp)
{
  apr_finfo_t finfo;
  return mp && d && (strlen(d) > 0) &&
    (apr_stat(&finfo, d, APR_FINFO_TYPE, mp) == APR_SUCCESS) &&
    (finfo.filetype == APR_DIR);
}

int ns_is_file(const char *f, apr_pool_t *mp)
{
  apr_finfo_t finfo;
  return mp && f && (strlen(f) > 0) &&
    (apr_stat(&finfo, f, APR_FINFO_NORM, mp) == APR_SUCCESS);
}

apr_status_t ns_file_open(apr_file_t **fd, const char *f, apr_int32_t fl, apr_pool_t *mp)
{
  apr_status_t rv = APR_EGENERAL;
  if (mp && f) {
    rv = apr_file_open(fd, f, fl, APR_OS_DEFAULT, mp);
  }
  return rv;
}

apr_status_t ns_file_open_read(apr_file_t **fd, const char *f, apr_pool_t *mp)
{
  return ns_file_open(fd, f, APR_READ, mp);
}

apr_status_t ns_file_open_append(apr_file_t **fd, const char *f, apr_pool_t *mp)
{
  return ns_file_open(fd, f, APR_WRITE | APR_CREATE | APR_APPEND, mp);
}

apr_status_t ns_file_open_truncate(apr_file_t **fd, const char *f,
                                   apr_pool_t *mp)
{
  return ns_file_open(fd, f, APR_WRITE | APR_CREATE | APR_TRUNCATE, mp);
}

apr_size_t ns_file_write(apr_file_t *fd, const char *buf, apr_size_t l)
{
  apr_size_t rv = 0;
  if (fd && buf && (l > 0)) {
    apr_status_t st = apr_file_write_full(fd, buf, l, &rv);
    if (st != APR_SUCCESS) {
      rv = 0;
    }
  }
  return rv;
}

apr_size_t ns_file_read(apr_pool_t *mp, apr_file_t *fd, void **buf)
{
  apr_size_t rv = 0;
  if (mp && fd && buf) {
    apr_finfo_t finfo;
    apr_status_t st = apr_file_info_get(&finfo, APR_FINFO_NORM, fd);
    apr_size_t fsize = 0;
    if (st == APR_SUCCESS) {
      fsize = (apr_size_t)finfo.size;
    }
    if (fsize <= 0) {
      *buf = NULL;
    } else {
      if (fsize > NS_MAX_READ_BUFFER) {
        fsize = NS_MAX_READ_BUFFER;
      }
      *buf = (void*)apr_palloc(mp, fsize);
      if (buf) {
        st = apr_file_read_full(fd, *buf, fsize, &rv);
      }
    }
  }
  return rv;
}

apr_status_t ns_file_close(apr_file_t *fd)
{
  return apr_file_close(fd);
}

apr_time_t ns_timestamp(int year, int month, int day, int hour,
                        int minute, int second)
{
  if (year == 0 && month == 0 && day == 0 && hour == 0 && minute == 0 && second == 0) {
    return apr_time_now();
  }
  if (year < 1970 || year > 2100 || month < 1 || month > 12 || day < 1 || day > 31 ||
    hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
    return NS_ERROR_TIMESTAMP;
  }
  apr_time_exp_t timeExp;
  apr_time_t currentTime = apr_time_now(); // Ottieni il tempo corrente
  apr_time_exp_gmt(&timeExp, currentTime); // Inizializza la struttura con il tempo corrente
  timeExp.tm_year = year - 1900;  // Anno - 1900
  timeExp.tm_mon = month - 1;    // Mese (da 0 a 11)
  timeExp.tm_mday = day;         // Giorno del mese
  timeExp.tm_hour = hour;        // Ora del giorno
  timeExp.tm_min = minute;       // Minuto
  timeExp.tm_sec = second;       // Secondo
  timeExp.tm_usec = 0;           // Microsecondo
  apr_time_t unixTime;
  apr_time_exp_gmt_get(&unixTime, &timeExp);
  return unixTime;
}

apr_time_t ns_now()
{
  return ns_timestamp(0, 0, 0, 0, 0, 0);
}

apr_table_entry_t* ns_table_entry(apr_table_t *t, int i)
{
  return (t != NULL) && (i >= 0) && (i < (apr_table_elts(t))->nelts)
    ? &((apr_table_entry_t*)((apr_table_elts(t))->elts))[i]
    : NULL;
}

// Legge i dati dallo standard input e li restituisce come una stringa.
// 'm' è il pool di memoria da utilizzare per l'allocazione di eventuali risorse.
char* ns_pipein(apr_pool_t *mp)
{
  char *rv = NULL;
  char buf[NS_MAX_READ_BUFFER] = {0};
  apr_size_t l;
  apr_file_t *fd;
  apr_size_t bytes = NS_MAX_READ_BUFFER - 1;
  apr_status_t st = apr_file_open_stdin(&fd, mp);
  if (st == APR_SUCCESS) {
    st = apr_file_read(fd, buf, &bytes);
  }
  if (st == APR_SUCCESS) {
    if (bytes > 0) {
      rv = (char*)apr_palloc(mp, bytes + 1);
    }
    if (rv) {
      memcpy(rv, buf, bytes);
      rv[bytes] = '\0';
    }
    apr_file_close(fd);
  }
  return rv;
}

char* ns_env(const char *e, apr_pool_t *mp)
{
  char *rv;
  return mp && e && (apr_env_get(&rv, e, mp) == APR_SUCCESS) ? rv : NULL;
}

void ns_daemonize()
{
  pid_t pid, sid;
  pid = fork();
  if (pid < 0) {
    perror("Fork failed");
    exit(1);
  }
  if (pid > 0) {
    exit(0);
  }
  sid = setsid();
  if (sid < 0) {
    perror("Error creating new session");
    exit(1);
  }
  pid = fork();
  if (pid < 0) {
    perror("Second fork failed");
    exit(1);
  }
  if (pid > 0) {
    exit(0);
  }
  if (chdir("/") < 0) {
    perror("Error changing working directory");
    exit(1);
  }
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}

/*
 * JSON
 */

ns_json_pair_t* ns_json_pair_init(apr_pool_t *mp) {
  ns_json_pair_t *ret = NULL;
  if (mp != NULL) {
    if ((ret = (ns_json_pair_t*)apr_palloc(mp, sizeof(ns_json_pair_t))) != NULL) {
      //ret->pool = mp;
      ret->key = NULL;
      ret->val = NULL;
      ret->type = NS_JSON_T_ZERO;
    }
  }
  return ret;
}

ns_json_object_t* ns_json_object_init(apr_pool_t *mp) {
  return (ns_json_object_t*)apr_array_make(mp, 0, sizeof(ns_json_pair_t*));
}

int ns_json_object_add(apr_pool_t *mp, ns_json_object_t *jo, ns_json_type_t tp,
                       const char *k, void *v)
{
  int ret = 0;
  ns_json_pair_t *entry;
  if ((mp != NULL) && (jo != NULL) && (tp >= 0)) {
    if ((entry = ns_json_pair_init(mp)) != NULL) {
      entry->key = k;
      entry->val = v;
      entry->type = tp;
      APR_ARRAY_PUSH(jo, ns_json_pair_t*) = entry;
      ret = 1;
    }
  }
  return ret;
}

ns_json_type_t ns_int_type(apr_int64_t v)
{
  if (v < APR_INT32_MIN) {
    return NS_JSON_T_INT64;
  } else if (v < APR_INT16_MIN) {
    return NS_JSON_T_INT32;
  } else if (v <= APR_INT16_MAX) {
    return NS_JSON_T_INT16;
  } else if (v <= APR_UINT16_MAX) {
    return NS_JSON_T_UINT16;
  } else if (v <= APR_INT32_MAX) {
    return NS_JSON_T_INT32;
  } else if (v <= APR_UINT32_MAX) {
    return NS_JSON_T_UINT32;
  } else if (v < APR_INT64_MAX) {
    return NS_JSON_T_INT64;
  } else {
    return NS_JSON_T_ZERO;
  }
}

ns_json_pair_t* ns_json_array_entry_make(apr_pool_t *mp, int type,
                                         const char *key, json_object *val)
{
  ns_json_pair_t *entry = ns_json_pair_init(mp);
  entry->key = key != NULL ? apr_pstrdup(mp, key) : NULL;
  // Eseguo lo switch dei tipi predefiniti di json-c
  switch (type) {
    case json_type_null: {
      entry->type = NS_JSON_T_NULL;
      entry->val = NULL;
    } break;
    case json_type_boolean:{
      entry->type = NS_JSON_T_BOOLEAN;
      entry->val = (void*)apr_palloc(mp, sizeof(char));
      *((char*)entry->val) = json_object_get_boolean(val);
    } break;
    case json_type_double: {
      entry->type = NS_JSON_T_DOUBLE;
      entry->val = (void*)apr_palloc(mp, sizeof(double));
      *((double*)entry->val) = json_object_get_double(val);
    } break;
    case json_type_int: {
      apr_uint64_t tmp_u = 0;
      apr_int64_t tmp_i = (apr_int64_t)json_object_get_int64(val);
      ns_json_type_t int_type = ns_int_type(tmp_i);
      if (!int_type) {
        tmp_u = (apr_uint64_t)json_object_get_uint64(val);
        if (tmp_u > APR_INT64_MAX) {
          int_type = NS_JSON_T_UINT64;
        } else {
          int_type = NS_JSON_T_INT64;
        }
      }
      if (int_type == NS_JSON_T_INT16) {
        entry->type = NS_JSON_T_INT16;
        entry->val = (void*)apr_palloc(mp, sizeof(apr_int16_t));
        *((apr_int16_t*)entry->val) = (apr_int16_t)tmp_i;
      } else if (int_type == NS_JSON_T_UINT16) {
        entry->type = NS_JSON_T_UINT16;
        entry->val = (void*)apr_palloc(mp, sizeof(apr_uint16_t));
        *((apr_uint16_t*)entry->val) = (apr_uint16_t)tmp_i;
      } else if (int_type == NS_JSON_T_INT32) {
        entry->type = NS_JSON_T_INT32;
        entry->val = (void*)apr_palloc(mp, sizeof(apr_int32_t));
        *((apr_int32_t*)entry->val) = (apr_int32_t)tmp_i;
      } else if (int_type == NS_JSON_T_UINT32) {
        entry->type = NS_JSON_T_UINT32;
        entry->val = (void*)apr_palloc(mp, sizeof(apr_uint32_t));
        *((apr_uint32_t*)entry->val) = (apr_uint32_t)tmp_i;
      } else if (int_type == NS_JSON_T_INT64) {
        entry->type = NS_JSON_T_INT64;
        entry->val = (void*)apr_palloc(mp, sizeof(apr_int64_t));
        *((apr_int64_t*)entry->val) = (apr_int64_t)tmp_i;
      } else if (int_type == NS_JSON_T_UINT64) {
        entry->type = NS_JSON_T_UINT64;
        entry->val = (void*)apr_palloc(mp, sizeof(apr_uint64_t));
        *((apr_uint64_t*)entry->val) = (apr_uint64_t)tmp_u;
      }
    } break;
    case json_type_string: {
      entry->type = NS_JSON_T_STRING;
      entry->val = (void*)apr_pstrdup(mp, (const char*)json_object_get_string(val));
    } break;
  }
  return entry;
}

apr_array_header_t* ns_json_parse(apr_pool_t *mp, json_object *jobj);

apr_array_header_t* ns_json_parse_array(apr_pool_t *mp, json_object *jarr)
{
  int jarr_l;
  enum json_type type;
  //, *jtmp; è stata sostituita dalla seguente riga:
  json_object *jval; 
  ns_json_pair_t *entry;
  apr_array_header_t *res = NULL;
  jarr_l = json_object_array_length(jarr);
  for (int i = 0; i < jarr_l; i ++) {
    jval = json_object_array_get_idx(jarr, i);
    type = json_object_get_type(jval);
    if (type == json_type_array) {
      entry = ns_json_pair_init(mp);
      entry->type = NS_JSON_T_ARRAY;
      entry->key = NULL;
      entry->val = (void*)ns_json_parse_array(mp, jval);
    } else if (type == json_type_object) {
      //entry = (ns_json_pair_t*)apr_palloc(mp, sizeof(ns_json_pair_t));
      entry = ns_json_pair_init(mp);
      entry->type = NS_JSON_T_OBJECT;
      entry->key = NULL;
      entry->val = (void*)ns_json_parse(mp, jval);
    } else {
      entry = ns_json_array_entry_make(mp, type, NULL, jval);
    }
    if (res == NULL) res = apr_array_make(mp, 0, sizeof(ns_json_pair_t*));
    APR_ARRAY_PUSH(res, ns_json_pair_t*) = entry;
  }
  return res;
}

apr_array_header_t* ns_json_parse(apr_pool_t *mp, json_object *jobj)
{
  ns_json_pair_t *entry = NULL;
  apr_array_header_t *res = NULL;
  enum json_type type;
  json_object *jtmp;
  json_object_object_foreach(jobj, key, val) {
    type = json_object_get_type(val);
    switch (type) {
      case json_type_object: {
        if (json_object_object_get_ex(jobj, key, &jtmp)) {
          entry = ns_json_pair_init(mp);
          entry->type = NS_JSON_T_OBJECT;
          entry->key = apr_pstrdup(mp, key);
          entry->val = (void*)ns_json_parse(mp, jtmp);
        }
      } break;
      case json_type_array: {
        if (json_object_object_get_ex(jobj, key, &jtmp)) {
          entry = ns_json_pair_init(mp);
          entry->type = NS_JSON_T_ARRAY;
          entry->key = apr_pstrdup(mp, key);
          entry->val = (void*)ns_json_parse_array(mp, jtmp);
        }
      } break;
      default: {
        entry = ns_json_array_entry_make(mp, type, key, val);
      } break;
    }
    if (res == NULL) res = apr_array_make(mp, 0, sizeof(ns_json_pair_t*));
    APR_ARRAY_PUSH(res, ns_json_pair_t*) = entry;
  }
  return res;
}

apr_array_header_t* ns_json_decode(apr_pool_t *mp, const char *s)
{
  json_object *jobj;
  apr_array_header_t* ret;
  jobj = json_tokener_parse(s);
  ret = ns_json_parse(mp, jobj);
  json_object_put(jobj);
  return ret;
}

const char* ns_json_encode(apr_pool_t *mp, const void *v, ns_json_type_t tp)
{
  int len;
  apr_table_entry_t *e;
  apr_table_t *t;
  ns_json_pair_t *p;
  // Dichiaro 2 array temporanei
  apr_array_header_t *obj, *arr = NULL;
  // Inizializzo il valore di ritorno
  const char *ret = NULL;
  // Verifico che la memoria sia allocata e il tipo di dato specificato
  if (mp != NULL && tp) {
    if (v == NULL || tp == NS_JSON_T_NULL) {
      // Il dato è una primitiva NULL
      ret = apr_pstrdup(mp, NS_JSON_NULL_S);
    } else if (tp == NS_JSON_T_BOOLEAN) {
      // Il dato è una primitiva booleana
      ret = apr_pstrdup(mp, *(char*)v ? NS_JSON_TRUE_S : NS_JSON_FALSE_S);
    } else if (tp == NS_JSON_T_INT16) {
      // Il dato è una primitiva intera
      ret = apr_psprintf(mp, "%hd", *((apr_int16_t*)v));
    } else if (tp == NS_JSON_T_UINT16) {
      // Il dato è una primitiva intera
      ret = apr_psprintf(mp, "%hu", *((apr_uint16_t*)v));
    } else if (tp == NS_JSON_T_INT32) {
      // Il dato è una primitiva intera
      ret = apr_psprintf(mp, "%d", *((apr_int32_t*)v));
    } else if (tp == NS_JSON_T_UINT32) {
      // Il dato è una primitiva intera
      ret = apr_psprintf(mp, "%u", *((apr_uint32_t*)v));
    } else if (tp == NS_JSON_T_INT64) {
      // Il dato è una primitiva intera
      ret = apr_psprintf(mp, "%" APR_INT64_T_FMT, *((apr_int64_t*)v));
    } else if (tp == NS_JSON_T_UINT64) {
      // Il dato è una primitiva intera
      ret = apr_psprintf(mp, "%" APR_UINT64_T_FMT, *((apr_uint64_t*)v));
    } else if (tp == NS_JSON_T_DOUBLE) {
      // Il dato è una primitiva double
      ret = apr_psprintf(mp, "%0.8lf", *(double*)v);
    } else if (tp == NS_JSON_T_STRING) {
      // Il dato è una stringa
      ret = apr_psprintf(mp, "\"%s\"", apr_pescape_echo(mp, (const char*)v, 1));
    } else if (tp == NS_JSON_T_JSON) {
      // Il dato è una stringa JSON pre-codificata
      ret = apr_psprintf(mp, "%s", (const char*)v);
    } else if (tp == NS_JSON_T_TIMESTAMP) {
      // Il dato è un apr_time_t
      ret = apr_psprintf(mp, "%" APR_TIME_T_FMT, (apr_time_t)v);
    } else if (tp > NS_JSON_T_VECTOR) {
      // Il dato è un vettore di elementi di tipo (tp - NS_JSON_T_VECTOR)
      // La funzione si aspetta un vettore di primitive o di stringhe
      int type = tp - NS_JSON_T_VECTOR;
      // Un vettore è una struttura apr_array_header_t di dati dello stesso tipo
      obj = (apr_array_header_t*)v;
      // Verifico che la struttura non sia vuota
      if (obj->nelts > 0) {
        if (arr == NULL) {
          // Alloco un array temporaneo per gli elementi del vettore
          arr = apr_array_make(mp, 1, sizeof(const char*));
        }
        if (arr != NULL) {
          // Ripeto per ogni elemento del vettore
          for (int i = 0; i < obj->nelts; i ++) {
            switch (type) {
              case NS_JSON_T_NULL: {
                // Aggiungo all'array temporaneo una stringa null
                APR_ARRAY_PUSH(arr, const char*) = apr_pstrdup(mp, NS_JSON_NULL_S);
              } break;
              case NS_JSON_T_BOOLEAN: {
                // Estraggo il intero
                int entry = APR_ARRAY_IDX(obj, i, int);
                // Aggiungo all'array temporaneo una stringa true o false
                APR_ARRAY_PUSH(arr, const char*) = apr_pstrdup(mp, entry ? NS_JSON_TRUE_S : NS_JSON_FALSE_S);
              } break;
              case NS_JSON_T_INT16: {
                // Estraggo il valore intero
                apr_int16_t entry = APR_ARRAY_IDX(obj, i, apr_int16_t);
                // Aggiungo all'array temporaneo il valore intero
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%hd", entry);
              } break;
              case NS_JSON_T_UINT16: {
                // Estraggo il valore intero
                apr_uint16_t entry = APR_ARRAY_IDX(obj, i, apr_uint16_t);
                // Aggiungo all'array temporaneo il valore intero
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%hu", entry);
              } break;
              case NS_JSON_T_INT32: {
                // Estraggo il valore intero
                apr_int32_t entry = APR_ARRAY_IDX(obj, i, apr_int32_t);
                // Aggiungo all'array temporaneo il valore intero
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%d", entry);
              } break;
              case NS_JSON_T_UINT32: {
                // Estraggo il valore intero
                apr_uint32_t entry = APR_ARRAY_IDX(obj, i, apr_uint32_t);
                // Aggiungo all'array temporaneo il valore intero
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%u", entry);
              } break;
              case NS_JSON_T_INT64: {
                // Estraggo il valore intero
                apr_int64_t entry = APR_ARRAY_IDX(obj, i, apr_int64_t);
                // Aggiungo all'array temporaneo il valore intero
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%" APR_INT64_T_FMT, entry);
              } break;
              case NS_JSON_T_UINT64: {
                // Estraggo il valore intero
                apr_uint64_t entry = APR_ARRAY_IDX(obj, i, apr_uint64_t);
                // Aggiungo all'array temporaneo il valore intero
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%" APR_UINT64_T_FMT, entry);
              } break;
              case NS_JSON_T_DOUBLE: {
                // Estraggo il valore double
                double entry = APR_ARRAY_IDX(obj, i, double);
                // Aggiungo all'array temporaneo il valore double
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%0.8lf", entry);
              } break;
              case NS_JSON_T_STRING: {
                // Estraggo il valore stringa
                // ------------------------------------------------------------
                // FIXME: deve essere eseguito l'escape della stringa estratta
                //        prima che venga aggiunta all'array temporaneo
                // ------------------------------------------------------------
                const char *entry = APR_ARRAY_IDX(obj, i, const char*);
                // Aggiungo all'array temporaneo il valore stringa
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\"", apr_pescape_echo(mp, entry, 1));
              } break;
              case NS_JSON_T_JSON: {
                const char *entry = APR_ARRAY_IDX(obj, i, const char*);
                // Aggiungo all'array temporaneo il valore stringa JSON
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%s", entry);
              } break;
              case NS_JSON_T_TIMESTAMP: {
                // Estraggo il valore apr_time_t
                apr_time_t entry = APR_ARRAY_IDX(obj, i, apr_time_t);
                // Aggiungo all'array temporaneo il valore apr_time_t
                APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "%" APR_TIME_T_FMT, entry);
              } break;
              case NS_JSON_T_TABLE: {
                apr_table_t *entry = APR_ARRAY_IDX(obj, i, apr_table_t*);
                APR_ARRAY_PUSH(arr, const char*) =
                  //apr_psprintf(mp, "\"%s\"", apr_pescape_echo(mp, entry, 1));
                  ns_json_encode(mp, (const void*)entry, NS_JSON_T_TABLE);
              } break;
            }
          }
          // Al termine del ciclo for se l'array temporaneo non è vuoto
          // setto il valore di ritorno con la sua versione serializzata
          // in caso contrario il valore di ritorno contiene ancora NULL
          if (arr->nelts > 0) {
            const char *tmp_s = ns_join(mp, arr, ",");
            if (tmp_s != NULL) {
              ret = apr_psprintf(mp, "[%s]", tmp_s);
            }
            // @todo else
          }
        }
      }
    } else if (tp == NS_JSON_T_TABLE) {
      t = (apr_table_t*)v;
      if (t && (len = (apr_table_elts(t))->nelts)) {
        if ((arr = apr_array_make(mp, len, sizeof(const char*)))) {
          for (int i = 0; i < len; i ++) {
            if ((e = &((apr_table_entry_t*)((apr_table_elts(t))->elts))[i])) {
              APR_ARRAY_PUSH(arr, const char*) =
                apr_psprintf(mp, "\"%s\":\"%s\"", (const char*)e->key,
                             apr_pescape_echo(mp, (const char*)e->val, 1));
            }
          }
          if (arr->nelts > 0) {
            const char *tmp_s = ns_join(mp, arr, ",");
            if (tmp_s != NULL) {
              ret = apr_psprintf(mp, "{%s}", tmp_s);
            }
          }
        }
      }
    } else if (tp == NS_JSON_T_OBJECT) {
      // Il dato è un oggetto (ovvero un array associativo)
      // Un oggetto è una struttura apr_array_header_t di ns_json_pair_t
      // La struttura ns_json_pair_t contiene informazioni anche sul tipo di dato
      // La funzione richiede che le chiavi dei pair dell'array non siano NULL
      // altrimenti l'elemento non verrà aggiunto all'array temporaneo
      obj = (apr_array_header_t*)v;
      // Verifico che l'oggetto non sia vuoto
      if (obj->nelts > 0) {
        // Alloco un array temporaneo per gli elementi dell'oggetto
        if ((arr = apr_array_make(mp, 1, sizeof(const char*))) != NULL) {
          // Ripeto per ogni elemento dell'oggetto
          for (int i = 0; i < obj->nelts; i++) {
            // Estraggo il prossimo pair
            if ((p = APR_ARRAY_IDX(obj, i, ns_json_pair_t*)) != NULL) {
              if (!p->key) continue;
              switch (p->type) {
                case NS_JSON_T_NULL: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore null
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%s", p->key, NS_JSON_NULL_S);
                } break;
                case NS_JSON_T_BOOLEAN: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore boolean
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%s", p->key, *(char*)p->val ? NS_JSON_TRUE_S : NS_JSON_FALSE_S);
                } break;
                case NS_JSON_T_INT16: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore integer
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%hd", p->key, *(apr_int16_t*)p->val);
                } break;
                case NS_JSON_T_UINT16: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore integer
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%hu", p->key, *(apr_uint16_t*)p->val);
                } break;
                case NS_JSON_T_INT32: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore integer
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%d", p->key, *(apr_int32_t*)p->val);
                } break;
                case NS_JSON_T_UINT32: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore integer
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%u", p->key, *(apr_uint32_t*)p->val);
                } break;
                case NS_JSON_T_INT64: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore integer
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%" APR_INT64_T_FMT, p->key, *(apr_int64_t*)p->val);
                } break;
                case NS_JSON_T_UINT64: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore integer
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%" APR_UINT64_T_FMT, p->key, *(apr_uint64_t*)p->val);
                } break;
                case NS_JSON_T_TIMESTAMP: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore timestamp
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%" APR_TIME_T_FMT, p->key, *(apr_time_t*)p->val);
                } break;
                case NS_JSON_T_DOUBLE: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore double
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%0.8lf", p->key, *(double*)p->val);
                } break;
                case NS_JSON_T_STRING: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore string
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":\"%s\"", p->key, apr_pescape_echo(mp, (const char*)p->val, 1));
                } break;
                case NS_JSON_T_JSON: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore string JSON
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%s", p->key, (const char*)p->val);
                } break;
                case NS_JSON_T_OBJECT: {
                  // Aggiungo all'array temporaneo una coppia chiave/valore object
                  APR_ARRAY_PUSH(arr, const char*) = apr_psprintf(mp, "\"%s\":%s", p->key, ns_json_encode(mp, p->val, NS_JSON_T_OBJECT));
                } break;
                default: break;
              }
            }
          }
          if (arr->nelts > 0) {
            const char *tmp_s = ns_join(mp, arr, ",");
            if (tmp_s != NULL) {
              ret = apr_psprintf(mp, "{%s}", tmp_s);
            }
          }
        }
      }
    }
  }
  return ret;
}

/*
 * LOGGER
 */

ns_logger_t* ns_log_alloc(apr_pool_t *mp, apr_proc_mutex_t *m, const char *f,
                          apr_size_t sz)
{
  ns_logger_t *ret = (ns_logger_t*)apr_palloc(mp, sizeof(ns_logger_t));
  if (ret != NULL) {
    ret->pool = mp;
    ret->fname = f;
    ret->mutex = m;
    ret->max_size = sz ? sz : NS_LOG_MAX_FILE_SIZE;
    apr_status_t st = ns_file_open_append(&(ret->fh), f, mp);
    if (st != APR_SUCCESS) {
      return NULL;
    }
    ns_log_rotate(ret);
  }
  return ret;
}

void ns_log_rotate(ns_logger_t *l)
{
  apr_finfo_t finfo;
  // Estraggo i metadati del file di log corrente
  apr_status_t rv = apr_file_info_get(&finfo, APR_FINFO_SIZE, l->fh);
  if (rv != APR_SUCCESS) {
    return;
  }
  // Estraggo la dimensione del file di log corrente
  apr_off_t sz = finfo.size;
  // Se la dimensione del file corrente è inferiore a quella massima termino
  if (sz < l->max_size) {
    return;
  }
  // Genero un nome di file per il file di log originale
  // con il timestamp unix corrente per non sovrascrivere file precedenti
  apr_time_t ts = ns_now();
  if (ts <= 0) {
    return;
  }
  const char *ts_s = apr_psprintf(l->pool, "%" APR_INT64_T_FMT, ts);
  if (ts_s == NULL) {
    return;
  }
  char *fname_old = apr_psprintf(l->pool, "%s_%s.old", l->fname, ts_s);
  if (fname_old == NULL) {
    return;
  }
  // Rinomino il file l->fname in fname_old
  // l->fh adesso punta al file fname_old pertanto le operazioni di
  // scrittura vengono registrate ancora sul file originale rinominato
  rv = apr_file_rename(l->fname, fname_old, l->pool);
  if (rv != APR_SUCCESS) {
    return;
  }
  // Apro un nuovo file con il nome l->fname
  // fh_new e l->fh non puntano allo stesso file
  apr_file_t *fh_new;
  rv = ns_file_open_truncate(&fh_new, l->fname, l->pool);
  if (rv != APR_SUCCESS) {
    // Provo a ripristinare il nome del file di ol originale
    apr_file_rename(fname_old, l->fname, l->pool);
    return;
  }
  // Scrivo '--log-rotate' sul file originale ancora puntato da l->fh
  int w_size = apr_file_printf(l->fh, "--log-rotate\r\n");
  if (w_size <= 0) {
    // Provo a ripristinare il nome del file di ol originale
    apr_file_rename(fname_old, l->fname, l->pool);
    return;
  }
  // Copio il descrittore di fh_new in l->fh
  // Da questo momento le oprazioni di scrittura usano sul nuovo file
  // l->fh e fh_new contengono 2 copie dello stesso descrittore
  rv = apr_file_dup2(l->fh, fh_new, l->pool);
  if (rv != APR_SUCCESS) {
    // Provo a ripristinare il nome del file di ol originale
    apr_file_rename(fname_old, l->fname, l->pool);
    return;
  }
  // Chiudo la copia del descrittore di file in fh_new
  apr_file_close(fh_new);
}

void ns_log_destroy(ns_logger_t *l)
{
  if (l != NULL) {
    if (l->fh != NULL) {
      apr_file_close(l->fh);
      l->fh = NULL;
    }
    l = NULL;
  }
}

/*
 * DBD
 */

ns_dbd_t* ns_dbd_alloc(apr_pool_t *mp)
{
  ns_dbd_t *ret = NULL;
  if (mp != NULL) {
    if ((ret = (ns_dbd_t*)apr_palloc(mp, sizeof(ns_dbd_t))) != NULL) {
      ret->drv = NULL;
      ret->hdl = NULL;
      ret->er_msg = NULL;
      ret->trx = NULL;
      ret->err = 0;
    }
  }
  return ret;
}

int ns_dbd_open(apr_pool_t *mp, ns_dbd_t *d, const char *s, const char *c)
{
  int ret = 0;
  apr_status_t rv;
  d->er_msg = NULL;
  d->drv = NULL;
  d->hdl = NULL;
  d->err = 0;
  if (mp && d) {
    rv = apr_dbd_get_driver(mp, s, &(d->drv));
  }
  if (rv == APR_SUCCESS) {
    rv = apr_dbd_open_ex(d->drv, mp, c, &(d->hdl), &(d->er_msg));
  }
  ret = rv == APR_SUCCESS;
  if (!ret) {
    d->drv = NULL;
    d->hdl = NULL;
    d->err = 1;
  }
  return ret;
}

const char* ns_dbd_escape(apr_pool_t *mp, ns_dbd_t *d, const char *s)
{
  return ((mp == NULL) || (d == NULL) || (s == NULL))
    ? NULL
    : apr_dbd_escape(d->drv, mp, s, d->hdl);
}

int ns_dbd_query(apr_pool_t *mp, ns_dbd_t *d, const char *sql)
{
  int aff_rows = 0;
  if (mp == NULL || d == NULL || sql == NULL) return -1;
  d->er_msg = NULL;
  d->err = apr_dbd_query(d->drv, d->hdl, &aff_rows, sql);
  if (d->err) {
    d->er_msg = apr_pstrdup(mp, apr_dbd_error(d->drv, d->hdl, d->err));
    return -1;
  }
  return aff_rows;
}

int ns_dbd_transaction_start(apr_pool_t *mp, ns_dbd_t *dbd)
{
  int rv = 1;
  const char *error;
  if ((mp != NULL) && (dbd != NULL)) {
    if ((rv = apr_dbd_transaction_start(dbd->drv, mp, dbd->hdl, &(dbd->trx)))) {
      if ((error = apr_dbd_error(dbd->drv, dbd->hdl, rv)) != NULL) {
        dbd->er_msg = apr_pstrdup(mp, error);
      }
    }
  }
  return (rv == 0 ? 0 : -1);
}

int ns_dbd_transaction_end(apr_pool_t *mp, ns_dbd_t *dbd)
{
  int rv = 1;
  const char *error;
  if ((mp != NULL) && (dbd != NULL)) {
    if ((rv = apr_dbd_transaction_end(dbd->drv, mp, dbd->trx))) {
      if ((error = apr_dbd_error(dbd->drv, dbd->hdl, rv)) != NULL) {
        dbd->er_msg = apr_pstrdup(mp, error);
      }
    }
  }
  return (rv == 0 ? 0 : -1);
}

apr_array_header_t* ns_dbd_result_to_array(apr_pool_t *mp, ns_dbd_t *dbd,
                                           apr_dbd_results_t *res)
{
  apr_table_t *rec;
  apr_dbd_row_t *row = NULL;
  apr_array_header_t *rset = NULL;
  const char *k, *v;
  int rv, first_rec, num_fields;
  if ((mp != NULL) && (dbd != NULL) && (res != NULL)) {
    if ((rv = apr_dbd_get_row(dbd->drv, mp, res, &row, -1)) != -1) {
      first_rec = 1;
      while (rv != -1) {
        if (first_rec) {
          num_fields = apr_dbd_num_cols(dbd->drv, res);
          rset = apr_array_make(mp, num_fields, sizeof(apr_table_t*));
          first_rec = 0;
        }
        rec = apr_table_make(mp, num_fields);
        for (int i = 0; i < num_fields; i++) {
          k = apr_dbd_get_name(dbd->drv, res, i);
          v = apr_dbd_get_entry(dbd->drv, row, i);
          apr_table_set(rec, apr_pstrdup(mp, k),
                        apr_pstrdup(mp, ns_is_empty(v) ? "NULL" : v));
        }
        APR_ARRAY_PUSH(rset, apr_table_t*) = rec;
        rv = apr_dbd_get_row(dbd->drv, mp, res, &row, -1);
      }
    }
  }
  return rset;
}

int ns_dbd_prepared_query(apr_pool_t *mp, ns_dbd_t *dbd, const char *sql,
                          apr_table_t *args)
{
  apr_table_entry_t *arg;
  const char **args_ar, *err;
  apr_dbd_prepared_t *stmt = NULL;
  int aff_rows = 0, nelts, rv;
  if (mp != NULL && dbd != NULL && sql != NULL) {
    dbd->er_msg = NULL;
    if ((nelts = apr_table_elts(args)->nelts) > 0) {
      args_ar = (const char**)apr_palloc(mp, sizeof(const char*)*nelts);
      if (args_ar != NULL) {
        for (int i = 0; i < nelts; i++) {
          arg = ns_table_entry(args, i);
          if (arg != NULL) {
            args_ar[i] = apr_pstrdup(mp, arg->val);
            if (args_ar[i] == NULL) {
              return -1;
            }
          }
        }
        dbd->err = apr_dbd_prepare(dbd->drv, mp, dbd->hdl, sql, NULL, &stmt);
        if (dbd->err) {
          err = apr_dbd_error(dbd->drv, dbd->hdl, dbd->err);
          dbd->er_msg = apr_pstrdup(mp, err);
          return -1;
        }
        dbd->err = apr_dbd_pquery(dbd->drv, mp, dbd->hdl, &aff_rows, stmt, nelts,
                                  args_ar);
        if (dbd->err) {
          err = apr_dbd_error(dbd->drv, dbd->hdl, dbd->err);
          dbd->er_msg = apr_psprintf(mp, "%s", err);
          return -1;
        }
      }
    }
  }
  return aff_rows;
}

// int ns_dbd_prepared_query(apr_pool_t *mp, ns_dbd_t *dbd,
//                           const char *sql, const char **args, int sz) {
  
//   const char *err;
//   apr_dbd_prepared_t *stmt = NULL;
//   int aff_rows = 0, rv;
//   if (mp != NULL && dbd != NULL && sql != NULL && args != NULL && sz > 0) {
//     dbd->er_msg = NULL;
//     rv = apr_dbd_prepare(dbd->drv, mp, dbd->hdl, sql, NULL, &stmt);
//     if (rv) {
//       err = apr_dbd_error(dbd->drv, dbd->hdl, rv);
//       dbd->er_msg = apr_pstrdup(mp, err);
//       return -1;
//     }
//     rv = apr_dbd_pquery(dbd->drv, mp, dbd->hdl, &aff_rows, stmt, sz, args);
//     if (rv) {
//       err = apr_dbd_error(dbd->drv, dbd->hdl, rv);
//       dbd->er_msg = apr_psprintf(mp, "%s", err);
//       return -1;
//     }
//   }
//   return aff_rows;
// }

apr_array_header_t* ns_dbd_prepared_select(apr_pool_t *mp, ns_dbd_t *dbd,
                                           const char *sql, apr_table_t *args)
{
  int rv, nelts;
  apr_dbd_results_t *res = NULL;
  apr_array_header_t *rset = NULL;
  char **args_ar;
  const char *err;
  apr_table_entry_t *arg;
  apr_dbd_prepared_t *stmt = NULL;
  if ((mp != NULL) && (dbd != NULL) && (sql != NULL) && (args != NULL)) {
    if ((nelts = apr_table_elts(args)->nelts) > 0) {
      if ((args_ar = (char**)apr_palloc(mp, sizeof(char*)*nelts)) != NULL) {
        for (int i = 0; i < nelts; i++) {
          if ((arg = ns_table_entry(args, i)) != NULL) {
            if ((args_ar[i] = apr_psprintf(mp, "%s", arg->val)) == NULL) {
              return NULL;
            }
          }
        }
        rv = apr_dbd_prepare(dbd->drv, mp, dbd->hdl, sql, NULL, &stmt);
        if (rv) {
          err = apr_dbd_error(dbd->drv, dbd->hdl, rv);
          dbd->er_msg = apr_psprintf(mp, "%s", err);
          return NULL;
        }
        rv = apr_dbd_pselect(dbd->drv, mp, dbd->hdl, &res,
                             stmt, 0, nelts, (const char**)args_ar);
        if (rv) {
          err = apr_dbd_error(dbd->drv, dbd->hdl, rv);
          dbd->er_msg = apr_psprintf(mp, "%s", err);
          return NULL;
        }
        rset = ns_dbd_result_to_array(mp, dbd, res);
      }
    }
  }
  return rset;
}

apr_array_header_t* ns_dbd_select(apr_pool_t *mp, ns_dbd_t *d, const char *sql)
{
  int rv, err;
  apr_dbd_results_t *res = NULL;
  apr_dbd_row_t *row = NULL;
  apr_array_header_t *rset = NULL;
  apr_table_t *rec;
  const char *k, *v;
  int first_rec, num_fields;
  if ((mp != NULL) && (d != NULL) && (sql != NULL)) {
    d->er_msg = NULL;
    if ((err = apr_dbd_select(d->drv, mp, d->hdl, &res, sql, 0))) {
      d->er_msg = apr_pstrdup(mp, apr_dbd_error(d->drv, d->hdl, err));
    } else {
      if (res != NULL) {
        if ((rv = apr_dbd_get_row(d->drv, mp, res, &row, -1)) != -1) {
          rset = NULL;
          first_rec = 1;
          while (rv != -1) {
            if (first_rec) {
              num_fields = apr_dbd_num_cols(d->drv, res);
              rset = apr_array_make(mp, num_fields, sizeof(apr_table_t*));
              first_rec = 0;
            }
            rec = apr_table_make(mp, num_fields);
            for (int i = 0; i < num_fields; i++) {
              k = apr_dbd_get_name(d->drv, res, i);
              v = apr_dbd_get_entry(d->drv, row, i);
              apr_table_set(rec, apr_pstrdup(mp, k),
                            apr_pstrdup(mp, ns_is_empty(v) ? "NULL" : v));
            }
            APR_ARRAY_PUSH(rset, apr_table_t*) = rec;
            rv = apr_dbd_get_row(d->drv, mp, res, &row, -1);
          }
        }
      }
    }
  }
  return rset;
}

int ns_dbd_num_records(apr_array_header_t *r) {
  return (int)(r != NULL ? r->nelts : 0);
}

int ns_dbd_num_columns(apr_array_header_t *r) {
  int ret = 0;
  apr_table_t *rec;
  if (r && r->nelts) {
    if ((rec = APR_ARRAY_IDX(r, 0, apr_table_t*))) {
      ret = apr_table_elts(rec)->nelts;
    }
  }
  return ret;
}

apr_array_header_t* ns_dbd_column_names(apr_pool_t *mp, apr_array_header_t *r)
{
  int nelts;
  apr_table_entry_t* e;
  apr_table_t *rec;
  apr_array_header_t *ret = NULL;
  if (r != NULL && r->nelts) {
    if ((rec = APR_ARRAY_IDX(r, 0, apr_table_t*))) {
      if ((nelts = (apr_table_elts(rec)->nelts))) {
        if ((ret = apr_array_make(mp, nelts, sizeof(const char*)))) {
          for (int i = 0; i < nelts; i++) {
            if ((e = &((apr_table_entry_t*)((apr_table_elts(rec))->elts))[i])) {
              APR_ARRAY_PUSH(ret, const char*) = apr_pstrdup(mp, e->key);
            }
          }
        }
      }
    }
  }
  return ret;
}

apr_table_t* ns_dbd_record(apr_array_header_t *r, int i)
{
  return (r != NULL) && r->nelts && (i <= r->nelts-1)
    ? APR_ARRAY_IDX(r, i, apr_table_t*)
    : NULL;
}

const char* ns_dbd_field_value(apr_array_header_t *res, int i, const char *k)
{
  if (res == NULL || res->nelts <= 0 || i > (res->nelts-1)) return NULL;
  apr_table_t* rec = APR_ARRAY_IDX(res, i, apr_table_t*);
  return apr_table_get(rec, k);
}

int ns_dbd_field_set(apr_array_header_t *r, int i, const char *k, const char *v)
{
  if (r == NULL || r->nelts <= 0 || i > (r->nelts-1)) return 1;
  apr_table_t* t = APR_ARRAY_IDX(r, i, apr_table_t*);
  apr_table_set(t, k, v);
  return 0;
}

int ns_dbd_close(ns_dbd_t *d)
{
  return d == NULL ? 0 : apr_dbd_close(d->drv, d->hdl);
}

const char* ns_dbd_driver_name(ns_dbd_t *dbd)
{
  return dbd == NULL ? NULL : apr_dbd_name(dbd->drv);
}

const char* ns_dbd_error(ns_dbd_t *d)
{
  return (d == NULL) ? NULL : d->er_msg;
}

/*
 * HTTP REQUEST
 */

ns_http_request_t* ns_http_request_alloc(apr_pool_t *mp)
{
  ns_http_request_t *r;
  r = (ns_http_request_t*)apr_palloc(mp, sizeof(ns_http_request_t));
  if (r) {
    r->pool = mp;
    r->args = NULL;
    r->body = NULL;
    r->headers = apr_table_make(mp, 0);
    r->parsed_uri = apr_table_make(mp, 0);
    r->query = NULL;
    r->uri = NULL;
    r->message = NULL;
    r->multipart_data = NULL;
    r->cookies = apr_table_make(mp, 0);
    r->username = NULL;
    r->password = NULL;
  }
  return r;
}

apr_table_t *ns_http_request_validate_args(ns_http_request_t *r, ns_request_validator_t *vd, int nargs)
{
  int is_valid;
  const char *curr_v;
  apr_table_t *result = apr_table_make(r->pool, 10);
  if (r && r->args) {
    for (int i = 0; i < nargs; ++i) {
      ns_request_validator_t v = vd[i];
      curr_v = apr_table_get(r->args, v.key);
      if (curr_v == NULL) {
        continue;
      }
      is_valid = 0;
      if (v.type == NS_REQUEST_T_INT) {
        is_valid = ns_is_int(curr_v);
      } else if (v.type == NS_REQUEST_T_DOUBLE) {
        is_valid = ns_is_double(curr_v);
      } else if (v.type == NS_REQUEST_T_STRING) {
        is_valid = !ns_is_empty(curr_v);
      } else if (v.type == NS_REQUEST_T_PASSWORD) {
        is_valid = !ns_is_empty(curr_v);
      } else if (v.type == NS_REQUEST_T_DATE) { // yyyy-mm-dd
        if (!ns_is_empty(curr_v) && strlen(curr_v) == 10) {
          apr_array_header_t *curr_v_ar = ns_split(r->pool, curr_v, "-");
          if (curr_v_ar && curr_v_ar->nelts == 3) {
            const char *y = APR_ARRAY_IDX(curr_v_ar, 0, const char*);
            const char *m = APR_ARRAY_IDX(curr_v_ar, 1, const char*);
            const char *d = APR_ARRAY_IDX(curr_v_ar, 2, const char*);
            is_valid = strlen(y) == 4 && ns_is_int(y) &&
                       strlen(m) == 2 && ns_is_int(m) &&
                       strlen(d) == 2 && ns_is_int(d);
          }
        }
      }
      if (is_valid) {
        if (v.filter == NS_REQUEST_F_MD5) {
          curr_v = ns_md5(r->pool, curr_v);
        }
        apr_table_set(result, v.key, curr_v);
      }
    }
  }
  return result;
}

apr_table_t *ns_http_request_validate_multipart_args(ns_http_request_t *r, ns_request_validator_t *vd, int nargs)
{
  int is_valid;
  const char *req_v;
  apr_table_t *result = apr_table_make(r->pool, 10);
  for (int i = 0; i < nargs; ++i) {
    ns_request_validator_t v = vd[i];
    for (int j = 0; j < r->multipart_data->nelts; ++j) {
      apr_table_t *entry = APR_ARRAY_IDX(r->multipart_data, j, apr_table_t*);
      if (!entry) {
        continue;
      }
      const char *key = apr_table_get(entry, "name");
      if (!key || (strcmp(v.key, key) != 0)) {
        continue;
      }
      req_v = apr_table_get(entry, "value");
      if (!req_v) {
        continue;
      }
      is_valid = 0;
      if (v.type == NS_REQUEST_T_INT) {
        is_valid = ns_is_int(req_v);
      } else if (v.type == NS_REQUEST_T_DOUBLE) {
        is_valid = ns_is_double(req_v);
      } else if (v.type == NS_REQUEST_T_STRING) {
        is_valid = !ns_is_empty(req_v);
      } else if (v.type == NS_REQUEST_T_PASSWORD) {
        is_valid = !ns_is_empty(req_v);
      } else if (v.type == NS_REQUEST_T_DATE) { // yyyy-mm-dd
        if (!ns_is_empty(req_v) && strlen(req_v) == 10) {
          apr_array_header_t *req_v_ar = ns_split(r->pool, req_v, "-");
          if (req_v_ar && req_v_ar->nelts == 3) {
            const char *y = APR_ARRAY_IDX(req_v_ar, 0, const char*);
            const char *m = APR_ARRAY_IDX(req_v_ar, 1, const char*);
            const char *d = APR_ARRAY_IDX(req_v_ar, 2, const char*);
            is_valid = strlen(y) == 4 && ns_is_int(y) &&
                       strlen(m) == 2 && ns_is_int(m) &&
                       strlen(d) == 2 && ns_is_int(d);
          }
        }
      }
      if (is_valid) {
        if (v.filter == NS_REQUEST_F_MD5) {
          req_v = ns_md5(r->pool, req_v);
        }
        apr_table_set(result, v.key, req_v);
      }
    }
  }
  return result;
}

/*
 * HTTP RESPONSE
 */

ns_http_response_t* ns_http_response_alloc(apr_pool_t *mp)
{
  ns_http_response_t *r;
  r = (ns_http_response_t*)apr_palloc(mp, sizeof(ns_http_response_t));
  if (r) {
    r->pool = mp;
    r->headers = apr_table_make(mp, 0);
    r->status = 0;
    r->size = 0;
    r->buffer = NULL;
  }
  return r;
}

void ns_http_response_header_set(ns_http_response_t *r,
                                 const char *k, const char *v)
{
  apr_table_set(r->headers, k, v);
}

const char* ns_http_response_header_get(ns_http_response_t *r, const char *k)
{
  return apr_table_get(r->headers, k);
}

const char* ns_http_response_headers_serialize(ns_http_response_t *r)
{
  const char *result = NULL;
  int nelts = ns_table_nelts(r->headers);
  if (nelts > 0) {
    apr_table_entry_t *e;
    e = ns_table_entry(r->headers, 0);
    result = apr_psprintf(r->pool, "%s: %s\r\n", e->key, e->val);
    for (int i = 1; i < nelts; i++) {
      e = ns_table_entry(r->headers, i);
      if (e) {
        char *h = apr_psprintf(r->pool, "%s: %s\r\n", e->key, e->val);
        result = apr_pstrcat(r->pool, result, h, NULL);
      }
    }
  }
  return result;
}

void ns_http_response_buffer_set(ns_http_response_t *r, void *buf, size_t sz)
{
  r->size = sz;
  r->buffer = apr_palloc(r->pool, sz);
  if (r->buffer) {
    memcpy(r->buffer, buf, sz);
  }
}

/*
 * SERVICE
 */

ns_service_t* ns_alloc(apr_pool_t *mp)
{
  ns_service_t *s = apr_palloc(mp, sizeof(ns_service_t));
  if (s) {
    s->pool = mp;
    s->authorized = 0;
    s->er_msg = NULL;
    s->request = NULL;
    s->response = NULL;
    s->dbd = NULL;
    s->logger = NULL;
  }
  return s;
}

void ns_route(ns_service_t *s, const char *mth, const char *uri, ns_route_t fn)
{
  if (s->response->status <= 0) {
    if (strcmp(s->request->method, mth) == 0) {
      if (strcmp(s->request->uri, uri) == 0) {
        s->response->status = fn(s);
      }
    }
  }
}

// // Aggiunge una stringa formattata al buffer dell'output
// void ns_printf(ns_service_t *s, const char *fmt, ...)
// {
//   va_list args;
//   va_start(args, fmt);
//   char *s = apr_pvsprintf(s->pool, fmt, args);
//   va_end(args);
//   if (s != NULL) {
//     s->response->is_binary = 0;
//     if (s->response->buffer == NULL) {
//       // Inizializzo il body della response HTTP
//       s->response->buffer = apr_pstrdup(s->pool, s);
//     } else {
//       // Concateno la stringa al body della response HTTP
//       s->response->buffer = apr_pstrcat(s->pool, s->response->buffer, s, NULL);
//     }
//   }
// }




void ns_printf(ns_service_t *s, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  // Calcolo la lunghezza della stringa formattata
  apr_size_t len = vsnprintf(NULL, 0, fmt, args);
  va_end(args);
  if (len > 0) {
    // Allocazione la memoria per la stringa formattata
    char *buffer = (char*)apr_palloc(s->pool, len + 1);
    if (buffer) {
      // Creo la stringa formattata
      va_start(args, fmt);
      vsnprintf(buffer, len + 1, fmt, args);
      va_end(args);
      buffer[len+1] = '\0';
      s->response->is_binary = 0;
      if (s->response->buffer == NULL) {
        // Inizializzo il body della response HTTP
        s->response->buffer = apr_pstrdup(s->pool, buffer);
      } else {
        // Concateno la stringa al body della response HTTP
        s->response->buffer = apr_pstrcat(s->pool, s->response->buffer, buffer, NULL);
      }
      if (s->response->buffer) {
        s->response->size = strlen(s->response->buffer);
      }
    }
  }
}
