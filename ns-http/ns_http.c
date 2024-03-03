
#include "apr.h"
#include "apr_pools.h"
#include "apr_tables.h"
#include "apr_strings.h"
#include "apr_proc_mutex.h"
#include "apr_dbd.h"
#include "stdio.h"
#include "errno.h"
#include "time.h"
#include "syscall.h"
#include "unistd.h"
#include "stdlib.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "sys/file.h"
#include "string.h"
#include "signal.h"
#include "mongoose.h"
#include "ns_runtime.h"

#ifndef DEBUG
#define NS_DEBUG 0
#else
#define NS_DEBUG 1
#endif

#ifndef MONGOOSE_DISABLED
#define NS_MONGOOSE_DISABLED 0
#else
#define NS_MONGOOSE_DISABLED 1
#endif

#ifndef DAEMONIZED
#define NS_DAEMONIZED 0
#else
#define NS_DAEMONIZED 1
#endif

/**
 * @brief Format of the HTTP 200 response
 */
#define HTTP_OK_FMT "HTTP/1.1 200 OK\r\n%sContent-Length: %d\r\n\r\n"

/**
 * @brief Initial size of the DBD connection pool
 */
#define NS_DBD_POOL_INIT_SIZE 20

/**
 * @brief Data structure associated with the DBD connection pool
 */
typedef struct ns_dbd_pool_t {
  apr_array_header_t *connections;
  int counter;
  apr_proc_mutex_t *mutex;
} ns_dbd_pool_t;

static ns_dbd_pool_t *dbd_pool;

/**
 * @brief Server activity state
 */
volatile sig_atomic_t server_run = 1;

/**
 * @brief Type of the callback function associated with the termination signal
 */
typedef void(*sighd_t)(int s);

/**
 * @brief Data structure associated with the global state of the server
 */
typedef struct ns_server_t {
  apr_pool_t *pool;
  const char *host;
  const char *port;
  const char *addr;
  const char *timeout;
  const char *max_threads;
  const char *log_file;
  const char *dbd_driver;
  const char *dbd_conn_s;
  const char *upload_dir;
  ns_logger_t *logger;
} ns_server_t;

/**
 * @brief Allocates the global state of the server
 * 
 * @param mp Memory pool
 * @return ns_server_t* Instance of the global state of the server
 */
static ns_server_t* ns_server_alloc(apr_pool_t *mp) {
  ns_server_t *s;
  s = (ns_server_t*)apr_palloc(mp, sizeof(ns_server_t));
  if (s != NULL) {
    s->pool = mp;
    s->host = NULL;
    s->port = NULL;
    s->timeout = NULL;
    s->max_threads = NULL;
    s->log_file = NULL;
    s->logger = NULL;
    s->dbd_driver = NULL;
    s->dbd_conn_s = NULL;
    s->upload_dir = NULL;
    s->addr = NULL;
  }
  return s;
}

/**
 * @brief Releases some resources allocated in the global state of the server
 * 
 * @param s Global state of the server
 */
static void ns_server_destroy(ns_server_t *s) {
  if (s && s->pool) {
    if (s->logger) {
      if (s->logger->mutex) {
        apr_proc_mutex_destroy(s->logger->mutex);
      }
      if (s->logger->fh) {
        apr_file_close(s->logger->fh);
      }
    }
  }
}

/**
 * @brief Allocates the DBD connections pool
 * 
 * @param mp Memory pool
 * @return int The result of allocation
 */
static int ns_dbd_pool_alloc(apr_pool_t *mp) {
  dbd_pool = (ns_dbd_pool_t*)apr_palloc(mp, sizeof(ns_dbd_pool_t));
  return dbd_pool != NULL;
}

/**
 * @brief Adds a DBD connection to the connection pool
 * 
 * Opens a new DBD connection and adds it to the connection pool,
 * then increments the counter of available connections.
 * Uses the mutex for exclusive access to the connection pool.
 * 
 * @param mp Memory pool
 * @param drv Database server driver in use
 * @param conn_s Connection string with the database server in use
 */
static void ns_dbd_pool_add(apr_pool_t *mp, const char *drv, const char *conn_s) {
  ns_dbd_t *dbd = ns_dbd_alloc(mp);
  if (dbd != NULL) {
    if (ns_dbd_open(mp, dbd, drv, conn_s)) {
      APR_ARRAY_PUSH(dbd_pool->connections, ns_dbd_t*) = dbd;
      dbd_pool->counter ++;
    }
  }
}

/**
 * @brief Initializes the DBD connection pool
 * 
 * Allocates the data structure associated with the DBD connection pool
 * in the memory pool and initializes the mutex for read/write access to it.
 * 
 * @param mp Memory pool
 * @param drv DBD driver name (eg. mysql)
 * @param conn_s DBD connection string
 * @return int DBD connections status
 */
static int ns_dbd_pool_init(apr_pool_t *mp, const char *drv, const char *conn_s) {
  int result = 0;
  if (dbd_pool != NULL) {
    dbd_pool->counter = -1;
    dbd_pool->connections = apr_array_make(mp, NS_DBD_POOL_INIT_SIZE,
                                           sizeof(ns_dbd_t*));
    if (dbd_pool->connections != NULL) {
      apr_status_t rv;
      rv = apr_proc_mutex_create(&(dbd_pool->mutex), "dbd_pool_mutex",
                                 APR_LOCK_DEFAULT, mp);
      if (rv == APR_SUCCESS) {
        for (int i = 0; i < NS_DBD_POOL_INIT_SIZE; ++i) {
          ns_dbd_pool_add(mp, drv, conn_s);
        }
        result = dbd_pool->connections->nelts == NS_DBD_POOL_INIT_SIZE;
      }
    }
  }
  return result;
}

/**
 * @brief Retrieves a connection from the DBD connection pool
 * 
 * Uses the mutex for exclusive access to the connection pool
 * Decrements the counter of available connections
 * 
 * @return ns_dbd_t* Data structure associated with the open connection
 */
static ns_dbd_t* ns_dbd_pool_get() {
  ns_dbd_t *dbd = NULL;
  apr_status_t rv = apr_proc_mutex_lock(dbd_pool->mutex);
  if (rv == APR_SUCCESS) {
    if (dbd_pool->connections->nelts > 0) {
      if (dbd_pool->counter >= 0) {
        dbd = APR_ARRAY_IDX(dbd_pool->connections, dbd_pool->counter, ns_dbd_t*);
        dbd_pool->counter --;
      }
    }
    apr_proc_mutex_unlock(dbd_pool->mutex);
  }
  return dbd;
}

/**
 * @brief Releases a connection to the DBD connection pool
 * 
 * Uses the mutex for exclusive access to the connection pool
 * Increments the counter of available connections
 */
static void ns_dbd_pool_release() {
  if (dbd_pool != NULL && dbd_pool->connections != NULL) {
    apr_status_t rv = apr_proc_mutex_lock(dbd_pool->mutex);
    if (rv == APR_SUCCESS) {
      if (dbd_pool->connections->nelts > 0) {
        if (dbd_pool->counter < NS_DBD_POOL_INIT_SIZE - 1) {
          dbd_pool->counter ++;
        }
      }
      apr_proc_mutex_unlock(dbd_pool->mutex);
    }
  }
}

static void ns_dbd_pool_destroy() {
  if (dbd_pool != NULL) {
    apr_status_t rv = apr_proc_mutex_lock(dbd_pool->mutex);
    if (rv == APR_SUCCESS) {
      if (dbd_pool->connections != NULL && dbd_pool->connections->nelts > 0) {
        for (int i = 0; i < NS_DBD_POOL_INIT_SIZE; ++i) {
          ns_dbd_t *dbd = APR_ARRAY_IDX(dbd_pool->connections, i, ns_dbd_t*);
          if (dbd != NULL && dbd->drv && dbd->hdl) {
            ns_dbd_close(dbd);
          }
        }
      }
      apr_proc_mutex_unlock(dbd_pool->mutex);
    }
  }
}

/**
 * @brief Sets a header in the HTTP response
 * 
 * @param mp Memory pool
 * @param rq HTTP request data structure
 * @param hm Data structure associated with the HTTP message
 */
static void ns_http_request_headers_set(apr_pool_t *mp, ns_http_request_t *rq,
                                        struct mg_http_message *hm) {
  apr_table_t *headers = NULL;
  size_t i, max = sizeof(hm->headers) / sizeof(hm->headers[0]);
  for (i = 0; i < max && hm->headers[i].name.len > 0; i++) {
    if (!(rq->headers)) {
      rq->headers = apr_table_make(mp, 1);
      if (!(rq->headers)) {
        break;
      }
    }
    struct mg_str *k, *v;
    const char *key = NULL, *val = NULL;
    k = &hm->headers[i].name;
    if (k) {
      key = apr_psprintf(mp, "%.*s", (int) k->len, k->ptr);  
    }
    v = &hm->headers[i].value;
    if (v) {
      val = apr_psprintf(mp, "%.*s", (int) v->len, v->ptr);
    }
    if (key && val) {
      apr_table_set(rq->headers, key, val);
    }
  }
}

/**
 * @brief Parser for a key/value pair string of the HTTP request
 * 
 * @param mp Memory pool
 * @param s Key/value pair string
 * @param sp1 Separator for key/value pairs
 * @param sp2 Key/value separator
 * @return apr_table_t* Table of key/value pairs or NULL in case of failure
 */
static apr_table_t* ns_http_request_args_parse(apr_pool_t *mp, const char *s,
                                               const char *sp1, const char *sp2) {
  apr_table_t *result = NULL;
  if (mp && s && sp1 && sp2) {
    apr_array_header_t *ar = ns_split(mp, s, sp1);
    if (ar && ar->nelts > 0) {
      for (int i = 0; i < ar->nelts; i++ ) {
        const char *entry = APR_ARRAY_IDX(ar, i, const char*);
        apr_array_header_t *pair = ns_split(mp, entry, sp2);
        if (pair && pair->nelts > 0) {
          if (!result) {
            result = apr_table_make(mp, 1);
            if (!result) {
              return NULL;
            }
          }
          char *k, *v;
          char *trm_k, *trm_v;
          k = apr_pstrdup(mp, APR_ARRAY_IDX(pair, 0, const char*));
          v = apr_pstrdup(mp, APR_ARRAY_IDX(pair, 1, const char*));
          trm_k = ns_trim(mp, k);
          trm_v = ns_trim(mp, v);
          apr_table_set(result, trm_k, trm_v);
        }
      }
    }
  }
  return result;
}

/**
 * @brief Parser for the cookies of the HTTP request
 * 
 * @param mp Memory pool
 * @param hm Data structure associated with the HTTP message
 * @return apr_table_t* Table of key/value pairs or NULL in case of failure
 */
static apr_table_t* ns_http_request_cookies_parse(apr_pool_t *mp,
                                                  struct mg_http_message *hm) {
  apr_table_t *result = NULL;
  struct mg_str *cookies = mg_http_get_header(hm, "Cookie");
  if (cookies != NULL) {
    result = ns_http_request_args_parse(mp, cookies->ptr, ";", "=");
  }
  return result;
}

/**
 * @brief Parser for the query string of the HTTP request
 * 
 * @param mp Memory pool
 * @param hm Data structure associated with the HTTP message
 * @return apr_table_t* Table of key/value pairs or NULL in case of failure
 */
static apr_table_t* ns_http_query_string_parse(apr_pool_t*mp,
                                               struct mg_http_message *hm) {
  apr_table_t *result = NULL;
  if (hm->query.len > 0) {
    const char *query = ns_str(mp, hm->query.ptr, hm->query.len);
    result = ns_http_request_args_parse(mp, query, "&", "=");
  }
  return result;
}

/**
 * @brief Parser for the body of the HTTP request
 * 
 * @param mp Memory pool
 * @param hm Data structure associated with the HTTP message
 * @return apr_table_t* Table of key/value pairs or NULL in case of failure
 */
static apr_table_t* ns_http_request_body_parse(apr_pool_t*mp,
                                               struct mg_http_message *hm) {
  apr_table_t *result = NULL;
  if (hm->body.len > 0) {
    const char *body = ns_str(mp, hm->body.ptr, hm->body.len);
    result = ns_http_request_args_parse(mp, body, "&", "=");
  }
  return result;
}

/**
 * @brief Callback function associated with a termination signal
 * 
 * @param signum Integer value associated with the signal
 */
static void ns_signal_exit(int signum) {
  if (signum == SIGTERM || signum == SIGINT) {
    server_run = 0;
  }
}

/**
 * @brief Associates a callback with a SIGTERM or SIGINT signal
 * 
 * @param sig_action Data structure associated with the signal
 * @param cb Callback function invoked upon handling the managed signals
 */
static void ns_signal_handler(struct sigaction *sig_action, sighd_t cb) {
  sig_action->sa_handler = cb;
  sigemptyset(&sig_action->sa_mask);
  sig_action->sa_flags = 0;
  sigaction(SIGTERM, sig_action, NULL);
  sigaction(SIGINT, sig_action, NULL);
}

/**
 * @brief Parser for HTTP multipart request
 * 
 * @param mp Memory pool
 * @param rq Request data structure
 * @param c Active connection
 * @param hm Data structure associated with the HTTP message
 * @return int 1 on success, otherwise 0
 */
static int ns_http_request_multipart_parse(apr_pool_t *mp, ns_http_request_t *rq,
                                           struct mg_connection *c,
                                           struct mg_http_message *hm) {
  char *err;
  apr_size_t fsize;
  const char *fname, *forig, *fpath;
  apr_table_t *entry;
  apr_file_t *fd;
  apr_status_t rv;
  struct mg_http_part part;
  size_t ofs = 0;
  rq->multipart_data = apr_array_make(mp, 0, sizeof(apr_table_t*));
  while ((ofs = mg_http_next_multipart(hm->body, ofs, &part)) != 0) {
    entry = apr_table_make(mp, 2);
    // Multipart files
    if ((int)part.filename.len > 0) {
      fname = apr_psprintf(mp, "%.*s", (int)part.name.len, part.name.ptr);
      forig = apr_psprintf(mp, "%.*s",
                           (int)part.filename.len, part.filename.ptr);
      fsize = (apr_size_t)part.body.len;
      fpath = apr_psprintf(mp, "%s/%s", "/tmp", forig);
      rv = ns_file_open_truncate(&fd, fpath, mp);
      if (rv == APR_SUCCESS) {
        fsize = ns_file_write(fd, part.body.ptr, fsize);
        apr_table_set(entry, "file_name", fname);
        apr_table_set(entry, "file_path", fpath);
      }
    }
    // Multipart arguments
    else {
      char *key = apr_psprintf(mp, "%.*s", (int)part.name.len, part.name.ptr);
      apr_table_set(entry, "name", key);
      char *val = apr_psprintf(mp, "%.*s", (int)part.body.len, part.body.ptr);
      apr_table_set(entry, "value", val);
    }
    APR_ARRAY_PUSH(rq->multipart_data, apr_table_t*) = entry;
  }
  return rq->multipart_data->nelts > 0;
}

/**
 * @brief HTTP request handler associated with client request
 * 
 * @param c Active connection
 * @param ev Event
 * @param ev_data Data structure associated with the event
 * @param fn_data Global server state
 */
static void ns_http_request_handler(struct mg_connection *c,
                                    int ev, void *ev_data) {
  struct state_t {
    struct flag_t {
      int ev_data, fn_data, init, pool, logger, request, method, uri, query,
          body, multipart, response, handler, resp_headers, resp_size, dbd,
          dbd_handler, service;
    } flag;
    int error;
    apr_pool_t *pool;
    ns_server_t *server;
    struct mg_http_message *hm;
    const char *er_msg;
  } st = {
    .flag.ev_data = 0, .flag.fn_data = 0, .flag.init = 0, .flag.pool = 0,
    .flag.logger = 0, .flag.request = 0, .flag.method = 0, .flag.uri = 0,
    .flag.query = 0, .flag.body = 0, .flag.multipart = 0, .flag.response = 0,
    .flag.resp_headers = 0, .flag.handler = 0, .flag.dbd = 0,
    .flag.dbd_handler = 0, .flag.service = 0, .flag.resp_size = 0, .error = 0,
    .server = NULL, .er_msg = NULL
  };

  do {
    if (ev == MG_EV_HTTP_MSG) {

      st.flag.ev_data = ev_data != NULL;
      if ((st.error = !st.flag.ev_data)) {
        break;
      }

      // Event data
      st.hm = (struct mg_http_message*)ev_data;

      st.flag.fn_data = c->fn_data != NULL;
      if ((st.error = !st.flag.fn_data)) {
        break;
      }

      // Server data
      st.server = (ns_server_t*)c->fn_data;
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "Client connected");
      }

      {
        apr_status_t rv;

        // APR initialization
        rv = apr_initialize();
        st.flag.init = (rv == APR_SUCCESS);
        if ((st.error = !st.flag.init)) {
          break;
        }
        if (NS_DEBUG) {
          ns_log((st.server)->logger, "INFO", "Service APR initialized");
        }

        // Memory pool allocation
        rv = apr_pool_create(&st.pool, NULL);
        st.flag.pool = (rv == APR_SUCCESS);
        if ((st.error = !st.flag.pool)) {
          break;
        }
        if (NS_DEBUG) {
          ns_log((st.server)->logger, "INFO", "Service pool created");
        }
      }

      // Service allocation
      ns_service_t* sv = ns_alloc(st.pool);
      st.flag.service = sv != NULL;
      if ((st.error = !st.flag.service)) {
        break;
      }
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "Service data struct allocated");
      }

      // Logger
      sv->logger = (st.server)->logger;
      st.flag.logger = sv->logger != NULL;
      if ((st.error = !st.flag.logger)) {
        break;
      }
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "Service logger initialized");
      }

      // Request
      sv->request = ns_http_request_alloc(st.pool);
      st.flag.request = sv->request != NULL;
      if ((st.error = !st.flag.request)) {
        break;
      }
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "Service HTTP request allocated");
      }

      // Request headers
      ns_http_request_headers_set(st.pool, sv->request, st.hm);
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "HTTP request headers parsed");
      }

      // Request method
      st.flag.method = (st.hm)->method.len > 0;
      if ((st.error = !st.flag.method)) {
        break;
      }
      sv->request->method = ns_str(st.pool, (st.hm)->method.ptr,
                                  (st.hm)->method.len);
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "HTTP request method parsed");
      }

      // Request URI
      st.flag.uri = (st.hm)->uri.len > 0;
      if ((st.error = !st.flag.uri)) {
        break;
      }
      sv->request->uri = ns_str(st.pool, (st.hm)->uri.ptr, (st.hm)->uri.len);
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "HTTP request uri parsed");
      }

      // Request query string
      if (strcmp(sv->request->method, "GET") == 0) {
        if ((st.hm)->query.len) {
          sv->request->query = ns_str(st.pool, (st.hm)->query.ptr,
                                     (st.hm)->query.len);
          st.flag.query = sv->request->query != NULL;
          if ((st.error = !st.flag.query)) {
            break;
          }
          sv->request->args = ns_http_query_string_parse(sv->pool, st.hm);
          if (sv->request->args) {
            if (NS_DEBUG) {
              ns_log((st.server)->logger, "INFO", "HTTP query string parsed");
            }
          }
        } else {
          st.flag.query = 1;
        }
      }

      // Request body
      if ((st.hm)->body.len) {
        sv->request->body = ns_str(st.pool, (st.hm)->body.ptr,
                                  (st.hm)->body.len);
        st.flag.body = sv->request->body != NULL;
        if ((st.error = !st.flag.body)) {
          break;
        }
        sv->request->args = ns_http_request_body_parse(sv->pool, st.hm);
        if (sv->request->args) {
          if (NS_DEBUG) {
            ns_log((st.server)->logger, "INFO", "HTTP body parsed");
          }
        }
      } else {
        st.flag.body = 1;
      }

      {
        // Request multipart data
        const char *ctype;
        ctype = apr_table_get(sv->request->headers, "Content-Type");
        if (ns_in_string(ctype, "multipart/form-data")) {
          st.flag.multipart =
            ns_http_request_multipart_parse(st.pool, sv->request, c, st.hm);
          if ((st.error = !st.flag.multipart)) {
            break;
          }
          if (NS_DEBUG) {
            ns_log((st.server)->logger, "INFO", "HTTP request multipart parsed");
          }
        } else {
          st.flag.multipart = 1;
        }
      }
      
      // Authorization
      {
        char user[256] = {0}, pass[256] = {0};
        mg_http_creds(st.hm, user, sizeof(user), pass, sizeof(pass));
        if (strlen(user) > 0) {
          sv->request->username = apr_pstrdup(st.pool, user);
        }
        if (strlen(pass) > 0) {
          sv->request->password = apr_pstrdup(st.pool, pass);
        }
      }

      // Response
      sv->response = ns_http_response_alloc(st.pool);
      st.flag.response = sv->response != NULL;
      if ((st.error = !st.flag.response)) {
        break;
      }
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "HTTP response allocated");
      }

      // Default response HTTP header Content-Type
      ns_http_response_hd_set(sv->response, "Content-Type", "text/plain");
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "HTTP response Content-Type defined");
      }

      // DBD connection
      if ((st.server)->dbd_driver && (st.server)->dbd_conn_s) {
        if (NS_DEBUG) {
          ns_log((st.server)->logger, "INFO", "DBD connection configured");
        }
        sv->dbd = ns_dbd_pool_get();
        st.flag.dbd = sv->dbd != NULL;
        if ((st.error = !st.flag.dbd)) {
          break;
        }
        if (NS_DEBUG) {
          ns_log((st.server)->logger, "INFO", "DBD connection opened");
        }
        st.flag.dbd_handler = sv->dbd->drv != NULL && sv->dbd->hdl != NULL;
        if ((st.error = !st.flag.dbd_handler)) {
          break;
        }
        if (NS_DEBUG) {
          ns_log((st.server)->logger, "INFO", "DBD handler initialized.");
        }
      }

      // ---------------
      // Service handler
      // ---------------
      ns_handler(sv);
      st.er_msg = sv->er_msg;
      st.flag.handler = st.er_msg == NULL;
      if ((st.error = !st.flag.handler)) {
        break;
      }
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "Service handler executed.");
      }

      ns_dbd_pool_release();
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "DBD connection released.");
      }

      // Response headers
      const char *http_hd;
      http_hd = ns_http_response_hd_serialize(sv->response);
      st.flag.resp_headers = http_hd != NULL;
      if ((st.error = !st.flag.resp_headers)) {
        break;
      }

      // Default HTTP response status (404 - Not Found)
      if (sv->response->status == 0) {
        sv->response->status = 404;
      }

      if (sv->response->status != 200) {
        // Not 200 OK response
        const char *ctype;
        ctype = ns_http_response_hd_get(sv->response, "Content-Type");
        if (ctype) {
          ctype = apr_psprintf(st.pool, "Content-Type: %s\r\n", ctype);
        }
        mg_http_reply(c, sv->response->status, ctype, "");
      } else {
        // 200 OK empty response
        st.flag.resp_size = sv->response->size > 0;
        if ((st.error = !st.flag.resp_size)) {
          break;
        }
        // 200 OK response
        mg_printf(c, HTTP_OK_FMT, http_hd ? http_hd : "", sv->response->size);
        if ((sv->response->size > 0) && sv->response->buffer) {
          mg_send(c, sv->response->buffer, sv->response->size);
        }
      }
    } /* ev == MG_EV_HTTP_MSG */
  } while (0);

  if (st.error) {
    const char ctype[] = "Content-Type: text/plain\r\n";
    if (!st.flag.ev_data) {
      mg_http_reply(c, 500, ctype, "Invalid event data.\r\n");
    } else if (!st.flag.fn_data) {
      mg_http_reply(c, 500, ctype, "Invalid server data.\r\n");
    } else if (!st.flag.init) {
      mg_http_reply(c, 500, ctype, "APR initialization error.\r\n");
    } else if (!st.flag.pool) {
      mg_http_reply(c, 500, ctype, "APR memory pool error.\r\n");
    } else if (!st.flag.service) {
      if (st.er_msg) {
        mg_http_reply(c, 500, ctype, st.er_msg);
      } else {
        mg_http_reply(c, 500, ctype, "HTTP service error.\r\n");
      }
    } else if (!st.flag.logger) {
      mg_http_reply(c, 500, ctype, "Invalid logger.\r\n");
    } else if (!st.flag.request) {
      mg_http_reply(c, 500, ctype, "Invalid request allocation.\r\n");
    } else if (!st.flag.method) {
      mg_http_reply(c, 500, ctype, "Invalid request method.\r\n");
    } else if (!st.flag.uri) {
      mg_http_reply(c, 500, ctype, "Invalid request uri.\r\n");
    } else if (!st.flag.query) {
      mg_http_reply(c, 500, ctype, "Invalid request query string.\r\n");
    } else if (!st.flag.body) {
      mg_http_reply(c, 500, ctype, "Invalid request body.\r\n");
    } else if (!st.flag.multipart) {
      mg_http_reply(c, 500, ctype, "Invalid request multipart data.\r\n");
    } else if (!st.flag.response) {
      mg_http_reply(c, 500, ctype, "Response allocation failure.\r\n");
    } else if (!st.flag.dbd) {
      mg_http_reply(c, 500, ctype, "DBD error.\r\n");
    } else if (!st.flag.dbd_handler) {
      mg_http_reply(c, 500, ctype, "DBD connection error.\r\n");
    } else if (!st.flag.handler) {
      if (st.er_msg) {
        mg_http_reply(c, 500, ctype, st.er_msg);
      } else {
        mg_http_reply(c, 500, ctype, "Request handler error.\r\n");
      }
    } else if (!st.flag.resp_headers) {
      mg_http_reply(c, 500, ctype, "Invalid HTTP response headers.\r\n");
    } else if (!st.flag.resp_size) {
      mg_http_reply(c, 500, ctype, "Empty response.\r\n");
    } else {
      mg_http_reply(c, 500, ctype, "General error.\r\n");
    }
  }

  if (st.flag.init) {
    if (st.flag.pool) {
      apr_pool_destroy(st.pool);
    }
    apr_terminate();
  }
}

/**
 * @brief Parses command line arguments
 * 
 * @param s Global server state
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @param er_msg Error message
 * @return int 1 on success, otherwise 0
 */
static int ns_cmd_args_parse(ns_server_t *s, int argc, char *argv[], char **er_msg) {
  struct state_t {
    struct flag_t {
      int input, arg_format, host, port, log_file;
    } flag;
    int error, result;
  } st = {
    .flag.input = 0, .flag.arg_format = 0, .error = 0, .result = 0
  };

  do {
    *er_msg = NULL;
    // Input validation
    st.flag.input = s != NULL && argv != NULL && argc > 1 && ((argc-1)%2) == 0;
    if ((st.error = !st.flag.input)) {
      break;
    }
    for (int i = 1; i < argc; i += 2) {
      // Command line arguments validation
      st.flag.arg_format = strlen(argv[i]) == 2;
      if ((st.error = !st.flag.arg_format)) {
        break;
      }
      // Command line arguments value
      if (argv[i][1] == 'h') {
        s->host = apr_pstrdup(s->pool, argv[i+1]);
      } else if (argv[i][1] == 'p') {
        s->port = apr_pstrdup(s->pool, argv[i+1]);
      } else if (argv[i][1] == 't') {
        s->timeout = apr_pstrdup(s->pool, argv[i+1]);
      } else if (argv[i][1] == 'T') {
        s->max_threads = apr_pstrdup(s->pool, argv[i+1]);
      } else if (argv[i][1] == 'l') {
        s->log_file = apr_pstrdup(s->pool, argv[i+1]);
      } else if (argv[i][1] == 'd') {
        s->dbd_driver = apr_pstrdup(s->pool, argv[i+1]);
      } else if (argv[i][1] == 'D') {
        s->dbd_conn_s = apr_pstrdup(s->pool, argv[i+1]);
      } else if (argv[i][1] == 'u') {
        s->upload_dir = apr_pstrdup(s->pool, argv[i+1]);
      }
    }

    st.error = st.error || !(s->host) || !(s->port) || !(s->log_file);
    if (st.error) {
      break;
    }

    st.result = 1;
  } while (0);

  if (st.error) {
    if (!st.flag.input) {
      *er_msg = apr_pstrdup(s->pool, "Invalid input.");
    } else if (!st.flag.arg_format) {
      *er_msg = apr_pstrdup(s->pool, "Invalid arguments format.");
    } else if (s->host == NULL) {
      *er_msg = apr_pstrdup(s->pool, "Invalid host address.");
    } else if (s->port == NULL) {
      *er_msg = apr_pstrdup(s->pool, "Invalid port number.");
    } else if (s->log_file == NULL) {
      *er_msg = apr_pstrdup(s->pool, "Invalid log file.");
    } else {
      *er_msg = apr_pstrdup(s->pool, "General error.");
    }
  }

  return st.result;
}

/**
 * @brief Initializes the global state of the server
 * 
 * @param mp Memory pool
 * @param s Server state
 * @param argc Number of command line arguments
 * @param argv Command line arguments
 * @param er_msg Error message
 * @return int 1 on success, otherwise 0
 */
static int ns_server_init(apr_pool_t *mp, ns_server_t **s, int argc,
                          char *argv[], char **er_msg) {
  struct state_t {
    struct flag_t {
      int input, args, addr, mutex, logger;
    } flag;
    int error, result;
    apr_status_t mutex;
    apr_proc_mutex_t *log_mutex;
  } st = {
    .flag.input = 0, .flag.args = 0, .flag.addr = 0, .flag.mutex = 0,
    .flag.logger = 0, .error = 0, .result = 0
  };

  do {
    *er_msg = NULL;

    st.flag.input = mp != NULL && *s != NULL && argv != NULL && argc > 1;
    if ((st.error = !st.flag.input)) {
      break;
    }

    st.flag.args = ns_cmd_args_parse(*s, argc, argv, er_msg);
    if ((st.error = !st.flag.args)) {
      break;
    }

    (*s)->addr = apr_psprintf(mp, "%s:%s", (*s)->host, (*s)->port);
    st.flag.addr = (*s)->addr != NULL;
    if ((st.error = !st.flag.addr)) {
      break;
    }

    apr_status_t rv;
    rv = apr_proc_mutex_create(&(st.log_mutex), "log_mutex", APR_LOCK_DEFAULT, mp);

    st.flag.mutex = rv == APR_SUCCESS;
    if ((st.error = !st.flag.mutex)) {
      break;
    }

    (*s)->logger = ns_log_alloc(mp, st.log_mutex, (*s)->log_file, 0);
    st.flag.logger = (*s)->logger != NULL;
    if ((st.error = !st.flag.logger)) {
      break;
    }

    st.result = 1;
  } while (0);

  if (st.error) {
    if (!st.flag.input) {
      *er_msg = apr_pstrdup(mp, "Invalid input");
    } else if (!st.flag.args) {
      if (*er_msg == NULL) {
        *er_msg = apr_pstrdup(mp, "Invalid arguments");
      }
    } else if (!st.flag.args) {
      *er_msg = apr_pstrdup(mp, "Invalid address");
    } else if (!st.flag.mutex) {
      *er_msg = apr_pstrdup(mp, "Logger mutex initialization error");
    } else if (!st.flag.logger) {
      *er_msg = apr_pstrdup(mp, "Logger initialization error");
    } else {
      *er_msg = apr_pstrdup(mp, "General error");
    }
  }

  return st.result;
}

/**
 * Main function
 */
int main(int argc, char **argv) {
  struct state_t {
    struct flag_t {
      int input, init, pool, server, dbd, dbd_pool;
    } flag;
    int error;
    ns_server_t *server;
    char *er_msg;
    apr_pool_t *pool;
    struct mg_mgr mgr;
    struct sigaction sig_action;
  } st = {
    .flag.input = 0, .flag.init = 0, .flag.pool = 0, .flag.server = 0,
    .flag.dbd = 0, .flag.dbd_pool = 0, .error = 0, .server = NULL,
    .er_msg = NULL
  };

  do {
    // Associate the callback that handles
    // the termination signal with the signal handler
    ns_signal_handler(&(st.sig_action), ns_signal_exit);

    st.flag.input = argv != NULL && argc > 1;
    if ((st.error = !st.flag.input)) {
      break;
    }

    {
      apr_status_t rv;
      
      // Initialize the data structures of the APR runtime
      rv = apr_initialize();
      st.flag.init = rv == APR_SUCCESS;
      if ((st.error = !st.flag.init)) {
        break;
      }

      // Instantiate the memory pool
      rv = apr_pool_create(&(st.pool), NULL);
      st.flag.pool = rv == APR_SUCCESS;
      if ((st.error = !st.flag.pool)) {
        break;
      }
    }

    // Allocate the data structure of the global service state
    st.server = ns_server_alloc(st.pool);
    st.flag.server = st.server != NULL;
    if ((st.error = !st.flag.server)) {
      break;
    }

    // Initialize the data structure of the global service state
    st.flag.server = ns_server_init(st.pool, &(st.server),
                                    argc, argv, &(st.er_msg));
    if ((st.error = !st.flag.server)) {
      break;
    }

    if (NS_DEBUG) {
      ns_log((st.server)->logger, "INFO", "Server starting...");
      ns_log((st.server)->logger, "INFO", "Server initialized");
    }

    if ((st.server)->dbd_driver != NULL) {
      if ((st.server)->dbd_conn_s != NULL) {
        apr_status_t rv;
        rv = apr_dbd_init(st.pool);
        st.flag.dbd = rv == APR_SUCCESS;
        if ((st.error = !st.flag.dbd)) {
          break;
        }
      }
    }

    dbd_pool = NULL;
    if (st.flag.dbd) {
        
      st.flag.dbd_pool = ns_dbd_pool_alloc(st.pool);
      if ((st.error = !st.flag.dbd_pool)) {
        break;
      }

      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "DBD connection pool allocated");
      }

      st.flag.dbd_pool = ns_dbd_pool_init(st.pool, (st.server)->dbd_driver,
                                          (st.server)->dbd_conn_s);
      if ((st.error = !st.flag.dbd_pool)) {
        break;
      }

      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "DBD connection pool initialized");
      }
    }

    if (NS_DAEMONIZED) {
      ns_daemonize();
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "Service daemonized");
      }
    }

    if (!NS_MONGOOSE_DISABLED) {
      mg_mgr_init(&(st.mgr));
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "HTTP server initialized");
      }
      mg_http_listen(&(st.mgr), (st.server)->addr,
                    ns_http_request_handler, (void*)(st.server));
      if (NS_DEBUG) {
        ns_log((st.server)->logger, "INFO", "HTTP server listening...");
      }
      while (server_run) {
        mg_mgr_poll(&(st.mgr), 1000);
      }
      mg_mgr_free(&(st.mgr));
    }
  } while (0);

  if (st.error) {
    if (!st.flag.input) {
      ns_log((st.server)->logger, "ERROR", "Invalid input");
    } else if (!st.flag.init) {
      ns_log((st.server)->logger, "ERROR", "Environment initialization error");
    } else if (!st.flag.pool) {
      ns_log((st.server)->logger, "ERROR", "Memory pool allocation error");
    } else if (!st.flag.server) {
      if (st.server == NULL) {
        ns_log((st.server)->logger, "ERROR", "Server allocation error");
      } else if (st.er_msg != NULL) {
        ns_log((st.server)->logger, "ERROR", st.er_msg);
      } else {
        ns_log((st.server)->logger, "ERROR", "Server initialization error");
      } 
    } else if (!st.flag.dbd) {
      ns_log((st.server)->logger, "ERROR", "DBD initialization failure");
    } else if (!st.flag.dbd_pool) {
      ns_log((st.server)->logger, "ERROR", "DBD pool initialization failure");
    } else {
      ns_log((st.server)->logger, "ERROR", "General error");
    }
  }

  if (st.flag.init) {
    if (st.flag.pool) {
      ns_dbd_pool_destroy();
      ns_server_destroy(st.server);
      apr_pool_destroy(st.pool);
    }
    apr_terminate();
  }

  return 0;
}
