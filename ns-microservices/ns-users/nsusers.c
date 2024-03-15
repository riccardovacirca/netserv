
#include "ns_runtime.h"

#define true 1
#define false 0

#ifdef _DEBUG
#define DEBUG 1
#else
#define DEBUG 0
#endif

#define JWT_SECRET_KEY "my_jwt_secret_key"

/**
 * @brief Pattern of the response string
 */
#define JSON_RESPONSE_SUCCESS "{\"err\":0,\"log\":null,\"out\":%s}"
#define JSON_RESPONSE_FAILURE "{\"err\":0,\"log\":\"%s\",\"out\":null}"

// Helpers

int authorize_route(ns_service_t *s)
{
  int auth = s && s->request && s->request->password &&
             ns_jwt_token_validate(s->pool, s->request->password, JWT_SECRET_KEY);
  if (!auth) {
    ns_printf(s, JSON_RESPONSE_FAILURE, "Unauthorized");
    s->response->status = 200;
  }
  return auth;
}

// Models

int SignUpModel(ns_service_t *s, void **res, apr_table_t *args)
{
  const char sql[] = "INSERT INTO users (username, password) VALUES (%s, %s)";
  return s->dbd ? ns_dbd_prepared_query(s->pool, s->dbd, sql, args) : 0;
}

int SignInModel(ns_service_t *s, void **res, apr_table_t *args)
{
  *res = NULL;
  apr_array_header_t *resultset = NULL;
  const char sql[] = "SELECT id, username FROM users "
                     "WHERE username=%s AND password=%s";
  if (s->dbd) {
    resultset = (void*)ns_dbd_prepared_select(s->pool, s->dbd, sql, args);
  }
  if (resultset) {
    apr_table_t *claims = APR_ARRAY_IDX(resultset, 0, apr_table_t*);
    if (claims != NULL) {
      *res = ns_jwt_token_create(s->pool, claims, JWT_SECRET_KEY);
    }
  }
  return *res != NULL;
}

int UserModel(ns_service_t *s, void **res, apr_table_t *args)
{
  *res = NULL;
  const char sql[] = "SELECT id, username FROM users WHERE id=%s";
  if (s->dbd != NULL) {
    *res = (void*)ns_dbd_prepared_select(s->pool, s->dbd, sql, args);
  }
  return *res != NULL;
}

int UsersListModel(ns_service_t *s, void **res, apr_table_t *args)
{
  *res = NULL;
  const char sql[] = "SELECT id, username FROM users";
  if (s->dbd != NULL) {
    *res = ns_dbd_select(s->pool, s->dbd, sql);
  }
  return *res != NULL;
}

// Controllers

ns_request_validator_t SignUpRequestValidator[] =
{
  {"username", NS_REQUEST_T_STRING, NS_REQUEST_F_NONE},
  {"password", NS_REQUEST_T_STRING, NS_REQUEST_F_MD5}
};

int SignUpController(ns_service_t *s)
{
  struct state_t {
    int error, result;
    struct flag_t { int args, result, json; } flag;
  } st = {
    .flag.args = false, .flag.result = false, .flag.json = false,
    .error = false, .result = false
  };
  
  do {
    const char ctype[] = "application/json";
    ns_http_response_hd_set(s->response, "Content-Type", ctype);

    apr_table_t *args;
    args = ns_http_request_validate_args(s->request, SignUpRequestValidator, 2);
    st.flag.args = (args != NULL) && (ns_table_nelts(args) == 2);
    if ((st.error = !st.flag.args)) {
      break;
    }

    st.result = SignUpModel(s, NULL, args);
    st.flag.result = st.result > 0;
    if ((st.error = !st.flag.result)) {
      break;
    }

    const char *json = apr_psprintf(s->pool, "%d", st.result);
    st.flag.json = json != NULL;
    if ((st.error = !st.flag.json)) {
      break;
    }

    ns_printf(s, JSON_RESPONSE_SUCCESS, json);

  } while (0);

  if (st.error) {
    const char *er = NULL;
    if (!st.flag.result) {
      er = ns_json_encode(s->pool, "Registration failure", NS_JSON_T_STRING);
    } else if (!st.flag.json) {
      er = ns_json_encode(s->pool, "JSON encoding failure", NS_JSON_T_STRING);
    } else {
      er = ns_json_encode(s->pool, "General error", NS_JSON_T_STRING);
    }
    if (er != NULL) {
      ns_printf(s, JSON_RESPONSE_FAILURE, er);
    } else {
      ns_printf(s, JSON_RESPONSE_FAILURE, "An error occurred.");
    }
  }

  return 200;
}

/**
 * @brief Validator of the HTTP request arguments
 */
ns_request_validator_t SignInRequestValidator[] =
{
  {"username", NS_REQUEST_T_STRING, NS_REQUEST_F_NONE},
  {"password", NS_REQUEST_T_PASSWORD, NS_REQUEST_F_MD5}
};

/**
 * @brief Returns a user to the client based on username and password
 * 
 * @param s Service state
 * @return int HTTP status code
 */
int SignInController(ns_service_t *s)
{
  struct state_t {
    int error;
    struct flag_t { int args, token; } flag;
  } st = {
    .flag.args = false, .flag.token = false, .error = false
  };

  do {
    const char ctype[] = "application/json";
    ns_http_response_hd_set(s->response, "Content-Type", ctype);

    apr_table_t *args;
    args = ns_http_request_validate_args(s->request, SignInRequestValidator, 2);
    st.flag.args = (args != NULL) && (ns_table_nelts(args) == 2);
    if ((st.error = !st.flag.args)) {
      break;
    }

    int n = 0;
    if (s->request->args) {
      n = ns_table_nelts(s->request->args);
    }

    const char *tok;
    st.flag.token = SignInModel(s, (void*)(&tok), args);
    if ((st.error = !st.flag.token)) {
      break;
    }

    const char *cookies;
    cookies = apr_psprintf(s->pool, "access_token=%s Path=/", (const char*)tok);
    ns_http_response_hd_set(s->response, "Set-Cookie", cookies);
    ns_printf(s, JSON_RESPONSE_SUCCESS, "true");

  } while (0);

  if (st.error) {
    const char *er = NULL;
    if (!st.flag.args) {
      er = ns_json_encode(s->pool, "Invalid request args", NS_JSON_T_STRING);
    } else if (!st.flag.token) {
      er = ns_json_encode(s->pool, "JWT token error", NS_JSON_T_STRING);
    } else {
      er = ns_json_encode(s->pool, "General error", NS_JSON_T_STRING);
    }
    if (er != NULL) {
      ns_printf(s, JSON_RESPONSE_FAILURE, er);
    } else {
      ns_printf(s, JSON_RESPONSE_FAILURE, "An error occurred.");
    }
  }

  return 200;
}

/**
 * @brief Returns a list of users to the client
 * 
 * @param s Service state
 * @return int HTTP status code
 */
int UsersListController(ns_service_t *s)
{
  struct state_t {
    int error;
    apr_array_header_t *list;
    struct flag_t { int list, json; } flag;
  } st = {
    .flag.list = false, .flag.json = false,
    .error = false, .list = NULL
  };

  do {

    // Sets the value of the Content-Type in the response header
    const char ctype[] = "application/json";
    ns_http_response_hd_set(s->response, "Content-Type", ctype);

    // Retrieves the list of users
    st.flag.list = UsersListModel(s, (void*)(&st.list), NULL);
    if ((st.error = !st.flag.list)) {
      break;
    }

    // Encodes the response in JSON format
    const char *json = ns_json_encode(s->pool, (const void*)st.list,
                                      NS_JSON_T_VECTOR|NS_JSON_T_TABLE);
    st.flag.json = json != NULL;
    if ((st.error = !st.flag.json)) {
      break;
    }

    // Sends the response to the client
    ns_printf(s, JSON_RESPONSE_SUCCESS, json);

  } while (0);

  if (st.error) {
    const char *er = NULL;
    if (!st.flag.list) {
      er = ns_json_encode(s->pool, "Users retrieving failure", NS_JSON_T_STRING);
    } else if (!st.flag.json) {
      er = ns_json_encode(s->pool, "JSON encoding failure", NS_JSON_T_STRING);
    } else {
      er = ns_json_encode(s->pool, "General error", NS_JSON_T_STRING);
    }
    if (er != NULL) {
      ns_printf(s, JSON_RESPONSE_FAILURE, er);
    } else {
      ns_printf(s, JSON_RESPONSE_FAILURE, "An error occurred.");
    }
  }

  return 200;
}

/**
 * @brief Validator of the HTTP request arguments
 */
ns_request_validator_t UserRequestValidator[] =
{
  {"id", NS_REQUEST_T_INT, NS_REQUEST_F_NONE}
};

/**
 * @brief Returns a user to the client based on the ID in the request
 * 
 * @param s Service state
 * @return int HTTP status code
 */
int UserController(ns_service_t *s)
{
  struct state_t {
    int error;
    apr_array_header_t *user;
    struct flag_t { int user, args, json; } flag;
  } st = {
    .flag.args = false, .flag.user = false, .flag.json = false,
    .error = false, .user = NULL
  };

  do {
    // Sets the value of the Content-Type in the response header
    const char ctype[] = "application/json";
    ns_http_response_hd_set(s->response, "Content-Type", ctype);

    // Performs validation of the request arguments
    apr_table_t *args;
    args = ns_http_request_validate_args(s->request, UserRequestValidator, 1);
    st.flag.args = (args != NULL) && (ns_table_nelts(args) == 1);
    if ((st.error = !st.flag.args)) {
      break;
    }

    // Retrieves the user based on the ID in the request
    st.flag.user = UserModel(s, (void*)(&st.user), args);
    if ((st.error = !st.flag.user)) {
      break;
    }

    // Encodes the response in JSON format
    const char *json = ns_json_encode(s->pool, (const void*)st.user,
                                      NS_JSON_T_VECTOR|NS_JSON_T_TABLE);
    st.flag.json = json != NULL;
    if ((st.error = !st.flag.json)) {
      break;
    }

    // Sends the response to the client
    ns_printf(s, JSON_RESPONSE_SUCCESS, json);

  } while (0);

  if (st.error) {
    const char *er = NULL;
    if (!s->authorized) {
      er = ns_json_encode(s->pool, "Forbidden", NS_JSON_T_STRING);
    } else if (!st.flag.user) {
      er = ns_json_encode(s->pool, "User retrieving failure", NS_JSON_T_STRING);
    } else if (!st.flag.json) {
      er = ns_json_encode(s->pool, "JSON encoding failure", NS_JSON_T_STRING);
    } else {
      er = ns_json_encode(s->pool, "General error", NS_JSON_T_STRING);
    }
    if (er != NULL) {
      ns_printf(s, JSON_RESPONSE_FAILURE, er);
    } else {
      ns_printf(s, JSON_RESPONSE_FAILURE, "An error occurred.");
    }
  }

  return 200;
}

void ns_handler(ns_service_t *s)
{
  ns_route(s, "POST", "/api/sign-in", SignInController);
  ns_route(s, "POST", "/api/sign-up", SignUpController);
  //ns_authorized_routes(s, authorize_route) {
    ns_route(s, "GET", "/api/user-data", UserController);
    ns_route(s, "GET", "/api/users-list", UsersListController);
  //}
}
