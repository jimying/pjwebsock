#ifndef __PJLIB_UTIL_HTTP_H__
#define __PJLIB_UTIL_HTTP_H__
#include <pjlib.h>

PJ_BEGIN_DECL

/**
 *  http uri (http/websocket url)
 *  syntax:
 *      <scheme>://<user>:<pass>@<host>:<port>/<path>?<query>
 */
typedef struct pj_http_uri {
    pj_str_t scheme; /**< scheme, can be http/https/ws/wss */
    pj_str_t user;   /**< user (optional) */
    pj_str_t pass;   /**< password (optional) */
    pj_str_t host;   /**< host */
    pj_str_t port;   /**< port */
    pj_str_t path;   /**< path */
    pj_str_t query;  /**< query argument, eg. ?x=1&y=2 (optional)*/
} pj_http_uri;

PJ_DECL(pj_status_t) pj_http_uri_parse(const char *str_url, pj_http_uri *uri);
PJ_DECL(pj_bool_t) pj_http_uri_istls(const pj_http_uri *uri);
PJ_DECL(pj_uint16_t) pj_http_uri_port(const pj_http_uri *uri);

/**
 *  MAX count of http headers
 */
#ifndef PJ_HTTP_MAX_HEADERS
#  define PJ_HTTP_MAX_HEADERS 32
#endif

/**
 * http header
 */
typedef struct pj_http_hdr {
    pj_str_t key;
    pj_str_t val;
} pj_http_hdr;

/**
 * request line
 */
typedef struct pj_http_req_line {
    pj_str_t *method;
    pj_str_t *path;
    pj_str_t *version;
} pj_http_req_line;

/**
 *  status line
 */
typedef struct pj_http_status_line {
    pj_str_t *version;
    pj_str_t *status;
    pj_str_t *reason;
} pj_http_status_line;

/**
 * start line (request-line/ status-line)
 */
typedef struct pj_http_start_line {
    pj_str_t s, s2, s3; /**< real data */
    union {
        pj_http_req_line req_line;
        pj_http_status_line status_line;
    } u;
} pj_http_start_line;

/**
 * http message
 */
typedef struct pj_http_msg {
    pj_http_start_line start_line;
    pj_http_hdr hdrs[PJ_HTTP_MAX_HEADERS];
    int hdr_cnt;
    pj_str_t body;
} pj_http_msg;

PJ_DECL(pj_status_t) pj_http_msg_parse(const void *data,
                                       pj_size_t size,
                                       pj_http_msg *msg,
                                       pj_size_t *msg_len);
PJ_DECL(pj_status_t) pj_http_msg_find_hdr(const pj_http_msg *msg,
                                          const pj_str_t *k,
                                          pj_str_t *v);
PJ_DECL(pj_bool_t) pj_http_msg_is_response(const pj_http_msg *msg);

PJ_END_DECL
#endif
