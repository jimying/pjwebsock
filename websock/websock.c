#include "websock.h"
#include "websock_transport.h"
#include <pjlib.h>
#include <pjlib-util/scanner.h>
#include <pjlib-util/base64.h>
#include <pjlib-util/sha1.h>

#define THIS_FILE "websock.c"

static const pj_time_val DELAY_TIMEOUT = { 10, 0 };
enum {
    TIMER_ID_NONE,
    TIMER_ID_TIMEOUT,
    TIMER_ID_PING,
};

struct pj_websock_endpoint {
    pj_pool_factory *pf;
    pj_ioqueue_t *ioq;
    pj_timer_heap_t *timer_heap;
    pj_websock_ssl_cert *cert;
    int max_rx_bufsize;
    pj_pool_t *pool;
    pj_websock_t *conn_list;
};

/* Http request header */
struct http_req_hdr {
    struct {
        pj_str_t method;       /**< Must be 'GET' */
        pj_str_t path;         /**< The request path */
        pj_str_t http_version; /**< The http version, http/1.1 */
    } req_line;

    pj_str_t host;        /**< The key 'HOST', value ip:port */
    pj_str_t connection;  /**< The key 'Connection', Must be 'Upgrade' */
    pj_str_t upgrade;     /**< The key 'Upgrade', Must be 'websocket */
    int websock_ver;      /**< The key 'Sec-WebSocket-Version' */
    pj_str_t websock_key; /**< The key 'Sec-WebSocket-Key' */
    pj_str_t subproto;    /**< The key 'Sec-WebSocket-Protocol' (optional) */

    pj_websock_http_hdr *hdrs; /**< Other http headers (optional) */
    int hdr_cnt;               /**< Other http headers count */
};

struct http_rsp_hdr {
    struct {
        pj_str_t http_version; /**< The http version, http/1.1 */
        int status_code;       /**< The status code */
        pj_str_t status_text;  /**< The status reason text */
    } status_line;
    pj_str_t connection;     /**< The key 'Connection', Must be 'Upgrade' */
    pj_str_t upgrade;        /**< The key 'Upgrade', Must be 'websocket */
    pj_str_t websock_accept; /**< The key 'Sec-WebSocket-Accept' */
    pj_str_t subproto;       /**< The key 'Sec-WebSocket-Protocol' (optional) */
};

struct pj_websock_t {
    PJ_DECL_LIST_MEMBER(struct pj_websock_t);
    pj_pool_t *pool;
    pj_websock_endpoint *endpt;

    pj_websock_cb cb;      /**< callbacks */
    const void *user_data; /**< user data */

    pj_bool_t is_srv;                  /**< whether is a server (listening) */
    pj_bool_t is_incoming;             /**< whether is incoming connection */
    pj_websock_t *parent;              /**< parent (only is_incoming=true)  */
    pj_websock_readystate state;       /**< current state */
    pj_sockaddr peer;                  /**< peer address */
    pj_websock_transport_type tp_type; /**< transport type */
    pj_websock_transport_t *tp;        /**< transport that used */

    struct http_req_hdr *http_req; /**< http request (only outgoing) */

    struct {
        pj_str_t paths[PJ_WEBSOCK_MAX_PATH_CNT];
        int path_cnt;

        pj_str_t subprotos[PJ_WEBSOCK_MAX_SUB_PROTO_CNT];
        int proto_cnt;
    } filter;

    pj_str_t req_path; /**< The request path that used */
    pj_str_t subproto; /** < The subproto that choose */

    pj_bool_t pending_payload;
    pj_websock_rx_data rdata;

    pj_timer_entry timer;
    pj_time_val ping_interval;
};

static pj_bool_t on_connect_complete(pj_websock_transport_t *t,
                                     pj_status_t status);

static pj_bool_t on_accept_complete(pj_websock_transport_t *t,
                                    pj_websock_transport_t *newt,
                                    const pj_sockaddr_t *src_addr,
                                    int src_addr_len);
static pj_bool_t on_data_read(pj_websock_transport_t *t,
                              void *data,
                              pj_size_t size,
                              pj_status_t status,
                              pj_size_t *remainder);

static pj_bool_t on_data_sent(pj_websock_transport_t *t,
                              pj_ioqueue_op_key_t *send_key,
                              pj_ssize_t sent);

static pj_status_t parse_http_req(char *data,
                                  pj_size_t size,
                                  struct http_req_hdr *req,
                                  pj_size_t *parse_len);

static pj_status_t parse_http_rsp(char *data,
                                  pj_size_t size,
                                  struct http_rsp_hdr *rsp,
                                  pj_size_t *parse_len);

static void generate_webosck_key(pj_pool_t *pool, pj_str_t *dst);
static void generate_websock_accept(const pj_str_t *key, char *buf, int *size);
static pj_bool_t validate_websock_accept(const pj_str_t *accept,
                                         const pj_str_t *key);
static pj_bool_t verify_srv_filter(pj_websock_t *srv,
                                   pj_websock_t *c,
                                   struct http_req_hdr *req);

void pj_websock_endpt_cfg_default(pj_websock_endpt_cfg *opt)
{
    pj_bzero(opt, sizeof(*opt));
    opt->max_rx_bufsize = 16000;
}

pj_status_t pj_websock_endpt_create(pj_websock_endpt_cfg *opt,
                                    pj_websock_endpoint **pendpt)
{
    pj_pool_t *pool;
    pj_websock_endpoint *endpt;
    PJ_ASSERT_RETURN(opt, PJ_EINVAL);
    PJ_ASSERT_RETURN(opt->pf, PJ_EINVAL);
    PJ_ASSERT_RETURN(opt->ioq, PJ_EINVAL);
    PJ_ASSERT_RETURN(opt->timer_heap, PJ_EINVAL);
    PJ_ASSERT_RETURN(pendpt, PJ_EINVAL);

    pool = pj_pool_create(opt->pf, "websock_ept%p", 500, 500, NULL);
    PJ_ASSERT_RETURN(pool, PJ_ENOMEM);

    endpt = PJ_POOL_ALLOC_T(pool, pj_websock_endpoint);
    PJ_ASSERT_RETURN(endpt, PJ_ENOMEM);
    endpt->pf = opt->pf;
    endpt->ioq = opt->ioq;
    endpt->timer_heap = opt->timer_heap;
    endpt->pool = pool;
    endpt->max_rx_bufsize = opt->max_rx_bufsize;

    if (opt->cert)
    {
        endpt->cert = PJ_POOL_ZALLOC_T(pool, pj_websock_ssl_cert);
        pj_strdup_with_null(pool, &endpt->cert->ca_file, &opt->cert->ca_file);
        pj_strdup_with_null(pool, &endpt->cert->cert_file,
                            &opt->cert->cert_file);
        pj_strdup_with_null(pool, &endpt->cert->private_file,
                            &opt->cert->private_file);
        pj_strdup_with_null(pool, &endpt->cert->private_pass,
                            &opt->cert->private_pass);
    }

    endpt->conn_list = PJ_POOL_ZALLOC_T(pool, pj_websock_t);
    pj_list_init(endpt->conn_list);

    *pendpt = endpt;

    return PJ_SUCCESS;
}

pj_status_t pj_websock_endpt_destroy(pj_websock_endpoint *endpt)
{
    if (!endpt)
        return PJ_EINVAL;
    while (pj_list_empty(endpt->conn_list) == PJ_FALSE)
    {
        pj_websock_t *c = endpt->conn_list->next;
        pj_websock_close(c, PJ_WEBSOCK_SC_NORMAL_CLOSURE, NULL);
    }

    pj_pool_release(endpt->pool);
    return PJ_SUCCESS;
}

static void on_syntax_error(struct pj_scanner *scanner)
{
    PJ_UNUSED_ARG(scanner);
    PJ_THROW(PJ_EINVAL);
}

static pj_status_t parse_req_url(const char *url,
                                 int *tp_type,
                                 int *af,
                                 pj_str_t *host,
                                 pj_uint16_t *port,
                                 pj_str_t *path)
{
    pj_status_t status;
    int default_port;
    pj_str_t WS = { "ws", 2 };
    pj_str_t WSS = { "wss", 3 };
    pj_scanner scanner;
    PJ_USE_EXCEPTION;

    pj_scan_init(&scanner, (char *)url, pj_ansi_strlen(url), 0,
                 on_syntax_error);

    PJ_TRY
    {
        pj_str_t s;
        /* parse protocol*/
        pj_scan_get_until_ch(&scanner, ':', &s);
        if (!pj_stricmp(&s, &WS))
        {
            *tp_type = PJ_WEBSOCK_TRANSPORT_TCP;
            default_port = 80;
        }
        else if (!pj_stricmp(&s, &WSS))
        {
            *tp_type = PJ_WEBSOCK_TRANSPORT_TLS;
            default_port = 443;
        }
        else
        {
            PJ_THROW(PJ_EINVAL);
        }

        /* skip "://" */
        pj_scan_advance_n(&scanner, 3, PJ_FALSE);

        /* skip user:password@ */
        pj_strset3(&s, scanner.curptr, scanner.end);
        if (pj_strchr(&s, '@'))
        {
            pj_scan_get_until_ch(&scanner, '@', &s);
            pj_scan_get_char(&scanner);
        }

        /* parse ip:port address string*/
        pj_scan_get_until_chr(&scanner, "/?", &s);

        status = pj_sockaddr_parse2(pj_AF_UNSPEC(), 0, &s, host, port, af);
        if (status != PJ_SUCCESS)
            PJ_THROW(status);
        if (*port == 0)
            *port = default_port;

        /* parse request path */
        if (pj_scan_is_eof(&scanner) || *scanner.curptr == '?')
        {
            *path = pj_str("/");
        }
        else
        {
            pj_scan_get_until_chr(&scanner, "?", path);
            while (path->slen > 1 && path->ptr[path->slen - 1] == '/')
            {
                /* strip path, eg. '/path/' to '/path' */
                path->slen--;
            }
        }
    }
    PJ_CATCH_ANY
    {
        pj_scan_fini(&scanner);
        status = PJ_GET_EXCEPTION();
    }
    PJ_END;

    return status;
}

static void generate_webosck_key(pj_pool_t *pool, pj_str_t *dst)
{
    pj_uint8_t nonce[16];
    char buf[80];
    int len = sizeof(buf);
    pj_str_t s;

    pj_create_random_string((char *)nonce, 16);
    pj_base64_encode((pj_uint8_t *)nonce, 16, buf, &len);
    pj_strset(&s, (char *)buf, len);
    pj_strdup_with_null(pool, dst, &s);
}

static void timer_callback(pj_timer_heap_t *heap, pj_timer_entry *e)
{
    pj_websock_t *c = (pj_websock_t *)e->user_data;
    char buf[1000];
    PJ_UNUSED_ARG(heap);

    if (c->timer.id == TIMER_ID_TIMEOUT)
    {
        PJ_LOG(2, (THIS_FILE, "!! %s negotiate timeout",
                   pj_websock_print(c, buf, sizeof(buf))));
        pj_assert(c->state == PJ_WEBSOCK_STATE_CONNECTING);
        c->timer.id = TIMER_ID_NONE;
        if (c->is_incoming)
        {
            /* incoming connection no request */
        }
        else
        {
            /* outgoing request no response */
            if (c->cb.on_connect_complete)
                c->cb.on_connect_complete(c, PJ_ETIMEDOUT);
        }

        /* close */
        pj_websock_close(c, PJ_WEBSOCK_SC_ABNORMAL_CLOSURE, NULL);
    }
    else if (c->timer.id == TIMER_ID_PING)
    {
        pj_assert(c->state == PJ_WEBSOCK_STATE_OPEN);
        pj_websock_send(c, PJ_WEBSOCK_OP_PING, PJ_TRUE, !c->is_incoming, 0, 0);

        /* next */
        pj_timer_heap_schedule(c->endpt->timer_heap, &c->timer,
                               &c->ping_interval);
    }
}

pj_status_t pj_websock_connect(pj_websock_endpoint *endpt,
                               const char *url,
                               const pj_websock_cb *cb,
                               const void *user_data,
                               pj_websock_http_hdr *hdrs,
                               int hdr_cnt,
                               pj_websock_t **pc)
{
    pj_status_t status;
    pj_websock_t *c;
    pj_pool_t *pool;

    int tp_type;
    int af;
    pj_uint16_t port;
    pj_str_t host;
    pj_str_t path;
    struct http_req_hdr *http_req;
    char buf[PJ_MAX_HOSTNAME];
    pj_websock_transport_param tp_param;

    PJ_ASSERT_RETURN(endpt, PJ_EINVAL);
    PJ_ASSERT_RETURN(url && url[0], PJ_EINVAL);
    PJ_ASSERT_RETURN(pc, PJ_EINVAL);

    pool = pj_pool_create(endpt->pf, "websock_c%p", 1000, 1000, NULL);
    PJ_ASSERT_RETURN(pool, PJ_ENOMEM);

    c = PJ_POOL_ZALLOC_T(pool, pj_websock_t);
    pj_timer_entry_init(&c->timer, TIMER_ID_NONE, c, timer_callback);
    c->pool = pool;
    c->state = PJ_WEBSOCK_STATE_CONNECTING;
    c->endpt = endpt;
    c->user_data = user_data;
    if (cb)
        pj_memcpy(&c->cb, cb, sizeof(*cb));

    /* parse request url */
    status = parse_req_url(url, &tp_type, &af, &host, &port, &path);
    if (status != PJ_SUCCESS)
    {
        PJ_PERROR(1, (THIS_FILE, status, "parse url:%s error", url));
        goto on_error;
    }
    c->tp_type = tp_type;
    pj_sockaddr_init(af, &c->peer, &host, port);
    pj_sockaddr_print(&c->peer, buf, sizeof(buf), 3);

    PJ_LOG(4, (THIS_FILE, "proto: %s, address: %s, path:%.*s",
               tp_type ? "WSS" : "WS", buf, (int)path.slen, path.ptr));

    /* Fill websock http request info */
    c->http_req = http_req = PJ_POOL_ZALLOC_T(pool, struct http_req_hdr);
    pj_strdup2_with_null(pool, &http_req->req_line.method, "GET");
    pj_strdup2_with_null(pool, &http_req->req_line.http_version, "1.1");
    pj_strdup_with_null(pool, &http_req->req_line.path, &path);
    pj_strdup2_with_null(pool, &http_req->host, buf);
    http_req->websock_ver = PJ_WEBSOCK_VERSION;
    generate_webosck_key(pool, &http_req->websock_key);
    if (hdr_cnt > 0 && hdrs)
    {
        int i;
        pj_websock_http_hdr *h;
        http_req->hdrs = pj_pool_alloc(pool, hdr_cnt * sizeof(hdrs[0]));
        PJ_ASSERT_RETURN(http_req->hdrs, PJ_ENOMEM);
        for (i = 0; i < hdr_cnt; i++)
        {
            h = http_req->hdrs + i;
            pj_strdup_with_null(pool, &h->key, &hdrs[i].key);
            pj_strdup_with_null(pool, &h->val, &hdrs[i].val);
        }
        http_req->hdr_cnt = hdr_cnt;
    }
    pj_strdup_with_null(pool, &c->req_path, &path); /* set target request path*/

    /* Create http transport and connect to peer */
    pj_websock_transport_param_default(&tp_param);
    tp_param.ioq = endpt->ioq;
    tp_param.pf = endpt->pf;
    tp_param.timer_heap = endpt->timer_heap;
    tp_param.max_rx_bufsize = endpt->max_rx_bufsize;

    switch (tp_type)
    {
    case PJ_WEBSOCK_TRANSPORT_TCP:
        status = pj_websock_transport_create_tcp(pool, &tp_param, &c->tp);
        break;
#if defined(PJ_HAS_SSL_SOCK) && PJ_HAS_SSL_SOCK != 0
    case PJ_WEBSOCK_TRANSPORT_TLS:
        status = pj_websock_transport_create_tls(pool, &tp_param, &c->tp);
        break;
#endif
    default:
        status = PJ_ENOTSUP;
        break;
    }
    if (status != PJ_SUCCESS)
    {
        PJ_PERROR(1, (THIS_FILE, status, "transport create error"));
        goto on_error;
    }
    c->tp->user_data = c;
    c->tp->cb.on_connect_complete = on_connect_complete;
    c->tp->cb.on_data_read = on_data_read;
    c->tp->cb.on_data_sent = on_data_sent;

    status = pj_websock_transport_start_connect(c->tp, &c->peer,
                                                pj_sockaddr_get_len(&c->peer));

    if (status == PJ_SUCCESS)
        return PJ_SUCCESS;

    if (status != PJ_EPENDING)
    {
        PJ_PERROR(1, (THIS_FILE, status, "transport start connect error"));
        goto on_error;
    }

    *pc = c;
    pj_list_push_front(endpt->conn_list, c);
    return status;
on_error:
    pj_pool_release(c->pool);
    *pc = NULL;
    return status;
}

pj_status_t pj_websock_close(pj_websock_t *c, int code, const char *reason)
{
    PJ_ASSERT_RETURN(c, PJ_EINVAL);
    pj_list_erase(c);
    if (c->timer.id != TIMER_ID_NONE)
    {
        pj_timer_heap_cancel(c->endpt->timer_heap, &c->timer);
        c->timer.id = TIMER_ID_NONE;
    }
    pj_websock_transport_destroy(c->tp);
    pj_pool_release(c->pool);
    // TODO:

    return PJ_SUCCESS;
}

pj_uint64_t pj_htonll(pj_uint64_t v)
{
    pj_uint64_t h = 0;
    pj_uint8_t *p = (pj_uint8_t *)&v;

    h |= (pj_uint64_t)*p++ << 56;
    h |= (pj_uint64_t)*p++ << 48;
    h |= (pj_uint64_t)*p++ << 40;
    h |= (pj_uint64_t)*p++ << 32;
    h |= (pj_uint64_t)*p++ << 24;
    h |= (pj_uint64_t)*p++ << 16;
    h |= (pj_uint64_t)*p++ << 8;
    h |= (pj_uint64_t)*p << 0;

    return h;
}

pj_uint64_t pj_ntohll(pj_uint64_t v)
{
    pj_uint64_t h;
    pj_uint8_t *p = (pj_uint8_t *)&h;

    *p++ = (pj_uint8_t)(v >> 56 & 0xff);
    *p++ = (pj_uint8_t)(v >> 48 & 0xff);
    *p++ = (pj_uint8_t)(v >> 40 & 0xff);
    *p++ = (pj_uint8_t)(v >> 32 & 0xff);
    *p++ = (pj_uint8_t)(v >> 24 & 0xff);
    *p++ = (pj_uint8_t)(v >> 16 & 0xff);
    *p++ = (pj_uint8_t)(v >> 8 & 0xff);
    *p = (pj_uint8_t)(v >> 0 & 0xff);

    return h;
}

pj_status_t pj_websock_send(pj_websock_t *c,
                            int opcode,
                            pj_bool_t fini,
                            pj_bool_t mask,
                            void *data,
                            pj_size_t len)
{
    pj_status_t status;
    pj_pool_t *pool;
    char *tx_buf;
    char *p;
    char *mkey = 0;
    char *pdata = 0;
    pj_ssize_t tx_len;
    pj_websock_tx_data *tdata;

    PJ_ASSERT_RETURN(c, PJ_EINVAL);
    PJ_ASSERT_RETURN(c->state == PJ_WEBSOCK_STATE_OPEN, PJ_EINVALIDOP);
    PJ_ASSERT_RETURN(len >= 0, PJ_EINVAL);

    pool = pj_pool_create(c->endpt->pf, "ws_tdata%p", 1000, 1000, NULL);
    tx_buf = (char *)pj_pool_alloc(pool, len + sizeof(pj_websock_frame_hdr));
    p = tx_buf;

    /* 1 bye: fini flag & opcode */
    *p++ = (fini << 7) | (opcode & 0x0f);

    /* mask flag & payload len */
    if (len <= 125)
    {
        /* 7bits */
        *p++ = (mask << 7) | (len & 0x7f);
    }
    else if (len <= 0xffff)
    {
        /* 7bits +  16bits */
        *p++ = (mask << 7) | 126;
        *((pj_uint16_t *)p) = pj_htons(len);
        p += 2;
    }
    else
    {
        /* 7 bits + 64 bits */
        *p++ = (mask << 7) | 127;
        *((pj_uint64_t *)p) = pj_htonll(len);
        p += 8;
    }

    /* 4 bytes: mask key */
    if (mask)
    {
        pj_create_random_string(p, 4);
        mkey = p;
        p += 4;
    }

    pdata = p;
    if (len > 0)
    {
        pj_memcpy(p, data, len);
        p += len;

        if (mask)
        {
            int i = 0;
            for (i = 0; i < len; i++)
                pdata[i] = pdata[i] ^ mkey[i % 4];
        }
    }

    tx_len = p - tx_buf;

    /* start send */
    tdata = PJ_POOL_ZALLOC_T(pool, pj_websock_tx_data);
    tdata->pool = pool;
    tdata->hdr.fin = fini;
    tdata->hdr.opcode = opcode;
    tdata->hdr.mask = mask;
    tdata->hdr.len = len;
    tdata->data = data;
    tdata->send_key.user_data = tdata;
    status =
        pj_websock_transport_send(c->tp, &tdata->send_key, tx_buf, &tx_len, 0);
    if (status == PJ_SUCCESS)
    {
        // pj_pool_release(pool);
        return PJ_SUCCESS;
    }

    if (status != PJ_EPENDING)
    {
        PJ_PERROR(1, (THIS_FILE, status, "send error"));
        pj_pool_release(pool);
        return status;
    }

    PJ_LOG(2, (THIS_FILE, "send, pending..."));

    return PJ_EPENDING;
}

pj_status_t pj_websock_listen(pj_websock_endpoint *endpt,
                              int tp_type,
                              pj_sockaddr_t *local_addr,
                              pj_websock_cb *cb,
                              const void *user_data,
                              pj_websock_t **s)
{
    pj_status_t status;
    pj_websock_t *ws;
    pj_pool_t *pool;
    pj_websock_transport_param tp_param;
    pj_websock_transport_t *tp = NULL;
    char sbuf[200];

    PJ_ASSERT_RETURN(endpt, PJ_EINVAL);
    PJ_ASSERT_RETURN(local_addr, PJ_EINVAL);
    pool = pj_pool_create(endpt->pf, "ws_srv%p", 1000, 1000, NULL);
    ws = PJ_POOL_ZALLOC_T(pool, pj_websock_t);
    ws->pool = pool;
    ws->endpt = endpt;

    pj_websock_transport_param_default(&tp_param);
    tp_param.ioq = endpt->ioq;
    tp_param.pf = endpt->pf;
    tp_param.timer_heap = endpt->timer_heap;
    tp_param.max_rx_bufsize = endpt->max_rx_bufsize;

    pj_sockaddr_print(local_addr, sbuf, sizeof(sbuf), 3);
    PJ_LOG(3, (THIS_FILE, "listen %s %s", sbuf,
               pj_websock_transport_str(tp_type)));

    switch (tp_type)
    {
    case PJ_WEBSOCK_TRANSPORT_TCP:
        status = pj_websock_transport_create_tcp(pool, &tp_param, &tp);
        break;
#if defined(PJ_HAS_SSL_SOCK) && PJ_HAS_SSL_SOCK != 0
    case PJ_WEBSOCK_TRANSPORT_TLS:
        if (endpt->cert)
        {
            tp_param.cert.ca_file = endpt->cert->ca_file;
            tp_param.cert.cert_file = endpt->cert->cert_file;
            tp_param.cert.private_file = endpt->cert->private_file;
            tp_param.cert.private_pass = endpt->cert->private_pass;
        }
        status = pj_websock_transport_create_tls(pool, &tp_param, &tp);
        break;
#endif
    default:
        status = PJ_ENOTSUP;
        break;
    }
    if (status != PJ_SUCCESS)
    {
        PJ_PERROR(1, (THIS_FILE, status, "server create transport"));
        goto on_error;
    }

    tp->user_data = ws;
    tp->cb.on_accept_complete = on_accept_complete;
    status = pj_websock_transport_start_accept(tp, local_addr,
                                               pj_sockaddr_get_len(local_addr));
    if (status != PJ_SUCCESS)
    {
        PJ_PERROR(1, (THIS_FILE, status, "server start accept"));
        goto on_error;
    }

    ws->tp = tp;
    ws->tp_type = tp_type;
    ws->is_srv = PJ_TRUE;
    ws->user_data = user_data;
    if (cb)
        pj_memcpy(&ws->cb, cb, sizeof(*cb));

    pj_list_push_front(endpt->conn_list, ws);

    *s = ws;
    return PJ_SUCCESS;

on_error:
    if (tp)
        pj_websock_transport_destroy(tp);
    pj_pool_release(pool);
    return status;
}

pj_status_t pj_websock_set_callbacks(pj_websock_t *c, const pj_websock_cb *cb)
{
    PJ_ASSERT_RETURN(c, PJ_EINVAL);
    if (cb)
    {
        pj_memcpy(&c->cb, cb, sizeof(*cb));
    }
    else
    {
        pj_bzero(&c->cb, sizeof(c->cb));
    }
    return PJ_SUCCESS;
}

pj_status_t pj_websock_set_userdata(pj_websock_t *c, const void *user_data)
{
    PJ_ASSERT_RETURN(c, PJ_EINVAL);
    c->user_data = user_data;
    return PJ_SUCCESS;
}

int pj_websock_get_ready_state(pj_websock_t *c)
{
    PJ_ASSERT_RETURN(c, -1);
    return c->state;
}

const void *pj_websock_get_userdata(pj_websock_t *c)
{
    PJ_ASSERT_RETURN(c, NULL);
    return c->user_data;
}

pj_status_t pj_websock_enable_ping(pj_websock_t *c, pj_time_val *t)
{
    PJ_ASSERT_RETURN(c, PJ_EINVAL);
    PJ_ASSERT_RETURN(!c->is_srv, PJ_EINVALIDOP); /* should't listening server */

    if (t && PJ_TIME_VAL_MSEC(*t))
    {
        /* enable*/
        if (c->state != PJ_WEBSOCK_STATE_OPEN)
        {
            PJ_LOG(2, (THIS_FILE, "%s state is not OPEN", c->pool->obj_name));
            return PJ_EINVALIDOP;
        }

        if (c->timer.id != TIMER_ID_NONE)
        {
            return PJ_EIGNORED;
        }

        pj_timer_heap_schedule(c->endpt->timer_heap, &c->timer, t);
        c->timer.id = TIMER_ID_PING;
        c->ping_interval = *t;
    }
    else
    {
        /* disable */
        if (c->timer.id != TIMER_ID_PING)
        {
            return PJ_EIGNORED;
        }
        pj_timer_heap_cancel(c->endpt->timer_heap, &c->timer);
        c->timer.id = TIMER_ID_NONE;
    }

    return PJ_SUCCESS;
}

pj_bool_t pj_websock_is_incoming(pj_websock_t *c)
{
    PJ_ASSERT_RETURN(c, PJ_FALSE);
    return c->is_incoming;
}

const char *pj_websock_get_request_path(pj_websock_t *c)
{
    PJ_ASSERT_RETURN(c, NULL);
    return c->req_path.ptr;
}

const char *pj_websock_get_subproto(pj_websock_t *c)
{
    PJ_ASSERT_RETURN(c, NULL);
    return c->subproto.ptr;
}

const char *pj_websock_print(pj_websock_t *c, char *buf, int len)
{
    char *p = buf;
    char *end = buf + len;
    PJ_ASSERT_RETURN(c, NULL);
    PJ_ASSERT_RETURN(buf, NULL);
    PJ_ASSERT_RETURN(len > 0, NULL);

    p += pj_ansi_snprintf(p, end - p, "%s", c->pool->obj_name);
    p += pj_ansi_snprintf(p, end - p, ",path:%s", c->req_path.ptr);
    p += pj_ansi_snprintf(p, end - p, ",sub-proto:%s,", c->subproto.ptr);
    pj_sockaddr_print(&c->peer, p, end - p, 3);

    return buf;
}

const char *pj_websock_opcode_str(int opcode)
{
    switch (opcode)
    {
    case PJ_WEBSOCK_OP_TEXT:
        return "TEXT";
    case PJ_WEBSOCK_OP_BIN:
        return "BIN";
    case PJ_WEBSOCK_OP_CONTN:
        return "CONTN";
    case PJ_WEBSOCK_OP_PING:
        return "PING";
    case PJ_WEBSOCK_OP_PONG:
        return "PONG";
    case PJ_WEBSOCK_OP_CLOSE:
        return "CLOSE";
    default:
        break;
    }
    return "?";
}

const char *pj_websock_state_str(int state)
{
    switch (state)
    {
    case PJ_WEBSOCK_STATE_CONNECTING:
        return "CONNECTING";
    case PJ_WEBSOCK_STATE_OPEN:
        return "OPEN";
    case PJ_WEBSOCK_STATE_CLOSING:
        return "CLOSING";
    case PJ_WEBSOCK_STATE_CLOSED:
        return "CLOSED";
    default:
        break;
    }
    return "?";
}

const char *pj_websock_transport_str(int type)
{
    switch (type)
    {
    case PJ_WEBSOCK_TRANSPORT_TCP:
        return "TCP";
    case PJ_WEBSOCK_TRANSPORT_TLS:
        return "TLS";
    default:
        break;
    }
    return "?";
}

pj_status_t pj_websock_set_support_path(pj_websock_t *srv,
                                        pj_str_t paths[],
                                        int cnt)
{
    int i = 0;
    PJ_ASSERT_RETURN(srv, PJ_EINVAL);
    PJ_ASSERT_RETURN(srv->is_srv, PJ_EINVALIDOP);
    PJ_ASSERT_RETURN(cnt <= PJ_WEBSOCK_MAX_PATH_CNT, PJ_ETOOMANY);

    for (i = 0; i < cnt; i++)
    {
        pj_strdup_with_null(srv->pool, &srv->filter.paths[i], &paths[i]);
    }
    srv->filter.path_cnt = cnt;

    return PJ_SUCCESS;
}
pj_status_t pj_websock_set_support_subproto(pj_websock_t *srv,
                                            pj_str_t protos[],
                                            int cnt)
{
    int i = 0;
    PJ_ASSERT_RETURN(srv, PJ_EINVAL);
    PJ_ASSERT_RETURN(srv->is_srv, PJ_EINVALIDOP);
    PJ_ASSERT_RETURN(cnt <= PJ_WEBSOCK_MAX_SUB_PROTO_CNT, PJ_ETOOMANY);

    for (i = 0; i < cnt; i++)
    {
        pj_strdup_with_null(srv->pool, &srv->filter.subprotos[i], &protos[i]);
    }
    srv->filter.proto_cnt = cnt;

    return PJ_SUCCESS;
}

static pj_bool_t on_connect_complete(pj_websock_transport_t *t,
                                     pj_status_t status)
{
    pj_websock_t *c = (pj_websock_t *)t->user_data;

    PJ_PERROR(4, (THIS_FILE, status, "%s() %s status:%d", __FUNCTION__,
                  c->pool->obj_name, status));

    if (status != PJ_SUCCESS)
    {
        /* pengding connect fail */
        if (c->cb.on_connect_complete)
            c->cb.on_connect_complete(c, status);
        c->state = PJ_WEBSOCK_STATE_CLOSED;
        pj_websock_close(c, PJ_WEBSOCK_SC_ABNORMAL_CLOSURE, NULL);
        return PJ_FALSE;
    }

    /*create and send http request */
    {
        pj_pool_t *pool =
            pj_pool_create(c->endpt->pf, "ws_tdata%p", 4000, 500, NULL);
        int len = 4000;
        char *buf = (char *)pj_pool_alloc(pool, len);
        char *p = buf;
        char *end = p + len;
        struct http_req_hdr *req = c->http_req;
        int i;
        pj_websock_http_hdr *h;
        pj_ssize_t size;
        pj_websock_tx_data *tdata = PJ_POOL_ZALLOC_T(pool, pj_websock_tx_data);

        /* request line */
        p += pj_ansi_snprintf(p, end - p, "%s %s HTTP/%s\r\n",
                              req->req_line.method.ptr, req->req_line.path.ptr,
                              req->req_line.http_version.ptr);
        /* host */
        p += pj_ansi_snprintf(p, end - p, "Host: %s\r\n", req->host.ptr);

        /* connection */
        p += pj_ansi_snprintf(p, end - p, "Connection: Upgrade\r\n");

        /* upgrade */
        p += pj_ansi_snprintf(p, end - p, "Upgrade: websocket\r\n");

        /* Sec-WebSocket-Version */
        p += pj_ansi_snprintf(p, end - p, "Sec-WebSocket-Version: %d\r\n",
                              req->websock_ver);

        /* Sec-WebSocket-Key */
        p += pj_ansi_snprintf(p, end - p, "Sec-WebSocket-Key: %s\r\n",
                              req->websock_key.ptr);

        /* Other headers */
        for (i = 0; i < req->hdr_cnt; i++)
        {
            h = req->hdrs + i;
            p += pj_ansi_snprintf(p, end - p, "%s: %s\r\n", h->key.ptr,
                                  h->val.ptr);
        }
        *p++ = '\r';
        *p++ = '\n';
        *p = '\0';

        size = p - buf;
        PJ_LOG(4, (THIS_FILE, "request:\n[%s], len=%d", buf, size));

        tdata->pool = pool;
        tdata->data = buf;
        tdata->hdr.len = size;
        tdata->send_key.user_data = tdata;
        pj_websock_transport_send(c->tp, &tdata->send_key, buf, &size, 0);

        /* start timer to check if recv peer response timeout */
        c->timer.id = TIMER_ID_TIMEOUT;
        pj_timer_heap_schedule(c->endpt->timer_heap, &c->timer, &DELAY_TIMEOUT);
    }

    return PJ_TRUE;
}

static pj_bool_t on_accept_complete(pj_websock_transport_t *t,
                                    pj_websock_transport_t *newt,
                                    const pj_sockaddr_t *src_addr,
                                    int src_addr_len)
{
    pj_websock_t *parent = (pj_websock_t *)t->user_data;
    pj_websock_t *newc;
    pj_websock_endpoint *endpt = parent->endpt;
    pj_pool_t *pool;
    char buf[80];

    PJ_LOG(5, (THIS_FILE, "%s() %s", __FUNCTION__,
               pj_sockaddr_print(src_addr, buf, sizeof(buf), 3)));

    /* new websocket connection */
    pool = pj_pool_create(endpt->pf, "websock_s%p", 1000, 1000, NULL);
    newc = PJ_POOL_ZALLOC_T(pool, pj_websock_t);
    pj_timer_entry_init(&newc->timer, TIMER_ID_NONE, newc, timer_callback);
    newc->state = PJ_WEBSOCK_STATE_CONNECTING;
    newc->pool = pool;
    newc->endpt = endpt;
    newc->is_incoming = PJ_TRUE;
    pj_sockaddr_cp(&newc->peer, src_addr);
    newc->tp = newt;
    newc->tp_type = parent->tp_type;
    newc->parent = parent;

    /* setup transport callbacks */
    newt->user_data = newc;
    newt->cb.on_data_read = on_data_read;
    newt->cb.on_data_sent = on_data_sent;

    pj_list_push_front(endpt->conn_list, newc);

    /* start timer to check if recv peer request timeout */
    newc->timer.id = TIMER_ID_TIMEOUT;
    pj_timer_heap_schedule(endpt->timer_heap, &newc->timer, &DELAY_TIMEOUT);

    return PJ_TRUE;
}

static void unmask_payload(pj_uint8_t *mkey,
                           pj_uint8_t *p,
                           pj_uint64_t len,
                           pj_uint64_t last_idx)
{
    pj_uint64_t i;
    if (len <= 0)
        return;
    for (i = 0; i < len; i++)
    {
        p[i] = p[i] ^ mkey[(i + last_idx) % 4];
    }
}

static pj_status_t http_reply_forbidden(pj_websock_t *c)
{
    pj_pool_t *pool;
    pj_websock_tx_data *tdata;
    char *p, *end;
    pj_ssize_t tx_len;

    pool = pj_pool_create(c->endpt->pf, "websock_tdata%p", 1000, 1000, NULL);
    tdata = PJ_POOL_ZALLOC_T(pool, pj_websock_tx_data);
    p = (char *)pj_pool_alloc(pool, 1000);
    end = p + 1000;
    tdata->pool = pool;
    tdata->data = p;
    tdata->send_key.user_data = tdata;

    p += pj_ansi_snprintf(p, end - p,
                          "HTTP/1.1 403 Forbidden\r\n"
                          "Content-Length: 0\r\n"
                          "\r\n");
    tx_len = p - (char *)tdata->data;
    PJ_LOG(4, (THIS_FILE, "TX to %s\n[%.*s]", c->pool->obj_name, (int)tx_len,
               (char *)tdata->data));
    pj_websock_transport_send(c->tp, &tdata->send_key, tdata->data, &tx_len, 0);

    return PJ_SUCCESS;
}

static pj_status_t http_reply_switching(pj_websock_t *c,
                                        const pj_str_t *websock_key)
{
    pj_pool_t *pool;
    pj_websock_tx_data *tdata;
    char *p, *end;
    pj_ssize_t tx_len;
    char accept[200];
    int accept_len = sizeof(accept);

    pool = pj_pool_create(c->endpt->pf, "websock_tdata%p", 1000, 1000, NULL);
    tdata = PJ_POOL_ZALLOC_T(pool, pj_websock_tx_data);
    p = (char *)pj_pool_alloc(pool, 1000);
    end = p + 1000;
    tdata->pool = pool;
    tdata->data = p;
    tdata->send_key.user_data = tdata;

    p += pj_ansi_snprintf(p, end - p,
                          "HTTP/1.1 101 Switching Protocols\r\n"
                          "Upgrade:websocket\r\n"
                          "Connection: Upgrade\r\n");
    generate_websock_accept(websock_key, accept, &accept_len);
    p += pj_ansi_snprintf(p, end - p, "Sec-WebSocket-Accept: %.*s\r\n",
                          accept_len, accept);

    if (c->subproto.slen > 0)
    {
        p += pj_ansi_snprintf(p, end - p, "Sec-WebSocket-Protocol: %.*s\r\n",
                              (int)c->subproto.slen, c->subproto.ptr);
    }
    *p++ = '\r';
    *p++ = '\n';
    tx_len = p - (char *)tdata->data;

    PJ_LOG(4, (THIS_FILE, "TX to %s\n[%.*s]", c->pool->obj_name, (int)tx_len,
               (char *)tdata->data));
    pj_websock_transport_send(c->tp, &tdata->send_key, tdata->data, &tx_len, 0);

    return PJ_SUCCESS;
}

static pj_bool_t on_data_read(pj_websock_transport_t *t,
                              void *data,
                              pj_size_t size,
                              pj_status_t status,
                              pj_size_t *remainder)
{
    pj_websock_t *c = (pj_websock_t *)t->user_data;
    pj_size_t left_size = size;
    char *pdata = (char *)data;
    pj_websock_rx_data *rdata = &c->rdata;

    if (status != PJ_SUCCESS)
    {
        if (c->cb.on_rx_msg)
            c->cb.on_rx_msg(c, NULL, status);
        pj_websock_close(c, PJ_WEBSOCK_SC_GOING_AWAY, NULL);
        return PJ_FALSE;
    }

again:

    if (c->state == PJ_WEBSOCK_STATE_CONNECTING && c->timer.id != TIMER_ID_NONE)
    {
        pj_timer_heap_cancel(c->endpt->timer_heap, &c->timer);
        c->timer.id = TIMER_ID_NONE;
    }

    if (c->state == PJ_WEBSOCK_STATE_CONNECTING && c->is_incoming == PJ_FALSE)
    {
        /* Outgoing websock connection recv http response */

        /* parse the http response */
        struct http_rsp_hdr rsp;
        pj_size_t parse_len = 0;
        PJ_LOG(4, (THIS_FILE, "%s start parse response:\n%.*s",
                   c->pool->obj_name, (int)left_size, pdata));
        status = parse_http_rsp(pdata, left_size, &rsp, &parse_len);
        if (status != PJ_SUCCESS)
            PJ_PERROR(2, (THIS_FILE, status, "parse response"));
        if (status == PJ_EPENDING)
        {
            /* has pending data to read */
            goto on_pending;
        }
        else if (status != PJ_SUCCESS)
        {
            /* parse error */
            pj_websock_close(c, PJ_WEBSOCK_SC_PROTOCOL_ERROR, NULL);
            return PJ_FALSE;
        }
        else
        {
            /* verify Sec-WebSocket-Accept with request Sec-WebSocket-Key */
            if (!validate_websock_accept(&rsp.websock_accept,
                                         &c->http_req->websock_key))
            {
                /* parse error */
                PJ_LOG(1, (THIS_FILE, "validate websock-accept fail"));
                if (c->cb.on_connect_complete)
                    c->cb.on_connect_complete(c, -PJ_WEBSOCK_SC_PROTOCOL_ERROR);
                pj_websock_close(c, PJ_WEBSOCK_SC_PROTOCOL_ERROR, NULL);
                return PJ_FALSE;
            }

            /* TODO: verify resp subproto match with request*/
            if (rsp.subproto.slen > 0)
            {
                pj_strdup_with_null(c->pool, &c->subproto, &rsp.subproto);
            }

            /* change state to connected */
            c->state = PJ_WEBSOCK_STATE_OPEN;
            if (c->cb.on_connect_complete)
                c->cb.on_connect_complete(c, PJ_SUCCESS);

            /* left size */
            left_size -= parse_len;
            pdata += parse_len;
        }
    }
    else if (c->state == PJ_WEBSOCK_STATE_CONNECTING &&
             c->is_incoming == PJ_TRUE)
    {
        /* Incoming websock connection recv http request */

        /* Parse the http request */
        struct http_req_hdr req;
        pj_size_t parse_len = 0;
        PJ_LOG(4, (THIS_FILE, "%s start parse request:\n%.*s",
                   c->pool->obj_name, (int)left_size, pdata));
        status = parse_http_req(pdata, left_size, &req, &parse_len);
        if (status != PJ_SUCCESS)
            PJ_PERROR(2, (THIS_FILE, status, "parse request"));
        if (status == PJ_EPENDING)
        {
            /* has pending data to read */
            goto on_pending;
        }
        else if (status != PJ_SUCCESS)
        {
            /* parse error */
            http_reply_forbidden(c);
            pj_websock_close(c, PJ_WEBSOCK_SC_PROTOCOL_ERROR, NULL);
            return PJ_FALSE;
        }
        else
        {
            pj_websock_t *parent = c->parent;

            /* verify request path and sub-protols by server filter */
            if (verify_srv_filter(parent, c, &req) == PJ_FALSE)
            {
                http_reply_forbidden(c);
                pj_websock_close(c, PJ_WEBSOCK_SC_PROTOCOL_ERROR, NULL);
                return PJ_FALSE;
            }

            /* reply 101 switching */
            http_reply_switching(c, &req.websock_key);

            /* change state to connected */
            c->state = PJ_WEBSOCK_STATE_OPEN;
            if (parent->cb.on_accept_complete)
            {
                /* Should Parent notify this event */
                parent->cb.on_accept_complete(c, &c->peer,
                                              pj_sockaddr_get_len(&c->peer));
            }
        }

        /* left size */
        left_size -= parse_len;
        pdata += parse_len;
    }
    else if (c->state == PJ_WEBSOCK_STATE_OPEN)
    {
        /* parse the incoming frame data */
        pj_uint8_t *p = (pj_uint8_t *)pdata;
        pj_uint8_t *paylod = NULL; /* payload data */
        pj_uint64_t len = 0;
        pj_websock_frame_hdr *hdr = &rdata->hdr;
        pj_uint8_t *mkey = hdr->mkey; /* mask key */
        pj_uint64_t expect_len;

        if (c->pending_payload == PJ_FALSE)
        {
            expect_len = 2;
            if (left_size < expect_len)
            {
                goto on_pending;
            }

            pj_bzero(rdata, sizeof(*rdata));
            hdr->fin = p[0] >> 7;
            hdr->opcode = p[0] & 0x0f;
            hdr->mask = p[1] >> 7;
            len = p[1] & 0x7f;
            if (hdr->mask)
                expect_len += 4;
            if (left_size < expect_len)
            {
                goto on_pending;
            }
            p += 2;

            /* get payload length */
            if (len <= 125)
            {
                expect_len += len;
            }
            else if (len == 126)
            {
                expect_len += 2; /* 16bit length */
                if (left_size < expect_len)
                {
                    goto on_pending;
                }

                len = pj_ntohs(*(pj_uint16_t *)p);
                expect_len += len;
                p += 2;
            }
            else
            {
                expect_len += 8; /* 64bit length */
                if (left_size < expect_len)
                {
                    goto on_pending;
                }

                len = pj_ntohll(*(pj_uint64_t *)p);
                expect_len += len;
                p += 8;
            }

            hdr->len = len;

            /* Get mask key */
            if (hdr->mask)
            {
                pj_memcpy(hdr->mkey, p, 4);
                p += 4;
            }

            /* Get payload */
            if (left_size < expect_len)
            {
                goto on_pending_payload;
            }

            /* unmask payload */
            if (len > 0 && hdr->mask)
                unmask_payload(mkey, p, len, rdata->has_read);
            paylod = p;
            p += len;
        }
        else
        {
            expect_len = hdr->len - rdata->has_read;
            if (left_size < expect_len)
            {
                goto on_pending_payload;
            }

            len = expect_len;
            /* unmask payload */
            if (len > 0 && hdr->mask)
                unmask_payload(mkey, p, len, rdata->has_read);
            paylod = p;
            p += len;
        }

        /* Notify recv msg event */
        rdata->data = paylod;
        rdata->data_len = len;
        rdata->has_read += len;

        if (c->cb.on_rx_msg)
        {
            if (!c->cb.on_rx_msg(c, rdata, status))
                return PJ_FALSE;
        }
        c->pending_payload = PJ_FALSE;

        /* left size */
        len = p - (pj_uint8_t *)pdata;
        left_size -= len;
        pdata += len;
    }

    if (left_size > 0)
        goto again;
    return PJ_TRUE;

on_pending:
    *remainder = left_size;
    if (*remainder >= c->endpt->max_rx_bufsize)
    {
        PJ_LOG(2, (THIS_FILE, "!!!read buffer is full (%d/%d)",
                   c->endpt->max_rx_bufsize, left_size));
    }
    return PJ_TRUE;

on_pending_payload:
    *remainder = left_size;
    c->pending_payload = PJ_TRUE;
    if (*remainder >= c->endpt->max_rx_bufsize)
    {
        pj_uint64_t exclude_len = 0;
        if (rdata->has_read == 0)
        {
            /* Exclude the frame header */
            exclude_len = 2;
            if (rdata->hdr.len > 0xffff)
                exclude_len += 8;
            else if (rdata->hdr.len > 125)
                exclude_len += 2;
            if (rdata->hdr.mask)
                exclude_len += 4;
        }
        rdata->data = pdata + exclude_len;
        rdata->data_len = c->endpt->max_rx_bufsize - exclude_len;
        /* unmask payload */
        if (rdata->data_len > 0 && rdata->hdr.mask)
            unmask_payload(rdata->hdr.mkey, (pj_uint8_t *)rdata->data,
                           rdata->data_len, rdata->has_read);
        rdata->has_read += rdata->data_len;
        if (c->cb.on_rx_msg)
        {
            if (!c->cb.on_rx_msg(c, rdata, status))
                return PJ_FALSE;
        }
        *remainder -= c->endpt->max_rx_bufsize;
    }
    return PJ_TRUE;
}

static pj_bool_t on_data_sent(pj_websock_transport_t *t,
                              pj_ioqueue_op_key_t *send_key,
                              pj_ssize_t sent)
{
    pj_websock_t *c = (pj_websock_t *)t->user_data;
    pj_websock_tx_data *tdata = (pj_websock_tx_data *)send_key->user_data;
    PJ_LOG(6, (THIS_FILE, "%s() %s sent:%d", __FUNCTION__, c->pool->obj_name,
               sent));
    if (c->state == PJ_WEBSOCK_STATE_OPEN)
    {
        if (c->cb.on_tx_msg)
            c->cb.on_tx_msg(c, tdata, sent);
    }

    pj_pool_release(tdata->pool);

    return PJ_TRUE;
}

static void parse_rsp_status_line(pj_scanner *pscanner,
                                  pj_str_t *ver,
                                  int *status_code,
                                  pj_str_t *status_text)
{
    /*
     * sample:
     *   HTTP/1.1 101 Switching Protocols\r\n
     */
    pj_str_t s;
    pj_str_t HTTP = { "HTTP", 4 };

    /* http */
    pj_scan_get_until_ch(pscanner, '/', &s);
    if (pj_stricmp(&s, &HTTP))
        PJ_THROW(PJ_EINVAL);
    if (*pscanner->curptr != '/')
        PJ_THROW(PJ_EINVAL);
    pj_scan_get_char(pscanner);

    /* version */
    pj_scan_get_until_ch(pscanner, ' ', ver);
    pj_scan_get_char(pscanner);

    /* status code */
    pj_scan_get_until_ch(pscanner, ' ', &s);
    pj_scan_get_char(pscanner);
    *status_code = pj_strtol(&s);

    /* status text */
    pj_scan_get_until_ch(pscanner, '\r', status_text);
    if (*pscanner->curptr != '\r')
        PJ_THROW(PJ_EINVAL);
    pj_scan_get_char(pscanner);
    if (*pscanner->curptr != '\n')
        PJ_THROW(PJ_EINVAL);
    pj_scan_get_char(pscanner);
}

static void parse_rsp_headers(pj_scanner *pscanner, struct http_rsp_hdr *rsp)
{
    pj_str_t k, v;

    while (!pj_scan_is_eof(pscanner))
    {
        if (*pscanner->curptr == '\r')
        {
            PJ_LOG(6, (THIS_FILE, "Finish parse headers"));
            pj_scan_advance_n(pscanner, 2, PJ_FALSE);
            break;
        }

        pj_scan_get_until_chr(pscanner, ":\n", &k);
        pj_scan_advance_n(pscanner, 1, PJ_TRUE);
        pj_scan_get_until_ch(pscanner, '\r', &v);
        if (*pscanner->curptr != '\r')
            PJ_THROW(PJ_EINVAL);
        pj_scan_get_char(pscanner);
        if (*pscanner->curptr != '\n')
            PJ_THROW(PJ_EINVAL);
        pj_scan_get_char(pscanner);

        if (!pj_stricmp2(&k, "Upgrade"))
        {
            if (pj_stricmp2(&v, "websocket"))
                PJ_THROW(PJ_EINVAL);
            pj_strassign(&rsp->upgrade, &v);
        }
        else if (!pj_stricmp2(&k, "Connection"))
        {
            if (pj_stricmp2(&v, "Upgrade"))
                PJ_THROW(PJ_EINVAL);
            pj_strassign(&rsp->connection, &v);
        }
        else if (!pj_stricmp2(&k, "Sec-WebSocket-Accept"))
        {
            pj_strassign(&rsp->websock_accept, &v);
        }
        else if (!pj_stricmp2(&k, "Sec-WebSocket-Protocol"))
        {
            pj_strassign(&rsp->subproto, &v);
        }
    }
}

static void parse_req_line(pj_scanner *pscanner,
                           pj_str_t *method,
                           pj_str_t *path,
                           pj_str_t *ver)
{
    /*
     * sample:
     *   GET /chat HTTP/1.1\r\n
     */
    pj_str_t s;
    pj_str_t HTTP = { "HTTP", 4 };

    /* method */
    pj_scan_get_until_ch(pscanner, ' ', method);
    pj_scan_get_char(pscanner);

    /* path */
    pj_scan_get_until_ch(pscanner, ' ', path);
    pj_scan_get_char(pscanner);

    /* http */
    pj_scan_get_until_ch(pscanner, '/', &s);
    if (pj_stricmp(&s, &HTTP))
        PJ_THROW(PJ_EINVAL);
    pj_scan_get_char(pscanner);

    /* version */
    pj_scan_get_until_ch(pscanner, '\r', ver);

    /* skip "\r\n" */
    if (*pscanner->curptr != '\r')
        PJ_THROW(PJ_EINVAL);
    pj_scan_get_char(pscanner);
    if (*pscanner->curptr != '\n')
        PJ_THROW(PJ_EINVAL);
    pj_scan_get_char(pscanner);
}

static void parse_req_headers(pj_scanner *pscanner, struct http_req_hdr *req)
{
    pj_str_t k, v;

    while (!pj_scan_is_eof(pscanner))
    {
        if (*pscanner->curptr == '\r')
        {
            PJ_LOG(6, (THIS_FILE, "Finish parse headers"));
            pj_scan_advance_n(pscanner, 2, PJ_FALSE);
            break;
        }

        pj_scan_get_until_chr(pscanner, ":\n", &k);
        pj_scan_advance_n(pscanner, 1, PJ_TRUE);
        pj_scan_get_until_ch(pscanner, '\r', &v);
        if (*pscanner->curptr != '\r')
            PJ_THROW(PJ_EINVAL);
        pj_scan_get_char(pscanner);
        if (*pscanner->curptr != '\n')
            PJ_THROW(PJ_EINVAL);
        pj_scan_get_char(pscanner);

        if (!pj_stricmp2(&k, "Upgrade"))
        {
            if (pj_stricmp2(&v, "websocket"))
                PJ_THROW(PJ_EINVAL);
            pj_strassign(&req->upgrade, &v);
        }
        else if (!pj_stricmp2(&k, "Connection"))
        {
            if (pj_stricmp2(&v, "Upgrade"))
                PJ_THROW(PJ_EINVAL);
            pj_strassign(&req->connection, &v);
        }
        else if (!pj_stricmp2(&k, "Sec-WebSocket-Key"))
        {
            pj_strassign(&req->websock_key, &v);
        }
        else if (!pj_stricmp2(&k, "Sec-WebSocket-Version"))
        {
            int ver = pj_strtol(&v);
            if (ver != PJ_WEBSOCK_VERSION)
                PJ_THROW(PJ_EINVAL);
        }
        else if (!pj_stricmp2(&k, "Sec-WebSocket-Protocol"))
        {
            pj_strassign(&req->subproto, &v);
        }
    }
}

static pj_status_t parse_http_req(char *data,
                                  pj_size_t size,
                                  struct http_req_hdr *req,
                                  pj_size_t *parse_len)
{
    pj_status_t status = PJ_SUCCESS;
    pj_scanner scanner;
    PJ_USE_EXCEPTION;

    pj_scan_init(&scanner, data, size, 0, on_syntax_error);

    PJ_TRY
    {
        pj_str_t GET = { "GET", 3 };
        pj_bzero(req, sizeof(*req));
        /* parse request line */
        parse_req_line(&scanner, &req->req_line.method, &req->req_line.path,
                       &req->req_line.http_version);
        if (pj_stricmp(&req->req_line.method, &GET))
            PJ_THROW(PJ_EINVAL);

        /* parse headers */
        parse_req_headers(&scanner, req);
        if (!req->connection.slen || !req->upgrade.slen ||
            !req->websock_key.slen)
        {
            /* These headers should not be null */
            PJ_THROW(PJ_EINVAL);
        }
    }
    PJ_CATCH_ANY
    {
        status = PJ_GET_EXCEPTION();
    }
    PJ_END
    pj_scan_fini(&scanner);
    if (status == PJ_SUCCESS)
    {
        *parse_len = scanner.curptr - data;
    }

    return status;
}

static pj_status_t parse_http_rsp(char *data,
                                  pj_size_t size,
                                  struct http_rsp_hdr *rsp,
                                  pj_size_t *parse_len)
{
    pj_status_t status = PJ_SUCCESS;
    pj_scanner scanner;
    PJ_USE_EXCEPTION;

    pj_scan_init(&scanner, data, size, 0, on_syntax_error);

    PJ_TRY
    {
        pj_bzero(rsp, sizeof(*rsp));
        /* parse status line */
        parse_rsp_status_line(&scanner, &rsp->status_line.http_version,
                              &rsp->status_line.status_code,
                              &rsp->status_line.status_text);
        if (rsp->status_line.status_code != 101)
        {
            /* status code should be 101 */
            PJ_LOG(1, (THIS_FILE, "Invalid http resp status code: %d",
                       rsp->status_line.status_code));
            PJ_THROW(PJ_EINVAL);
        }

        /* parse headers */
        parse_rsp_headers(&scanner, rsp);
        if (!rsp->connection.slen || !rsp->upgrade.slen ||
            !rsp->websock_accept.slen)
        {
            /* These headers should not be null */
            PJ_THROW(PJ_EINVAL);
        }
    }
    PJ_CATCH_ANY
    {
        status = PJ_GET_EXCEPTION();
    }
    PJ_END
    pj_scan_fini(&scanner);

    if (status == PJ_SUCCESS)
    {
        *parse_len = scanner.curptr - data;
    }

    return status;
}

static void generate_websock_accept(const pj_str_t *key, char *buf, int *size)
{
    pj_str_t salt = { "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36 };
    pj_sha1_context ctx;
    pj_uint8_t sha1[PJ_SHA1_DIGEST_SIZE];
    int len = *size;

    pj_sha1_init(&ctx);
    pj_sha1_update(&ctx, (pj_uint8_t *)key->ptr, key->slen);
    pj_sha1_update(&ctx, (pj_uint8_t *)salt.ptr, salt.slen);
    pj_sha1_final(&ctx, sha1);

    pj_base64_encode(sha1, PJ_SHA1_DIGEST_SIZE, buf, &len);
    buf[len] = '\0';
}

static pj_bool_t validate_websock_accept(const pj_str_t *accept,
                                         const pj_str_t *key)
{
    char buf[512];
    int len = sizeof(buf);

    generate_websock_accept(key, buf, &len);

    PJ_LOG(6, (THIS_FILE, "validate accept:%.*s, out:%.*s", (int)accept->slen,
               accept->ptr, len, buf));

    if (pj_stricmp2(accept, buf) == 0)
        return PJ_TRUE;

    return PJ_FALSE;
}

static pj_bool_t verify_srv_filter(pj_websock_t *srv,
                                   pj_websock_t *c,
                                   struct http_req_hdr *req)
{
    int i;
    pj_bool_t found = PJ_FALSE;
    pj_str_t *req_path = &req->req_line.path;

    /* check if request path support */
    if (srv->filter.path_cnt > 0)
    {
        for (i = 0; i < srv->filter.path_cnt; i++)
        {
            if (!pj_stricmp(&srv->filter.paths[i], req_path))
            {
                found = PJ_TRUE;
                pj_strdup_with_null(c->pool, &c->req_path, req_path);
                break;
            }
        }

        if (found == PJ_FALSE)
        {
            PJ_LOG(1, (THIS_FILE, "srv_filter, not support path: %.*s",
                       (int)req_path->slen, req_path->ptr));
            return PJ_FALSE;
        }
    }
    else
    {
        pj_strdup_with_null(c->pool, &c->req_path, req_path);
    }

    /* check if sub-proto support */
    if (srv->filter.proto_cnt > 0)
    {
        if (req->subproto.slen == 0)
        {
            PJ_LOG(1, (THIS_FILE, "srv_filter, request no subproto"));
            return PJ_FALSE;
        }

        found = PJ_FALSE;
        for (i = 0; i < srv->filter.proto_cnt; i++)
        {
            pj_str_t *proto = &srv->filter.subprotos[i];
            pj_ssize_t found_idx = 0;
            pj_str_t token = { 0 };
            while (found_idx != req->subproto.slen)
            {
                found_idx = pj_strtok2(&req->subproto, ",", &token,
                                       (found_idx + token.slen));

                pj_str_t *xproto = pj_strtrim(&token);
                if (!pj_stricmp(proto, xproto))
                {
                    found = PJ_TRUE;
                    pj_strdup_with_null(c->pool, &c->subproto, proto);
                    break;
                }
            }

            if (found)
                break;
        }

        if (found == PJ_FALSE)
        {
            PJ_LOG(1, (THIS_FILE, "srv_filter, not support subprotol: %.*s",
                       (int)req->subproto.slen, req->subproto.ptr));
            return PJ_FALSE;
        }
    }
    else
    {
        if (req->subproto.slen > 0)
        {
            /* default choose the first sub-protol that request */
            pj_str_t token;
            pj_strtok2(&req->subproto, ",", &token, 0);
            pj_strdup_with_null(c->pool, &c->subproto, &token);
        }
    }

    return PJ_TRUE;
}
