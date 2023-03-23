#include "websock_transport.h"
#include <pjlib.h>

#if defined(PJ_HAS_SSL_SOCK) && PJ_HAS_SSL_SOCK != 0
#  define THIS_FILE "websock_transport_tls.c"

struct tls_transport {
    pj_websock_transport_t base;
    pj_pool_t *pool_own;
    pj_ssl_sock_t *ssock;
    pj_ssl_cert_t *cert;
};

static pj_status_t tp_connect(pj_websock_transport_t *t,
                              const pj_sockaddr_t *remaddr,
                              int addr_len);
static pj_status_t tp_accept(pj_websock_transport_t *t,
                             const pj_sockaddr_t *local_addr,
                             int addr_len);
static pj_status_t tp_destroy(pj_websock_transport_t *t);
static pj_status_t tp_send(pj_websock_transport_t *t,
                           pj_ioqueue_op_key_t *send_key,
                           const void *data,
                           pj_ssize_t *size,
                           unsigned flags);

static pj_bool_t on_accept_complete(pj_ssl_sock_t *ssock,
                                    pj_ssl_sock_t *newsock,
                                    const pj_sockaddr_t *src_addr,
                                    int src_addr_len);
static pj_bool_t on_connect_complete(pj_ssl_sock_t *ssock, pj_status_t status);
static pj_bool_t on_data_read(pj_ssl_sock_t *ssock,
                              void *data,
                              pj_size_t size,
                              pj_status_t status,
                              pj_size_t *remainder);
static pj_bool_t on_data_sent(pj_ssl_sock_t *ssock,
                              pj_ioqueue_op_key_t *send_key,
                              pj_ssize_t sent);

/**
 * TLS transport operations
 */
static pj_websock_transport_op tls_op = {
    .connect = tp_connect,
    .accept = tp_accept,
    .destroy = tp_destroy,
    .send = tp_send,
};

PJ_DEF(pj_status_t)
pj_websock_transport_create_tls(pj_pool_t *pool,
                                pj_websock_transport_param *param,
                                pj_websock_transport_t **pt)
{
    struct tls_transport *tp;
    pj_pool_t *xpool = pool;
    pj_status_t status;

    PJ_ASSERT_RETURN(pt, PJ_EINVAL);
    PJ_ASSERT_RETURN(param, PJ_EINVAL);
    PJ_ASSERT_RETURN(param->ioq, PJ_EINVAL);
    *pt = NULL;

    if (!pool) {
        PJ_ASSERT_RETURN(param->pf, PJ_EINVAL);
        xpool = pj_pool_create(param->pf, "ws_tptls%p", 500, 500, NULL);
        PJ_ASSERT_RETURN(xpool, PJ_ENOMEM);
    }

    tp = PJ_POOL_ZALLOC_T(xpool, struct tls_transport);
    if (!pool)
        tp->pool_own = xpool;
    tp->base.pool = xpool;
    tp->base.ioq = param->ioq;
    tp->base.timer_heap = param->timer_heap;
    tp->base.pf = param->pf;
    tp->base.op = &tls_op;
    tp->base.user_data = param->user_data;
    tp->base.max_rx_bufsize = param->max_rx_bufsize;
    tp->base.async_cnt = param->async_cnt;
    if (param->cb)
        pj_memcpy(&tp->base.cb, param->cb, sizeof(pj_websock_transport_cb));

    if (param->cert.private_file.slen > 0) {
        status = pj_ssl_cert_load_from_files(
            xpool, &param->cert.ca_file, &param->cert.cert_file,
            &param->cert.private_file, &param->cert.private_pass, &tp->cert);
        if (status != PJ_SUCCESS) {
            PJ_PERROR(1, (THIS_FILE, status, "load ssl cert error"));
        }
    }
    *pt = &tp->base;

    return PJ_SUCCESS;
}

static pj_status_t tp_connect(pj_websock_transport_t *t,
                              const pj_sockaddr_t *remaddr,
                              int addr_len)
{
    pj_status_t status;
    struct tls_transport *tp = (struct tls_transport *)t;
    pj_sockaddr *rmt_addr = (pj_sockaddr *)remaddr;
    pj_ioqueue_t *ioq;
    pj_pool_t *pool;
    int af;
    pj_ssl_sock_t *ssock = NULL;
    pj_ssl_sock_param param;
    pj_sockaddr local_addr;

    PJ_ASSERT_RETURN(t, PJ_EINVAL);
    PJ_ASSERT_RETURN(remaddr, PJ_EINVAL);
    PJ_ASSERT_RETURN(((addr_len == sizeof(pj_sockaddr_in) &&
                       rmt_addr->addr.sa_family == pj_AF_INET()) ||
                      (addr_len == sizeof(pj_sockaddr_in6) &&
                       rmt_addr->addr.sa_family == pj_AF_INET6())),
                     PJ_EINVAL);

    ioq = tp->base.ioq;
    pool = tp->base.pool;
    af = rmt_addr->addr.sa_family;

    pj_ssl_sock_param_default(&param);
    param.ioqueue = ioq;
    param.timer_heap = t->timer_heap;
    param.timeout.sec = PJ_SSL_HANDSHARKE_TIMEOUT_MSEC / 1000;
    param.timeout.msec = PJ_SSL_HANDSHARKE_TIMEOUT_MSEC % 1000;
    param.user_data = t;
    param.sock_af = af;
    param.async_cnt = t->async_cnt;
    param.cb.on_connect_complete = on_connect_complete;
    param.cb.on_data_read = on_data_read;
    param.cb.on_data_sent = on_data_sent;
    status = pj_ssl_sock_create(pool, &param, &ssock);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "ssock create error"));
        goto on_error;
    }

    pj_sockaddr_init(af, &local_addr, NULL, 0);
    status = pj_ssl_sock_start_connect(ssock, pool, &local_addr, remaddr,
                                       addr_len);
    if (status == PJ_SUCCESS) {
        tp->ssock = ssock;
        on_connect_complete(ssock, PJ_SUCCESS);
        return PJ_SUCCESS;
    }
    if (status != PJ_EPENDING) {
        PJ_PERROR(1, (THIS_FILE, status, "sscock start connect error"));
        goto on_error;
    }

    tp->ssock = ssock;
    return PJ_EPENDING;

on_error:
    if (ssock) {
        pj_ssl_sock_close(ssock);
    }
    return status;
}

static pj_status_t tp_accept(pj_websock_transport_t *t,
                             const pj_sockaddr_t *local_addr,
                             int addr_len)
{
    struct tls_transport *tp = (struct tls_transport *)t;
    pj_status_t status;
    pj_ioqueue_t *ioq = t->ioq;
    pj_pool_t *pool = t->pool;
    pj_sockaddr *paddr = (pj_sockaddr *)local_addr;
    int af = paddr->addr.sa_family;
    pj_ssl_sock_t *ssock = NULL;
    pj_ssl_sock_param param;

    PJ_ASSERT_RETURN(t, PJ_EINVAL);
    PJ_ASSERT_RETURN(local_addr, PJ_EINVAL);

    pj_ssl_sock_param_default(&param);
    param.ioqueue = ioq;
    param.timer_heap = t->timer_heap;
    param.timeout.sec = PJ_SSL_HANDSHARKE_TIMEOUT_MSEC / 1000;
    param.timeout.msec = PJ_SSL_HANDSHARKE_TIMEOUT_MSEC % 1000;
    param.sock_af = af;
    param.reuse_addr = PJ_TRUE;
    param.async_cnt = t->async_cnt;
    param.user_data = t;
    param.cb.on_accept_complete = on_accept_complete;
    param.cb.on_data_read = on_data_read;
    param.cb.on_data_sent = on_data_sent;

    status = pj_ssl_sock_create(pool, &param, &ssock);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "ssock create error"));
        goto on_error;
    }

    if (tp->cert)
        pj_ssl_sock_set_certificate(ssock, pool, tp->cert);

    status = pj_ssl_sock_start_accept(ssock, pool, local_addr, addr_len);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "ssock accept error"));
        goto on_error;
    }

    tp->ssock = ssock;

    return PJ_SUCCESS;
on_error:
    if (ssock) {
        pj_ssl_sock_close(ssock);
    }
    return status;
}

static pj_status_t tp_destroy(pj_websock_transport_t *t)
{
    struct tls_transport *tp = (struct tls_transport *)t;

    PJ_ASSERT_RETURN(tp, PJ_EINVAL);
    if (tp->ssock) {
        pj_ssl_sock_close(tp->ssock);
        tp->ssock = NULL;
    }

    if (tp->pool_own) {
        pj_pool_release(tp->pool_own);
    }

    return PJ_SUCCESS;
}

static pj_status_t tp_send(pj_websock_transport_t *t,
                           pj_ioqueue_op_key_t *send_key,
                           const void *data,
                           pj_ssize_t *size,
                           unsigned flags)
{
    struct tls_transport *tp = (struct tls_transport *)t;
    pj_status_t status;

    PJ_ASSERT_RETURN(t, PJ_EINVAL);
    PJ_ASSERT_RETURN(send_key, PJ_EINVAL);
    PJ_ASSERT_RETURN(data, PJ_EINVAL);
    PJ_ASSERT_RETURN(size && *size > 0, PJ_EINVAL);

    status = pj_ssl_sock_send(tp->ssock, send_key, data, size, flags);
    if (status == PJ_SUCCESS) {
        pj_websock_transport_cb *cb = &tp->base.cb;
        if (cb->on_data_sent)
            cb->on_data_sent(&tp->base, send_key, *size);
        return PJ_SUCCESS;
    }

    if (status != PJ_EPENDING) {
        PJ_PERROR(1, (THIS_FILE, status, "send error"));
        pj_websock_transport_cb *cb = &tp->base.cb;
        if (cb->on_data_sent)
            cb->on_data_sent(&tp->base, send_key, -status);
    }

    return status;
}

static pj_bool_t on_accept_complete(pj_ssl_sock_t *ssock,
                                    pj_ssl_sock_t *newsock,
                                    const pj_sockaddr_t *src_addr,
                                    int src_addr_len)
{
    /* create new transport for the new connection */
    pj_status_t status;
    pj_websock_transport_t *tp = pj_ssl_sock_get_user_data(ssock);
    pj_websock_transport_t *new_tp = NULL;
    struct tls_transport *tls_tp = NULL;
    pj_websock_transport_param tp_param;
    pj_ioqueue_t *ioq = tp->ioq;
    pj_pool_factory *pf = tp->pf;
    pj_pool_t *pool;

    pj_bzero(&tp_param, sizeof(tp_param));
    tp_param.ioq = ioq;
    tp_param.timer_heap = tp->timer_heap;
    tp_param.pf = pf;
    tp_param.max_rx_bufsize = tp->max_rx_bufsize;

    status = pj_websock_transport_create_tls(NULL, &tp_param, &new_tp);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(
            1, (THIS_FILE, status, "%s() new transport error", __FUNCTION__));
        goto on_error;
    }
    tls_tp = (struct tls_transport *)new_tp;

    pool = new_tp->pool;
    tls_tp->ssock = newsock;
    pj_ssl_sock_set_user_data(newsock, new_tp);

    status = pj_ssl_sock_start_read(newsock, pool, tp->max_rx_bufsize, 0);
    if (status != PJ_SUCCESS) {
        PJ_PERROR(1, (THIS_FILE, status, "start read error"));
        goto on_error;
    }

    /*notify accept event*/
    if (tp->cb.on_accept_complete)
        tp->cb.on_accept_complete(tp, new_tp, src_addr, src_addr_len);

    return PJ_TRUE;
on_error:
    if (new_tp)
        tp_destroy(new_tp);
    else if (newsock)
        pj_ssl_sock_close(newsock);
    return PJ_FALSE;
}

static pj_bool_t on_connect_complete(pj_ssl_sock_t *ssock, pj_status_t status)
{
    struct tls_transport *tp = pj_ssl_sock_get_user_data(ssock);
    pj_websock_transport_cb *cb = &tp->base.cb;
    PJ_PERROR(6, (THIS_FILE, status, "%s() %s status:%d", __FUNCTION__,
                  tp->base.pool->obj_name, status));

    if (status == PJ_SUCCESS) {
        status = pj_ssl_sock_start_read(tp->ssock, tp->base.pool,
                                        tp->base.max_rx_bufsize, 0);
        if (status != PJ_SUCCESS) {
            PJ_PERROR(1, (THIS_FILE, status, "start read error"));
        }
    }

    if (cb->on_connect_complete)
        return cb->on_connect_complete(&tp->base, status);

    return (status == PJ_SUCCESS ? PJ_TRUE : PJ_FALSE);
}

static pj_bool_t on_data_read(pj_ssl_sock_t *ssock,
                              void *data,
                              pj_size_t size,
                              pj_status_t status,
                              pj_size_t *remainder)
{
    struct tls_transport *tp = pj_ssl_sock_get_user_data(ssock);
    pj_websock_transport_cb *cb = &tp->base.cb;

    PJ_PERROR(6, (THIS_FILE, status, "%s() %s status:%d, size:%d", __FUNCTION__,
                  tp->base.pool->obj_name, status, size));

    if (status != PJ_SUCCESS) {
        /* immediately close sock when connection disconnected */
        PJ_PERROR(2, (THIS_FILE, status, "%s() %s status:%d, size:%lu",
                      __FUNCTION__, tp->base.pool->obj_name, status, size));
        pj_ssl_sock_close(ssock);
        tp->ssock = NULL;
    }

    if (cb->on_data_read)
        return cb->on_data_read(&tp->base, data, size, status, remainder);

    return (status == PJ_SUCCESS ? PJ_TRUE : PJ_FALSE);
}

static pj_bool_t on_data_sent(pj_ssl_sock_t *ssock,
                              pj_ioqueue_op_key_t *send_key,
                              pj_ssize_t sent)
{
    struct tls_transport *tp = pj_ssl_sock_get_user_data(ssock);
    pj_websock_transport_cb *cb = &tp->base.cb;

    PJ_LOG(6, (THIS_FILE, "%s() %ld", __FUNCTION__, sent));

    if (cb->on_data_sent)
        return cb->on_data_sent(&tp->base, send_key, sent);

    return PJ_TRUE;
}

#endif
