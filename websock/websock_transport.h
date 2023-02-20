#ifndef __PJLIB_UTIL_WEBSOCK_TRANSPORT_H__
#define __PJLIB_UTIL_WEBSOCK_TRANSPORT_H__

/**
 * @file websock_transport.h
 * @brief Websocket transport
 */

#include <pj/types.h>
#include <pj/ioqueue.h>

PJ_BEGIN_DECL

/**
 * SSL handsharke timeout milliseconds
 */
#ifndef PJ_SSL_HANDSHARKE_TIMEOUT_MSEC
#  define PJ_SSL_HANDSHARKE_TIMEOUT_MSEC (10 * 1000)
#endif

typedef struct pj_websock_transport_t pj_websock_transport_t;

/**
 * Websocket transport operations
 */
typedef struct pj_websock_transport_op {
    /**
     * Connect to remote address
     */
    pj_status_t (*connect)(pj_websock_transport_t *t,
                           const pj_sockaddr_t *remaddr,
                           int addr_len);

    /**
     * Accept on local address
     */
    pj_status_t (*accept)(pj_websock_transport_t *t,
                          const pj_sockaddr_t *local_addr,
                          int addr_len);

    /**
     * Transport destroy
     *
     */
    pj_status_t (*destroy)(pj_websock_transport_t *t);

    /**
     * Transport send data
     */
    pj_status_t (*send)(pj_websock_transport_t *t,
                        pj_ioqueue_op_key_t *send_key,
                        const void *data,
                        pj_ssize_t *size,
                        unsigned flags);
} pj_websock_transport_op;

/**
 * Websocket transport callbacks
 */
typedef struct pj_websock_transport_cb {
    pj_bool_t (*on_connect_complete)(pj_websock_transport_t *t,
                                     pj_status_t status);
    pj_bool_t (*on_accept_complete)(pj_websock_transport_t *t,
                                    pj_websock_transport_t *newt,
                                    const pj_sockaddr_t *src_addr,
                                    int src_addr_len);
    pj_bool_t (*on_data_read)(pj_websock_transport_t *t,
                              void *data,
                              pj_size_t size,
                              pj_status_t status,
                              pj_size_t *remainder);

    pj_bool_t (*on_data_sent)(pj_websock_transport_t *t,
                              pj_ioqueue_op_key_t *send_key,
                              pj_ssize_t sent);
} pj_websock_transport_cb;

/**
 * Websocket transport
 */
struct pj_websock_transport_t {
    pj_pool_t *pool;             /**< Memory pool that used */
    pj_ioqueue_t *ioq;           /**< Ioqueue that used */
    pj_timer_heap_t *timer_heap; /**< Timer heap that used */
    pj_pool_factory *pf;         /**< Pool factory that used */
    int max_rx_bufsize;          /**< recv buffer size */
    unsigned async_cnt;          /**< the number of asynchronous read */
    const void *user_data;       /**< User data */
    pj_websock_transport_cb cb;  /**< User transport callbacks */
    pj_websock_transport_op *op; /**< Transport operations */
};

/**
 * Websocket transport creation parameters
 */
typedef struct pj_websock_transport_param {
    pj_ioqueue_t *ioq;
    pj_timer_heap_t *timer_heap;
    pj_pool_factory *pf;
    pj_websock_transport_cb *cb;
    const void *user_data;
    int max_rx_bufsize;
    unsigned async_cnt;

    struct {
        pj_str_t ca_file;
        pj_str_t cert_file;
        pj_str_t private_file;
        pj_str_t private_pass;
    } cert;
} pj_websock_transport_param;

PJ_DECL(void)
pj_websock_transport_param_default(pj_websock_transport_param *param);

PJ_DECL(pj_status_t)
pj_websock_transport_create_tcp(pj_pool_t *pool,
                                pj_websock_transport_param *param,
                                pj_websock_transport_t **pt);

#if defined(PJ_HAS_SSL_SOCK) && PJ_HAS_SSL_SOCK != 0
PJ_DECL(pj_status_t)
pj_websock_transport_create_tls(pj_pool_t *pool,
                                pj_websock_transport_param *param,
                                pj_websock_transport_t **pt);
#endif

PJ_DECL(pj_status_t) pj_websock_transport_destroy(pj_websock_transport_t *t);

PJ_DECL(pj_status_t)
pj_websock_transport_start_connect(pj_websock_transport_t *t,
                                   const pj_sockaddr_t *remaddr,
                                   int addr_len);

PJ_DECL(pj_status_t)
pj_websock_transport_start_accept(pj_websock_transport_t *t,
                                  const pj_sockaddr_t *local_addr,
                                  int addr_len);

PJ_DECL(pj_status_t) pj_websock_transport_send(pj_websock_transport_t *t,
                                               pj_ioqueue_op_key_t *send_key,
                                               const void *data,
                                               pj_ssize_t *size,
                                               unsigned flags);

PJ_END_DECL
/**
 * @}
 */
#endif
