#include "websock_transport.h"
#include <pjlib.h>

PJ_DEF(void)
pj_websock_transport_param_default(pj_websock_transport_param *param)
{
    pj_bzero(param, sizeof(*param));
    param->max_rx_bufsize = 16000;
    param->async_cnt = 1;
}

PJ_DEF(pj_status_t) pj_websock_transport_destroy(pj_websock_transport_t *t)
{
    PJ_ASSERT_RETURN(t && t->op, PJ_EINVALIDOP);
    return t->op->destroy(t);
}

PJ_DEF(pj_status_t)
pj_websock_transport_start_connect(pj_websock_transport_t *t,
                                   const pj_sockaddr_t *remaddr,
                                   int addr_len)
{
    PJ_ASSERT_RETURN(t && t->op, PJ_EINVALIDOP);
    return t->op->connect(t, remaddr, addr_len);
}

PJ_DEF(pj_status_t)
pj_websock_transport_start_accept(pj_websock_transport_t *t,
                                  const pj_sockaddr_t *local_addr,
                                  int addr_len)
{
    PJ_ASSERT_RETURN(t && t->op, PJ_EINVALIDOP);
    return t->op->accept(t, local_addr, addr_len);
}

PJ_DEF(pj_status_t) pj_websock_transport_send(pj_websock_transport_t *t,
                                              pj_ioqueue_op_key_t *send_key,
                                              const void *data,
                                              pj_ssize_t *size,
                                              unsigned flags)
{
    PJ_ASSERT_RETURN(t && t->op, PJ_EINVALIDOP);
    return t->op->send(t, send_key, data, size, flags);
}
