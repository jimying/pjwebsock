#include <stdio.h>
#include <string.h>
#include <pjlib.h>

#include "websock.h"

#define THIS_FILE "main.c"

#define WS_PORT 7788
#define WSS_PORT 7789

#define CERT_FILE "./cert/test.pem"
#define CERT_KEY "./cert/test.key"

static pj_bool_t g_quit = PJ_FALSE;
static pj_caching_pool g_app_cp;
static pj_pool_factory *g_app_pf = &g_app_cp.factory;
static pj_pool_t *g_app_pool = NULL;
static pj_thread_t *g_evt_thread = NULL;

static pj_ioqueue_t *g_ioq = NULL;
static pj_timer_heap_t *g_timer_heap = NULL;

static pj_websock_endpoint *g_ws_endpt = NULL;

static void print_usage(void)
{
    puts("\n==============================\n");
    puts("Usage:");
    puts("\tq   quit");
    puts("\n==============================\n");
}

static void app_destroy()
{
    if (g_evt_thread)
    {
        pj_thread_join(g_evt_thread);
        pj_thread_destroy(g_evt_thread);
    }
    if (g_ws_endpt)
    {
        pj_websock_endpt_destroy(g_ws_endpt);
    }

    if (g_ioq)
    {
        pj_ioqueue_destroy(g_ioq);
    }

    if (g_timer_heap)
    {
        pj_timer_heap_destroy(g_timer_heap);
    }

    pj_pool_release(g_app_pool);
    pj_caching_pool_destroy(&g_app_cp);
    pj_shutdown();
}

static int work_proc(void *arg)
{
    while (!g_quit)
    {
        pj_time_val timeout = { 0, 20 };
        pj_time_val timeout2 = { 0, 0 };

        pj_timer_heap_poll(g_timer_heap, &timeout2);

        if (PJ_TIME_VAL_GT(timeout, timeout2))
        {
            timeout = timeout2;
        }
        pj_ioqueue_poll(g_ioq, &timeout);
    }
    return 0;
}

static pj_bool_t on_connect_complete(pj_websock_t *c, pj_status_t status)
{
    char buf[1000];
    PJ_PERROR(4, (THIS_FILE, status, "%s() %s", __FUNCTION__,
                  pj_websock_print(c, buf, sizeof(buf))));
    if (status == PJ_SUCCESS)
    {
        pj_websock_send(c, PJ_WEBSOCK_OP_TEXT, PJ_TRUE, PJ_TRUE,
                        "hi, this is a client", 20);
    }
    return PJ_TRUE;
}

static pj_bool_t on_rx_msg(pj_websock_t *c,
                           pj_websock_rx_data *msg,
                           pj_status_t status)
{
    pj_websock_frame_hdr *hdr;
    char *data;
    char buf[1000];

    if (status != PJ_SUCCESS)
    {
        PJ_PERROR(2, (THIS_FILE, status, "#Disconnect with %s",
                      pj_websock_print(c, buf, sizeof(buf))));
        return PJ_FALSE;
    }

    hdr = &msg->hdr;
    data = (char *)msg->data;

    if (hdr->opcode == PJ_WEBSOCK_OP_TEXT)
    {
        PJ_LOG(4, (THIS_FILE,
                   "RX from %s:\n"
                   "TEXT %s %ld/%ld/%ld [%.*s]",
                   pj_websock_print(c, buf, sizeof(buf)),
                   hdr->mask ? "(masked)" : "", hdr->len, msg->has_read,
                   msg->data_len, (int)msg->data_len, data));

        /* echo response */
        // pj_websock_send(c, hdr->opcode, PJ_TRUE, PJ_FALSE, data, hdr->len);
    }
    else if (hdr->opcode == PJ_WEBSOCK_OP_PING)
    {
        PJ_LOG(4, (THIS_FILE, "RX from %s PING",
                   pj_websock_print(c, buf, sizeof(buf))));
        /* response pong */
        pj_websock_send(c, PJ_WEBSOCK_OP_PONG, PJ_TRUE, PJ_TRUE, NULL, 0);
    }
    else if (hdr->opcode == PJ_WEBSOCK_OP_PONG)
    {
        PJ_LOG(4, (THIS_FILE, "RX from %s PONG",
                   pj_websock_print(c, buf, sizeof(buf))));
    }
    else if (hdr->opcode == PJ_WEBSOCK_OP_CLOSE)
    {
        PJ_LOG(4, (THIS_FILE, "RX from %s CLOSE",
                   pj_websock_print(c, buf, sizeof(buf))));
        pj_websock_close(c, PJ_WEBSOCK_SC_GOING_AWAY, NULL);
        return PJ_FALSE; /* Must return false to stop read any more */
    }

    return PJ_TRUE;
}

static pj_bool_t on_tx_msg(pj_websock_t *c,
                           pj_websock_tx_data *msg,
                           pj_ssize_t sent)
{
    pj_websock_frame_hdr *hdr;
    char *data;
    char buf[1000];

    hdr = &msg->hdr;
    data = (char *)msg->data;

    if (hdr->opcode == PJ_WEBSOCK_OP_TEXT)
    {
        PJ_LOG(4, (THIS_FILE,
                   "TX to %s:\n"
                   "TEXT %s %ld/%ld [%.*s]",
                   pj_websock_print(c, buf, sizeof(buf)),
                   hdr->mask ? "(masked)" : "", hdr->len, sent, (int)hdr->len,
                   data));
    }
    else if (hdr->opcode == PJ_WEBSOCK_OP_PING)
    {
        PJ_LOG(4, (THIS_FILE, "TX to %s PING",
                   pj_websock_print(c, buf, sizeof(buf))));
    }
    else if (hdr->opcode == PJ_WEBSOCK_OP_PONG)
    {
        PJ_LOG(4, (THIS_FILE, "TX to %s PONG",
                   pj_websock_print(c, buf, sizeof(buf))));
    }
    else if (hdr->opcode == PJ_WEBSOCK_OP_CLOSE)
    {
        PJ_LOG(4, (THIS_FILE, "TX to %s CLOSE",
                   pj_websock_print(c, buf, sizeof(buf))));
    }

    return PJ_TRUE;
}

static void on_state_change(pj_websock_t *c, int state)
{
    char buf[1000];
    PJ_LOG(4, (THIS_FILE, "%s() %s %s", __FUNCTION__,
               pj_websock_print(c, buf, sizeof(buf)),
               pj_websock_state_str(state)));
}

static int on_accept_complete(pj_websock_t *c,
                              const pj_sockaddr_t *src_addr,
                              int src_addr_len)
{
    pj_websock_cb cb;
    char buf[1000];
    PJ_LOG(4, (THIS_FILE, "accept new connection...%s",
               pj_websock_print(c, buf, sizeof(buf))));

    /* set new websocket connection user callbacks and user data */
    pj_bzero(&cb, sizeof(cb));
    cb.on_rx_msg = on_rx_msg;
    cb.on_tx_msg = on_tx_msg;
    cb.on_state_change = on_state_change;
    pj_websock_set_callbacks(c, &cb);
    pj_websock_set_userdata(c, NULL); // TODO:

    /* say hi*/
    pj_websock_send(c, PJ_WEBSOCK_OP_TEXT, PJ_TRUE, PJ_FALSE,
                    "hi, this is a server", 20);

    /* test: enable auto send ping */
    pj_time_val interval = { 30, 0 };
    pj_websock_enable_ping(c, &interval);

    return PJ_TRUE;
}

int main(int argc, char **argv)
{
    int status;
    char cmd[80];
    unsigned log_decor;

    /* pjlib init */
    pj_init();
    log_decor = pj_log_get_decor();
    log_decor |= PJ_LOG_HAS_LEVEL_TEXT;
    log_decor |= PJ_LOG_HAS_SENDER;
    pj_log_set_decor(log_decor);
    pj_log_set_level(5);

    /* init random */
    pj_time_val now;
    pj_gettimeofday(&now);
    pj_srand((unsigned)now.sec);

    /* init memroy pool */
    pj_caching_pool_init(&g_app_cp, NULL, 0);
    g_app_pool = pj_pool_create(g_app_pf, "app", 1000, 1000, NULL);

    /* create websock endpoint */
    {
        status = pj_ioqueue_create(g_app_pool, PJ_IOQUEUE_MAX_HANDLES, &g_ioq);
        if (status != PJ_SUCCESS)
        {
            PJ_PERROR(1, (THIS_FILE, status, "create ioqueue error"));
            goto on_error;
        }

        status = pj_timer_heap_create(g_app_pool, 128, &g_timer_heap);
        if (status != PJ_SUCCESS)
        {
            PJ_PERROR(1, (THIS_FILE, status, "create timer heap error"));
            goto on_error;
        }

        pj_websock_ssl_cert cert;
        pj_bzero(&cert, sizeof(cert));
        cert.ca_file = pj_str(CERT_FILE);
        cert.cert_file = pj_str(CERT_FILE);
        cert.private_file = pj_str(CERT_KEY);

        pj_websock_endpt_cfg opt;
        pj_websock_endpt_cfg_default(&opt);
        opt.pf = g_app_pf;
        opt.ioq = g_ioq;
        opt.timer_heap = g_timer_heap;
        opt.cert = &cert;

        status = pj_websock_endpt_create(&opt, &g_ws_endpt);
        if (status != PJ_SUCCESS)
        {
            PJ_PERROR(1, (THIS_FILE, status, "create websock endpoint error"));
            goto on_error;
        }

        /* start ioqueue poll thread */
        pj_thread_create(g_app_pool, "thr_evt", work_proc, NULL, 0, 0,
                         &g_evt_thread);
    }

    /* create websocket server */
    {
        pj_websock_t *ws = NULL;
        pj_websock_t *wss = NULL;
        pj_websock_cb cb;
        pj_sockaddr local_addr;
        pj_bzero(&cb, sizeof(cb));
        cb.on_accept_complete = on_accept_complete;
        pj_sockaddr_init(pj_AF_INET(), &local_addr, NULL, WS_PORT);

        /* TCP */
        pj_websock_listen(g_ws_endpt, PJ_WEBSOCK_TRANSPORT_TCP, &local_addr,
                          &cb, NULL, &ws);

        /* TLS */
        pj_sockaddr_init(pj_AF_INET(), &local_addr, NULL, WSS_PORT);
        pj_websock_listen(g_ws_endpt, PJ_WEBSOCK_TRANSPORT_TLS, &local_addr,
                          &cb, NULL, &wss);

        pj_str_t support_protols[] = {
            pj_str("pjsip"),
            pj_str("test"),
        };

        pj_str_t support_paths[] = {
            pj_str("/pjsip"),
            pj_str("/test"),
            pj_str("/tcp"),
            pj_str("/tls"),
        };

        if (ws)
        {
            pj_websock_set_support_subproto(ws, support_protols,
                                            PJ_ARRAY_SIZE(support_protols));
            pj_websock_set_support_path(ws, support_paths,
                                        PJ_ARRAY_SIZE(support_paths));
        }
        if (wss)
        {
            pj_websock_set_support_subproto(wss, support_protols,
                                            PJ_ARRAY_SIZE(support_protols));
            pj_websock_set_support_path(wss, support_paths,
                                        PJ_ARRAY_SIZE(support_paths));
        }
    }

    /* create websock client (connect to server)*/
    {
        pj_websock_t *wc = NULL;
        pj_websock_http_hdr hdr;
        pj_websock_cb cb;
        pj_bzero(&cb, sizeof(cb));
        cb.on_connect_complete = on_connect_complete;
        cb.on_rx_msg = on_rx_msg;
        cb.on_tx_msg = on_tx_msg;
        cb.on_state_change = on_state_change;

        {
            hdr.key = pj_str("Sec-WebSocket-Protocol");
            hdr.val = pj_str("pjsip");
            pj_websock_connect(g_ws_endpt, "ws://127.0.0.1:7788/tcp", &cb, NULL,
                               &hdr, 1, &wc);
            pj_websock_connect(g_ws_endpt, "wss://127.0.0.1:7789/tls", &cb,
                               NULL, &hdr, 1, &wc);
        }
    }

    while (!g_quit)
    {
        fgets(cmd, sizeof(cmd), stdin);
        switch (cmd[0])
        {
        case 'q':
            g_quit = PJ_TRUE;
            break;
        default:
            print_usage();
            break;
        }
    }

on_error:
    app_destroy();
    return status;
}
