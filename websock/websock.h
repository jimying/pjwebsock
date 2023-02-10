#ifndef __PJLIB_UTIL_WEBSOCK_H__
#define __PJLIB_UTIL_WEBSOCK_H__

/**
 * @file websock.h
 * @brief Websocket
 */

#include <pj/types.h>
#include <pj/ioqueue.h>

PJ_BEGIN_DECL

/**
 *  Max number of allowed request paths
 */
#ifndef PJ_WEBSOCK_MAX_PATH_CNT
#  define PJ_WEBSOCK_MAX_PATH_CNT 8
#endif

/**
 *  Max number of allowed sub-protocols
 */
#ifndef PJ_WEBSOCK_MAX_SUB_PROTO_CNT
#  define PJ_WEBSOCK_MAX_SUB_PROTO_CNT 8
#endif

/**
 * WebSocket endpoint type
 */
typedef struct pj_websock_endpoint pj_websock_endpoint;

/**
 * WebSocket connection type
 */
typedef struct pj_websock_t pj_websock_t;

/**
 * Websocket version
 */
enum pj_websock_ver {
    PJ_WEBSOCK_VERSION = 13,
} pj_websock_ver;

/**
 *  Websocket Data Framing header
 */
typedef struct pj_websock_frame_hdr {
    unsigned fin:1;     /**< Whether is the final fragment in a message*/
    unsigned rsv1:1;    /**< Reserved */
    unsigned rsv2:1;    /**< Reserved */
    unsigned rsv3:1;    /**< Reserved */
    unsigned opcode:4;  /**< The interpretation of the payload */
    unsigned mask:1;    /**< Whether the payload is masked */
    pj_uint64_t len;    /**< Payload length */
    pj_uint8_t mkey[4]; /**< Masking-key */
} pj_websock_frame_hdr;

/**
 * WebSocket Opcode Registry
 */
typedef enum pj_websock_opcode {
    PJ_WEBSOCK_OP_CONTN = 0x0, /**< Continuation Frame */
    PJ_WEBSOCK_OP_TEXT = 0x1,  /**< Text Frame */
    PJ_WEBSOCK_OP_BIN = 0x2,   /**< Binary Frame */
    PJ_WEBSOCK_OP_CLOSE = 0x8, /**< Connection Close Frame */
    PJ_WEBSOCK_OP_PING = 0x9,  /**< Ping Frame */
    PJ_WEBSOCK_OP_PONG = 0xa,  /**< Pong Frame */
} pj_websock_opcode;

/**
 *  WebSocket Status code Registry
 */
typedef enum pj_websock_scode {
    PJ_WEBSOCK_SC_NORMAL_CLOSURE = 1000,   /**< Normal Closure */
    PJ_WEBSOCK_SC_GOING_AWAY = 1001,       /**< Going Away */
    PJ_WEBSOCK_SC_PROTOCOL_ERROR = 1002,   /**< Protocol error */
    PJ_WEBSOCK_SC_UNSUPPORTED_DATA = 1003, /**< Unsupported Data */
    PJ_WEBSOCK_SC_ABNORMAL_CLOSURE = 1006, /**< Abnormal Closure */
    PJ_WEBSOCK_SC_INVALID_PAYLOAD = 1007,  /**< Invalid frame payload data */
    PJ_WEBSOCK_SC_POLICY_VIOLATION = 1008, /**< Policy Violation */
    PJ_WEBSOCK_SC_MESSAGE_TOO_BIG = 1009,  /**< Message Too Big */
    PJ_WEBSOCK_SC_EXTENSION_ERROR = 1010,  /**< Mandatory Ext */
    PJ_WEBSOCK_SC_INTERNAL_ERROR = 1011,   /**< Internal Server Error */
    PJ_WEBSOCK_SC_TLS_HANDSHAKE = 1015,    /**< TLS handshake Fail */
} pj_websock_scode;

/**
 * WebSocket connection status
 */
typedef enum pj_websock_readystate {
    PJ_WEBSOCK_STATE_CONNECTING = 1, /**< connecting */
    PJ_WEBSOCK_STATE_OPEN,           /**< open, connected */
    PJ_WEBSOCK_STATE_CLOSING,        /**< closing */
    PJ_WEBSOCK_STATE_CLOSED,         /**< closed */
} pj_websock_readystate;

/**
 * Websocket transport type
 */
typedef enum pj_websock_transport_type {
    PJ_WEBSOCK_TRANSPORT_TCP, /**< TCP */
    PJ_WEBSOCK_TRANSPORT_TLS, /**< TLS */
} pj_websock_transport_type;

/**
 * Websocket tx data
 */
typedef struct pj_websock_tx_data {
    pj_pool_t *pool;          /**< only for internal used, can't use outside */
    pj_websock_frame_hdr hdr; /**< websock data frame header */
    void *data;               /** data that sent */
    pj_ioqueue_op_key_t send_key; /** send key */
} pj_websock_tx_data;

/**
 * Websocket rx data
 */
typedef struct pj_websock_rx_data {
    pj_pool_t *pool;          /**< only for internal used, can't use outside */
    pj_websock_frame_hdr hdr; /**< websock data frame header */
    void *data;               /**< current read data */
    pj_uint64_t data_len;     /**< current read data length */
    pj_uint64_t has_read;     /**< when finish has_read = hdr.len */
} pj_websock_rx_data;

/**
 * WebSocket connection callbacks
 */
typedef struct pj_websock_cb {
    pj_bool_t (*on_connect_complete)(pj_websock_t *c, pj_status_t status);
    pj_bool_t (*on_accept_complete)(pj_websock_t *c,
                                    const pj_sockaddr_t *src_addr,
                                    int src_addr_len);
    pj_bool_t (*on_rx_msg)(pj_websock_t *c,
                           pj_websock_rx_data *msg,
                           pj_status_t status);
    pj_bool_t (*on_tx_msg)(pj_websock_t *c,
                           pj_websock_tx_data *msg,
                           pj_ssize_t sent);
    void (*on_state_change)(pj_websock_t *c, int state);
} pj_websock_cb;

/**
 * WebSocket http request/response header
 */
typedef struct pj_websock_http_hdr {
    pj_str_t key;
    pj_str_t val;
} pj_websock_http_hdr;

/**
 * Wesocket ssl certificate files
 */
typedef struct pj_websock_ssl_cert {
    pj_str_t ca_file;
    pj_str_t cert_file;
    pj_str_t private_file;
    pj_str_t private_pass;
} pj_websock_ssl_cert;

/**
 * Websock endpoint configure
 */
typedef struct pj_websock_endpt_cfg {
    pj_pool_factory *pf;
    pj_ioqueue_t *ioq;
    pj_timer_heap_t *timer_heap;
    pj_websock_ssl_cert *cert;
    int max_rx_bufsize;
    unsigned async_cnt;
} pj_websock_endpt_cfg;

/**
 * Websocket endpoint default configure
 *
 */

PJ_DECL(void) pj_websock_endpt_cfg_default(pj_websock_endpt_cfg *opt);

/**
 * WebSocket endpoint create
 *
 * @param opt
 *
 * @return
 */
PJ_DECL(pj_status_t) pj_websock_endpt_create(pj_websock_endpt_cfg *opt,
                                             pj_websock_endpoint **pendpt);

/**
 *  WebSocket endpoint destroy
 *
 * @param endpt
 *
 * @return
 */
PJ_DECL(pj_status_t) pj_websock_endpt_destroy(pj_websock_endpoint *endpt);

/**
 * Connect to websocket server
 *
 * @param endpt     The endpoint that belong
 * @param url       The server url, "ws(s)://host:port"
 * @param cb        The callbacks
 * @param user_data The user data
 * @param hdrs      The custom http request header(s)
 * @param hdr_cnt   The header count
 * @param pc        The new websocket connection object that created
 *
 * @return  if success return PJ_PENDING, In this case the
 *      \a on_connect_complete callback will be called when connection is
 *      complete. Any other return value (except PJ_SUCCESS) indicates error
 *      condition.
 */
PJ_DECL(pj_status_t) pj_websock_connect(pj_websock_endpoint *endpt,
                                        const char *url,
                                        const pj_websock_cb *cb,
                                        const void *user_data,
                                        pj_websock_http_hdr *hdrs,
                                        int hdr_cnt,
                                        pj_websock_t **pc);

/**
 * Close a websocket connection
 * @param c      The websocket connection object
 * @param code   The close code \a pj_websock_scode
 * @param reason The close reason text (optional, can be NULL)
 *
 * @return return PJ_SUCCESS if successful
 */
PJ_DECL(pj_status_t) pj_websock_close(pj_websock_t *c,
                                      int code,
                                      const char *reason);

/**
 *  Send websocket data frame message
 *
 * @param c       The websocket connection object
 * @param opcode  The type of message \a pj_websock_opcode
 * @param fini    Whether the final fragment (if a data send by multi messages).
 *          Currently not support the feature, it should set to PJ_TRUE.
 * @param mask    Whether encrypt message by mask the data simplely
 * @param data    The payload data
 * @param len     The payload len
 *
 * @return  PJ_SUCCESS if data has been sent immediately, or
 *      PJ_EPENDING if data cannot be sent immediately. In
 *      this case the \a on_tx_msg() callback will be
 *      called when data is actually sent. Any other return
 *      value indicates error condition.
 *
 */
PJ_DECL(pj_status_t) pj_websock_send(pj_websock_t *c,
                                     int opcode,
                                     pj_bool_t fini,
                                     pj_bool_t mask,
                                     void *data,
                                     pj_size_t len);

/**
 * Listen on address to accept new connection (work as server)
 *
 * @param tp_type The transport type \a pj_websock_transport_type
 * @param local_addr The bound local address
 * @param cb         The callbacks
 * @param user_data  The user data
 * @param s          The websocket server object
 *
 * @return PJ_SUCCESS if success
 */
PJ_DECL(pj_status_t) pj_websock_listen(pj_websock_endpoint *endpt,
                                       int tp_type,
                                       pj_sockaddr_t *local_addr,
                                       pj_websock_cb *cb,
                                       const void *user_data,
                                       pj_websock_t **s);

/**
 * Set websocket server support/allowed request paths
 *
 * @param srv   The websocket server listener
 * @param paths The array of paths
 * @param cnt   Count
 *
 * @return PJ_SUCCESS if success
 *
 */
PJ_DECL(pj_status_t) pj_websock_set_support_path(pj_websock_t *srv,
                                                 pj_str_t paths[],
                                                 int cnt);
/**
 * Set websocket server support/allowed sub-protocols
 *
 * @param srv   The websocket server listener
 * @param paths The array of sub-protocols
 * @param cnt   Count
 *
 * @return PJ_SUCCESS if success
 *
 */
PJ_DECL(pj_status_t) pj_websock_set_support_subproto(pj_websock_t *srv,
                                                     pj_str_t protos[],
                                                     int cnt);

/**
 * Set websocket user callbacks
 *
 * @param c         The websocket connection object
 * @param cb        The callbacks
 *
 * @return PJ_SUCCESS if successful
 *
 */
PJ_DECL(pj_status_t) pj_websock_set_callbacks(pj_websock_t *c,
                                              const pj_websock_cb *cb);

/**
 * Set websocket user data
 *
 * @param c         The websocket connection object
 * @param user_data The user data
 *
 * @return PJ_SUCCESS if successful
 *
 */
PJ_DECL(pj_status_t) pj_websock_set_userdata(pj_websock_t *c,
                                             const void *user_data);

/**
 * Get websocket user data
 *
 * @param c    The websocket connection object
 * @return     The websocket user data
 */
PJ_DECL(const void *) pj_websock_get_userdata(pj_websock_t *c);

/**
 * enable/disable websocket ping timer (auto send ping)
 *
 * @param c    The websocket connection object
 * @param t    The interval timeout to send ping message. if NULL, disable
 *
 * @return PJ_SUCCESS if successful
 */
PJ_DECL(pj_status_t) pj_websock_enable_ping(pj_websock_t *c, pj_time_val *t);

/**
 * Whether websocket connection is incoming
 *
 * @param c    The websocket connection object
 * @return     PJ_TRUE is incoming, else outgoing
 */
PJ_DECL(pj_bool_t) pj_websock_is_incoming(pj_websock_t *c);

/** Get websocket ready state
 *
 * @param c    The websocket connection object
 * @return     The websocket user data
 */
PJ_DECL(int) pj_websock_get_ready_state(pj_websock_t *c);

/**
 * Get Websocket request path
 * @param c    The websocket connection object
 * @return     The request path or NULL
 */
PJ_DECL(const char *) pj_websock_get_request_path(pj_websock_t *c);

/**
 * Get Websocket sub-protocol
 * @param c    The websocket connection object
 * @return     The sub-protol or NULL
 */
PJ_DECL(const char *) pj_websock_get_subproto(pj_websock_t *c);

/**
 * print Websocket basic info
 *
 * @param c    The websocket connection object
 * @param buf  The buffer to print use
 * @param len  The buffer length
 * @return     The info string
 */
PJ_DECL(const char *) pj_websock_print(pj_websock_t *c, char *buf, int len);

/**
 * Get websocket opcode string
 *
 * @param opcode  The opcode \a pj_websock_opcode
 * @return   Then string
 *
 */
PJ_DECL(const char *) pj_websock_opcode_str(int opcode);

/**
 * Get websocket state string
 *
 * @param state   The state \a pj_websock_readystate
 * @return   Then string
 */
PJ_DECL(const char *) pj_websock_state_str(int state);

/**
 * Get websocket transport type string
 *
 * @param type    The transport type \a pj_websock_transport_type
 * @return   Then string
 */
PJ_DECL(const char *) pj_websock_transport_str(int type);

PJ_END_DECL
/**
 * @}
 */
#endif
