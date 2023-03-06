#include "http.h"
#include <pjlib-util/scanner.h>

#define THIS_FILE "http.c"

static void on_syntax_error(struct pj_scanner *scanner)
{
    PJ_UNUSED_ARG(scanner);
    PJ_THROW(PJ_EINVAL);
}

PJ_DEF(pj_status_t) pj_http_uri_parse(const char *str_url, pj_http_uri *uri)
{
    pj_status_t status = PJ_SUCCESS;
    pj_scanner scanner;
    pj_cis_buf_t cs_buf;
    pj_cis_t spec; /* "/?" */
    pj_str_t s;
    char *p, *p2;

    PJ_ASSERT_RETURN(str_url && str_url[0], PJ_EINVAL);
    PJ_ASSERT_RETURN(uri, PJ_EINVAL);

    PJ_USE_EXCEPTION;

    pj_bzero(uri, sizeof(*uri));
    pj_scan_init(&scanner, (char *)str_url, pj_ansi_strlen(str_url), 0,
                 on_syntax_error);
    pj_cis_buf_init(&cs_buf);
    pj_cis_init(&cs_buf, &spec);
    pj_cis_add_str(&spec, "/?");

    PJ_TRY
    {
        /* get scheme */
        pj_scan_get_until_ch(&scanner, ':', &uri->scheme);

        /* next string must = "://" */
        if (pj_scan_strcmp(&scanner, "://", 3))
            return PJ_EINVAL;
        pj_scan_advance_n(&scanner, 3, PJ_FALSE);

        /*user:password@*/
        /*get util \?*, middle part "<user>:<pass>@<host>:<port>" */
        pj_scan_peek_until(&scanner, &spec, &s);
        p = pj_strchr(&s, '@');
        if (p) {
            p2 = pj_strchr(&s, ':');
            if (!p2)
                PJ_THROW(PJ_EINVAL);
            pj_strset3(&uri->user, s.ptr, p2);
            if (p2 + 1 == p) {
                /* passwd is empty */
                uri->pass.slen = 0;
                uri->pass.ptr = 0;
            } else {
                pj_strset3(&uri->pass, p2 + 1, p);
            }

            /* update position */
            pj_scan_advance_n(&scanner, p - s.ptr + 1, PJ_FALSE);
        }

        /* parse host:port */
        pj_scan_get_until(&scanner, &spec, &s);
        if (*s.ptr == '[' && (p = pj_strchr(&s, ']'))) {
            /*ipv6*/
            pj_strset3(&uri->host, s.ptr, p + 1);
            if (*(p + 1) == ':') {
                pj_strset3(&uri->port, p + 2, scanner.curptr);
            }
        } else {
            p = pj_strchr(&s, ':');
            if (p) {
                pj_strset3(&uri->host, s.ptr, p);
                pj_strset3(&uri->port, p + 1, scanner.curptr);
            } else {
                pj_strset3(&uri->host, s.ptr, scanner.curptr);
            }
        }

        /* parse request path */
        if (pj_scan_is_eof(&scanner) || *scanner.curptr == '?') {
            uri->path = pj_str("/");
        } else {
            pj_scan_get_until_chr(&scanner, "?", &uri->path);
            while (uri->path.slen > 1 &&
                   uri->path.ptr[uri->path.slen - 1] == '/') {
                /* strip path, eg. '/path/' to '/path' */
                uri->path.slen--;
            }
        }

        /* parse search args */
        if (*scanner.curptr == '?' && scanner.end - scanner.curptr > 1) {
            pj_strset3(&uri->search, scanner.curptr + 1, scanner.end);
        }
    }
    PJ_CATCH_ANY
    {
        status = PJ_GET_EXCEPTION();
    }
    PJ_END
    pj_scan_fini(&scanner);

    if (status != PJ_SUCCESS)
        return status;

    if (pj_stricmp2(&uri->scheme, "ws") && pj_stricmp2(&uri->scheme, "wss") &&
        pj_stricmp2(&uri->scheme, "http") &&
        pj_stricmp2(&uri->scheme, "https")) {
        return PJ_ENOTSUP;
    }

    if (uri->port.slen == 0) {
        /* set default port */
        if (!pj_stricmp2(&uri->scheme, "ws") ||
            !pj_stricmp2(&uri->scheme, "http")) {
            uri->port = pj_str("80");
        } else if (!pj_stricmp2(&uri->scheme, "wss") ||
                   !pj_stricmp2(&uri->scheme, "https")) {
            uri->port = pj_str("443");
        }
    } else {
        if (pj_strtol(&uri->port) > 65535)
            return PJ_ETOOBIG;
        if (pj_strtol(&uri->port) < 0)
            return PJ_ETOOSMALL;
    }

    return PJ_SUCCESS;
}

PJ_DEF(pj_bool_t) pj_http_uri_istls(const pj_http_uri *uri)
{
    if (!pj_stricmp2(&uri->scheme, "wss") ||
        !pj_stricmp2(&uri->scheme, "https")) {
        return PJ_TRUE;
    }
    return PJ_FALSE;
}

PJ_DEF(pj_uint16_t) pj_http_uri_port(const pj_http_uri *uri)
{
    if (uri->port.slen == 0) {
        if (pj_http_uri_istls(uri))
            return 443;
        else
            return 80;
    }
    return (pj_uint16_t)pj_strtoul(&uri->port);
}

static void init_http_msg(pj_http_msg *msg)
{
    pj_http_start_line *sl = &msg->start_line;

    pj_bzero(msg, sizeof(*msg));

    /* init start-line*/
    sl->u.req_line.method = &sl->s;
    sl->u.req_line.path = &sl->s2;
    sl->u.req_line.version = &sl->s3;
    sl->u.status_line.version = &sl->s;
    sl->u.status_line.status = &sl->s2;
    sl->u.status_line.reason = &sl->s3;
}
static void http_parse_start_line(pj_scanner *scanner, pj_http_msg *msg)
{
    pj_http_start_line *sl = &msg->start_line;
    pj_str_t CRLF = {"\r\n", 2};
    pj_str_t s;

    /*
     * simple check first char value
     * response-line : Must be HTTP/xx
     * start-line: GET (other method not supported now) // TODO:
     */
    if ((*scanner->curptr != 'H' && *scanner->curptr != 'h')    /* HTTP */
        && (*scanner->curptr != 'G' && *scanner->curptr != 'g') /* GET */
    ) {
        PJ_THROW(PJ_EINVAL);
    }

    /* Must contain CRLF */
    pj_strset3(&s, scanner->curptr, scanner->end);
    if (!pj_strstr(&s, &CRLF)) {
        /* incomplete */
        PJ_THROW(PJ_EPENDING);
    }

    /* first string */
    pj_scan_get_until_chr(scanner, " \r\n", &sl->s);
    if (*scanner->curptr != ' ')
        PJ_THROW(PJ_EINVAL);
    pj_scan_advance_n(scanner, 1, PJ_TRUE);

    /* second string */
    pj_scan_get_until_chr(scanner, " \r\n", &sl->s2);
    if (*scanner->curptr != ' ')
        PJ_THROW(PJ_EINVAL);
    pj_scan_advance_n(scanner, 1, PJ_TRUE);

    /* third string */
    pj_scan_get_until_chr(scanner, "\r\n", &sl->s3);
    if (pj_scan_strcmp(scanner, "\r\n", 2))
        PJ_THROW(PJ_EINVAL);
    pj_scan_advance_n(scanner, 2, PJ_FALSE);
}

static void http_parse_headers(pj_scanner *scanner, pj_http_msg *msg)
{
    pj_str_t TWO_CRLF = {"\r\n\r\n", 4};
    pj_str_t k, v;
    int max_cnt = PJ_ARRAY_SIZE(msg->hdrs);
    pj_http_hdr *hdrs = msg->hdrs;
    int cnt = 0;

    /* Must contain two CRLF */
    pj_strset3(&k, scanner->curptr, scanner->end);
    if (!pj_strstr(&k, &TWO_CRLF)) {
        /* incomplete */
        PJ_THROW(PJ_EPENDING);
    }

    while (1) {
        if (!pj_scan_strcmp(scanner, "\r\n", 2)) {
            /* finish parse headers */
            pj_scan_advance_n(scanner, 2, PJ_FALSE);
            break;
        }

        /* Get key */
        pj_scan_get_until_chr(scanner, ":\r\n", &k);
        if (*scanner->curptr != ':')
            PJ_THROW(PJ_EINVAL);
        pj_scan_advance_n(scanner, 1, PJ_TRUE);

        /* Get value */
        if (!pj_scan_strcmp(scanner, "\r\n", 2)) {
            /* value is empty */
            v.ptr = 0;
            v.slen = 0;
        } else {
            pj_scan_get_until_chr(scanner, "\r\n", &v);
            if (pj_scan_strcmp(scanner, "\r\n", 2))
                PJ_THROW(PJ_EINVAL);
        }
        pj_scan_advance_n(scanner, 2, PJ_FALSE);

        if (cnt < max_cnt) {
            pj_strtrim(&k);
            pj_strtrim(&v);
            hdrs[cnt].key = k;
            hdrs[cnt].val = v;
            cnt++;
        }
    }
    msg->hdr_cnt = cnt;
}

static void http_parse_body(pj_scanner *scanner, pj_http_msg *msg)
{
    pj_status_t status;
    pj_str_t C_LEN = {"Content-Length", 14};
    pj_str_t T_ENC = {"Transfer-Encoding", 17};
    pj_str_t CHUNKED = {"chunked", 7};
    pj_str_t s;
    pj_size_t len = 0;

    /* Get length by key name "Content-Length" */
    status = pj_http_msg_find_hdr(msg, &C_LEN, &s);
    if (status != PJ_SUCCESS) {
        /* Find key "Transfer-Encoding" */
        status = pj_http_msg_find_hdr(msg, &T_ENC, &s);
        if (status == PJ_SUCCESS && !pj_stricmp(&CHUNKED, &s)) {
            /* Not support "chunked": TODO: */
            PJ_THROW(PJ_ENOTSUP);
        }
    } else {
        len = (pj_size_t)pj_strtol(&s);
    }

    if (len == 0)
        return;
    if (scanner->end - scanner->curptr < len) {
        /* incomplete */
        PJ_THROW(PJ_EPENDING);
    }

    pj_strset(&msg->body, scanner->curptr, len);
    scanner->curptr += len;
}

PJ_DEF(pj_status_t) pj_http_msg_parse(const void *data,
                                      pj_size_t size,
                                      pj_http_msg *msg,
                                      pj_size_t *msg_len)
{
    pj_status_t status = PJ_SUCCESS;
    pj_scanner scanner;

    PJ_ASSERT_RETURN(data, PJ_EINVAL);
    PJ_ASSERT_RETURN(size > 0, PJ_EINVAL);
    PJ_ASSERT_RETURN(msg, PJ_EINVAL);

    init_http_msg(msg);

    PJ_USE_EXCEPTION;
    pj_scan_init(&scanner, (char *)data, size, 0, on_syntax_error);

    PJ_TRY
    {
        while (*scanner.curptr == '\r' || *scanner.curptr == '\n')
            pj_scan_get_newline(&scanner);
        http_parse_start_line(&scanner, msg);
        http_parse_headers(&scanner, msg);
        http_parse_body(&scanner, msg);
    }
    PJ_CATCH_ANY
    {
        status = PJ_GET_EXCEPTION();
        PJ_PERROR(2, (THIS_FILE, status, "msg parse, line:%d", scanner.line));
    }
    PJ_END
    pj_scan_fini(&scanner);

    if (status != PJ_SUCCESS) {
        return status;
    }

    if (msg_len)
        *msg_len = scanner.curptr - scanner.begin;

    return PJ_SUCCESS;
}

PJ_DEF(pj_status_t) pj_http_msg_find_hdr(const pj_http_msg *msg,
                                         const pj_str_t *key,
                                         pj_str_t *val)
{
    int i;
    PJ_ASSERT_RETURN(msg, PJ_EINVAL);
    PJ_ASSERT_RETURN(key, PJ_EINVAL);
    PJ_ASSERT_RETURN(val, PJ_EINVAL);

    for (i = 0; i < msg->hdr_cnt; i++) {
        if (!pj_stricmp(&msg->hdrs[i].key, key)) {
            *val = msg->hdrs[i].val;
            return PJ_SUCCESS;
        }
    }

    val->slen = 0;
    val->ptr = NULL;
    return PJ_ENOTFOUND;
}

PJ_DEF(pj_bool_t) pj_http_msg_is_response(const pj_http_msg *msg)
{
    PJ_ASSERT_RETURN(msg, PJ_FALSE);
    const pj_http_start_line *sl = &msg->start_line;

    if (!pj_strnicmp2(&sl->s, "HTTP/", 5))
        return PJ_TRUE;
    return PJ_FALSE;
}
