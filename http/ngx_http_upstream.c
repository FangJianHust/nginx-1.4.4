#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#if (NGX_HTTP_CACHE)
static ngx_int_t ngx_http_upstream_cache(ngx_http_request_t *r,ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_cache_send(ngx_http_request_t *r,ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_cache_status(ngx_http_request_t *r,ngx_http_variable_value_t *v, uintptr_t data);
#endif

static void ngx_http_upstream_init_request(ngx_http_request_t *r);
static void ngx_http_upstream_resolve_handler(ngx_resolver_ctx_t *ctx);
static void ngx_http_upstream_rd_check_broken_connection(ngx_http_request_t *r);
static void ngx_http_upstream_wr_check_broken_connection(ngx_http_request_t *r);
static void ngx_http_upstream_check_broken_connection(ngx_http_request_t *r,ngx_event_t *ev);
static void ngx_http_upstream_connect(ngx_http_request_t *r,ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_reinit(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_send_request(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_send_request_handler(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_process_header(ngx_http_request_t *r,ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_test_next(ngx_http_request_t *r,ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_intercept_errors(ngx_http_request_t *r,ngx_http_upstream_t *u);
static ngx_int_t ngx_http_upstream_test_connect(ngx_connection_t *c);
static ngx_int_t ngx_http_upstream_process_headers(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_process_body_in_memory(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_send_response(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_upgrade(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_upgraded_read_downstream(ngx_http_request_t *r);
static void ngx_http_upstream_upgraded_write_downstream(ngx_http_request_t *r);
static void ngx_http_upstream_upgraded_read_upstream(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_upgraded_write_upstream(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_process_upgraded(ngx_http_request_t *r,ngx_uint_t from_upstream, ngx_uint_t do_write);
static void ngx_http_upstream_process_non_buffered_downstream(ngx_http_request_t *r);
static void ngx_http_upstream_process_non_buffered_upstream(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_process_non_buffered_request(ngx_http_request_t *r,ngx_uint_t do_write);
static ngx_int_t ngx_http_upstream_non_buffered_filter_init(void *data);
static ngx_int_t ngx_http_upstream_non_buffered_filter(void *data,ssize_t bytes);
static void ngx_http_upstream_process_downstream(ngx_http_request_t *r);
static void ngx_http_upstream_process_upstream(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_process_request(ngx_http_request_t *r);
static void ngx_http_upstream_store(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_dummy_handler(ngx_http_request_t *r,ngx_http_upstream_t *u);
static void ngx_http_upstream_next(ngx_http_request_t *r,ngx_http_upstream_t *u, ngx_uint_t ft_type);
static void ngx_http_upstream_cleanup(void *data);
static void ngx_http_upstream_finalize_request(ngx_http_request_t *r, ngx_http_upstream_t *u, ngx_int_t rc);
static ngx_int_t ngx_http_upstream_process_header_line(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_content_length(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_set_cookie(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_cache_control(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_ignore_header_line(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_expires(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_accel_expires(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_limit_rate(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_buffering(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_charset(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_connection(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_process_transfer_encoding(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_copy_header_line(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_copy_multi_header_lines(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_copy_content_type(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_copy_last_modified(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_rewrite_location(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_rewrite_refresh(ngx_http_request_t *r,ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_rewrite_set_cookie(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);
static ngx_int_t ngx_http_upstream_copy_allow_ranges(ngx_http_request_t *r, ngx_table_elt_t *h, ngx_uint_t offset);

#if (NGX_HTTP_GZIP)
static ngx_int_t ngx_http_upstream_copy_content_encoding(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset);
#endif

static ngx_int_t ngx_http_upstream_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_upstream_addr_variable(ngx_http_request_t *r,ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_status_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_response_time_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upstream_response_length_variable( ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static char *ngx_http_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);
static char *ngx_http_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd,void *conf);
static ngx_addr_t *ngx_http_upstream_get_local(ngx_http_request_t *r,ngx_http_upstream_local_t *local);
static void *ngx_http_upstream_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_init_main_conf(ngx_conf_t *cf, void *conf);

#if (NGX_HTTP_SSL)
static void ngx_http_upstream_ssl_init_connection(ngx_http_request_t *,
    ngx_http_upstream_t *u, ngx_connection_t *c);
static void ngx_http_upstream_ssl_handshake(ngx_connection_t *c);
#endif


ngx_http_upstream_header_t  ngx_http_upstream_headers_in[] = {

    { ngx_string("Status"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, status),
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("Content-Type"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, content_type),
                 ngx_http_upstream_copy_content_type, 0, 1 },

    { ngx_string("Content-Length"),
                 ngx_http_upstream_process_content_length,
                 offsetof(ngx_http_upstream_headers_in_t, content_length),
                 ngx_http_upstream_ignore_header_line, 0, 0 },

    { ngx_string("Date"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, date),
                 ngx_http_upstream_copy_header_line,
                 offsetof(ngx_http_headers_out_t, date), 0 },

    { ngx_string("Last-Modified"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, last_modified),
                 ngx_http_upstream_copy_last_modified, 0, 0 },

    { ngx_string("ETag"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, etag),
                 ngx_http_upstream_copy_header_line,
                 offsetof(ngx_http_headers_out_t, etag), 0 },

    { ngx_string("Server"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, server),
                 ngx_http_upstream_copy_header_line,
                 offsetof(ngx_http_headers_out_t, server), 0 },

    { ngx_string("WWW-Authenticate"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, www_authenticate),
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("Location"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, location),
                 ngx_http_upstream_rewrite_location, 0, 0 },

    { ngx_string("Refresh"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_rewrite_refresh, 0, 0 },

    { ngx_string("Set-Cookie"),
                 ngx_http_upstream_process_set_cookie, 0,
                 ngx_http_upstream_rewrite_set_cookie, 0, 1 },

    { ngx_string("Content-Disposition"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_copy_header_line, 0, 1 },

    { ngx_string("Cache-Control"),
                 ngx_http_upstream_process_cache_control, 0,
                 ngx_http_upstream_copy_multi_header_lines,
                 offsetof(ngx_http_headers_out_t, cache_control), 1 },

    { ngx_string("Expires"),
                 ngx_http_upstream_process_expires, 0,
                 ngx_http_upstream_copy_header_line,
                 offsetof(ngx_http_headers_out_t, expires), 1 },

    { ngx_string("Accept-Ranges"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, accept_ranges),
                 ngx_http_upstream_copy_allow_ranges,
                 offsetof(ngx_http_headers_out_t, accept_ranges), 1 },

    { ngx_string("Connection"),
                 ngx_http_upstream_process_connection, 0,
                 ngx_http_upstream_ignore_header_line, 0, 0 },

    { ngx_string("Keep-Alive"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_ignore_header_line, 0, 0 },

    { ngx_string("X-Powered-By"),
                 ngx_http_upstream_ignore_header_line, 0,
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("X-Accel-Expires"),
                 ngx_http_upstream_process_accel_expires, 0,
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("X-Accel-Redirect"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, x_accel_redirect),
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("X-Accel-Limit-Rate"),
                 ngx_http_upstream_process_limit_rate, 0,
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("X-Accel-Buffering"),
                 ngx_http_upstream_process_buffering, 0,
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("X-Accel-Charset"),
                 ngx_http_upstream_process_charset, 0,
                 ngx_http_upstream_copy_header_line, 0, 0 },

    { ngx_string("Transfer-Encoding"),
                 ngx_http_upstream_process_transfer_encoding, 0,
                 ngx_http_upstream_ignore_header_line, 0, 0 },

#if (NGX_HTTP_GZIP)
    { ngx_string("Content-Encoding"),
                 ngx_http_upstream_process_header_line,
                 offsetof(ngx_http_upstream_headers_in_t, content_encoding),
                 ngx_http_upstream_copy_content_encoding, 0, 0 },
#endif

    { ngx_null_string, NULL, 0, NULL, 0, 0 }
};

//配置项命令
static ngx_command_t  ngx_http_upstream_commands[] = {

    { ngx_string("upstream"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_http_upstream,
      0,
      0,
      NULL },

    { ngx_string("server"),
      NGX_HTTP_UPS_CONF|NGX_CONF_1MORE,
      ngx_http_upstream_server,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_module_ctx = {
    ngx_http_upstream_add_variables,       /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_upstream_create_main_conf,    /* create main configuration */
    ngx_http_upstream_init_main_conf,      /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_module_ctx,         /* module context */
    ngx_http_upstream_commands,            /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_variable_t  ngx_http_upstream_vars[] = {

    { ngx_string("upstream_addr"), NULL,
      ngx_http_upstream_addr_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_status"), NULL,
      ngx_http_upstream_status_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_response_time"), NULL,
      ngx_http_upstream_response_time_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_string("upstream_response_length"), NULL,
      ngx_http_upstream_response_length_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

#if (NGX_HTTP_CACHE)

    { ngx_string("upstream_cache_status"), NULL,
      ngx_http_upstream_cache_status, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },

#endif

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_http_upstream_next_t  ngx_http_upstream_next_errors[] = {
    { 500, NGX_HTTP_UPSTREAM_FT_HTTP_500 },
    { 502, NGX_HTTP_UPSTREAM_FT_HTTP_502 },
    { 503, NGX_HTTP_UPSTREAM_FT_HTTP_503 },
    { 504, NGX_HTTP_UPSTREAM_FT_HTTP_504 },
    { 404, NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { 0, 0 }
};


ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[] = {
   { ngx_string("GET"),  NGX_HTTP_GET},
   { ngx_string("HEAD"), NGX_HTTP_HEAD },
   { ngx_string("POST"), NGX_HTTP_POST },
   { ngx_null_string, 0 }
};


ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[] = {
    { ngx_string("X-Accel-Redirect"), NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT },
    { ngx_string("X-Accel-Expires"), NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES },
    { ngx_string("X-Accel-Limit-Rate"), NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE },
    { ngx_string("X-Accel-Buffering"), NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING },
    { ngx_string("X-Accel-Charset"), NGX_HTTP_UPSTREAM_IGN_XA_CHARSET },
    { ngx_string("Expires"), NGX_HTTP_UPSTREAM_IGN_EXPIRES },
    { ngx_string("Cache-Control"), NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL },
    { ngx_string("Set-Cookie"), NGX_HTTP_UPSTREAM_IGN_SET_COOKIE },
    { ngx_null_string, 0 }
};

//创建upstream对象，将upstream对象挂在r->upstream字段下
ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r)
{
    ngx_http_upstream_t  *u;
    u = r->upstream;
    if (u && u->cleanup) {
        r->main->count++;
        ngx_http_upstream_cleanup(r);
    }
    u = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_t));
    if (u == NULL) {
        return NGX_ERROR;
    }
    r->upstream = u;
    u->peer.log = r->connection->log;
    u->peer.log_error = NGX_ERROR_ERR;
#if (NGX_THREADS)
    u->peer.lock = &r->connection->lock;
#endif
#if (NGX_HTTP_CACHE)
    r->cache = NULL;
#endif
    u->headers_in.content_length_n = -1;
    return NGX_OK;
}

//启动upstream机制
void ngx_http_upstream_init(ngx_http_request_t *r)
{
    ngx_connection_t     *c;
    c = r->connection;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http init upstream, client timer: %d", c->read->timer_set);
#if (NGX_HTTP_SPDY)
    if (r->spdy_stream) {
        ngx_http_upstream_init_request(r);
        return;
    }
#endif
	/* 首先检查请求对应于客户端的连接，这个连接上的读事件如果在定时器中，也就是说，读事件的timer_set为1,那么把读事件从定时器中移除，
	 * 因为一旦启动upstream机制，就不应该对客户端的读操作带有超时时间的处理，请求的主要触发事件将以与上游服务器的连接为主*/
    if (c->read->timer_set)
	{
        ngx_del_timer(c->read);
    }
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT)
    {
        if (!c->write->active)
        {
            if (ngx_add_event(c->write, NGX_WRITE_EVENT, NGX_CLEAR_EVENT) == NGX_ERROR)
            {
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }
    }
    ngx_http_upstream_init_request(r);
}

//向后端服务器发起请求
static void ngx_http_upstream_init_request(ngx_http_request_t *r)
{
    ngx_str_t                      *host;
    ngx_uint_t                      i;
    ngx_resolver_ctx_t             *ctx, temp;
    ngx_http_cleanup_t             *cln;
    ngx_http_upstream_t            *u;
    ngx_http_core_loc_conf_t       *clcf;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;
    if (r->aio) {
        return;
    }
    u = r->upstream;
#if (NGX_HTTP_CACHE)
    if (u->conf->cache)
    {
        ngx_int_t  rc;
        rc = ngx_http_upstream_cache(r, u);
        if (rc == NGX_BUSY) {
            r->write_event_handler = ngx_http_upstream_init_request;
            return;
        }
        r->write_event_handler = ngx_http_request_empty_handler;
        if (rc == NGX_DONE) {
            return;
        }
        if (rc != NGX_DECLINED) {
            ngx_http_finalize_request(r, rc);
            return;
        }
    }
#endif
    u->store = (u->conf->store || u->conf->store_lengths);
	/*ignore_client_abort为0时表示与上游服务器交互时需要处理Nginx与下游客户端之间的连接是否断开，如果出现错误，会立即终止连接*/
    if (!u->store && !r->post_action && !u->conf->ignore_client_abort) 
	{
        r->read_event_handler = ngx_http_upstream_rd_check_broken_connection;
        r->write_event_handler = ngx_http_upstream_wr_check_broken_connection;
    }
    if (r->request_body) {
        u->request_bufs = r->request_body->bufs;
    }
	//构造发往发往上游服务器的请求
    if (u->create_request(r) != NGX_OK) 
	{
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    u->peer.local = ngx_http_upstream_get_local(r, u->conf->local);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    u->output.alignment = clcf->directio_alignment;
    u->output.pool = r->pool;
    u->output.bufs.num = 1;
    u->output.bufs.size = clcf->client_body_buffer_size;
    u->output.output_filter = ngx_chain_writer;
    u->output.filter_ctx = &u->writer;
    u->writer.pool = r->pool;
    if (r->upstream_states == NULL)
    {
        r->upstream_states = ngx_array_create(r->pool, 1,sizeof(ngx_http_upstream_state_t));
        if (r->upstream_states == NULL) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }
    else
    {
        u->state = ngx_array_push(r->upstream_states);
        if (u->state == NULL)
        {
            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));
    }
	//向这个请求main成员指向的原始请求中的cleanup链表末尾添加一个新成员
    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
	//当请求结束时，一定会调用ngx_http_upstream_cleanup方法
    cln->handler = ngx_http_upstream_cleanup;
    cln->data = r;
    u->cleanup = &cln->handler;
    if (u->resolved == NULL) {
        uscf = u->conf->upstream;
    }
    else
    {
        if (u->resolved->sockaddr)
        {
            if (ngx_http_upstream_create_round_robin_peer(r, u->resolved) != NGX_OK)
            {
                ngx_http_upstream_finalize_request(r, u,NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
            //nginx与后台服务器建立通信连接
            ngx_http_upstream_connect(r, u);
            return;
        }
        host = &u->resolved->host;
        umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
        uscfp = umcf->upstreams.elts;
        for (i = 0; i < umcf->upstreams.nelts; i++)
        {
            uscf = uscfp[i];
            if (uscf->host.len == host->len &&
            			((uscf->port == 0 && u->resolved->no_port) || uscf->port == u->resolved->port) &&
            			ngx_memcmp(uscf->host.data, host->data, host->len) == 0)
            {
                goto found;
            }
        }
        if (u->resolved->port == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no port in upstream \"%V\"", host);
            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        temp.name = *host;
        ctx = ngx_resolve_start(clcf->resolver, &temp);
        if (ctx == NULL) {
            ngx_http_upstream_finalize_request(r, u,NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        if (ctx == NGX_NO_RESOLVER) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no resolver defined to resolve %V", host);
            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
            return;
        }
        ctx->name = *host;
        ctx->type = NGX_RESOLVE_A;
        ctx->handler = ngx_http_upstream_resolve_handler;
        ctx->data = r;
        ctx->timeout = clcf->resolver_timeout;
        u->resolved->ctx = ctx;
        if (ngx_resolve_name(ctx) != NGX_OK) {
            u->resolved->ctx = NULL;
            ngx_http_upstream_finalize_request(r, u,NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        return;
    }
found:
    if (uscf == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "no upstream configuration");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    if (uscf->peer.init(r, uscf) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_http_upstream_connect(r, u);
}
#if (NGX_HTTP_CACHE)

static ngx_int_t
ngx_http_upstream_cache(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t          rc;
    ngx_http_cache_t  *c;

    c = r->cache;

    if (c == NULL) {

        if (!(r->method & u->conf->cache_methods)) {
            return NGX_DECLINED;
        }

        if (r->method & NGX_HTTP_HEAD) {
            u->method = ngx_http_core_get_method;
        }

        if (ngx_http_file_cache_new(r) != NGX_OK) {
            return NGX_ERROR;
        }

        if (u->create_key(r) != NGX_OK) {
            return NGX_ERROR;
        }

        /* TODO: add keys */

        ngx_http_file_cache_create_key(r);

        if (r->cache->header_start + 256 >= u->conf->buffer_size) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%V_buffer_size %uz is not enough for cache key, "
                          "it should increased at least to %uz",
                          &u->conf->module, u->conf->buffer_size,
                          ngx_align(r->cache->header_start + 256, 1024));

            r->cache = NULL;
            return NGX_DECLINED;
        }

        u->cacheable = 1;

        switch (ngx_http_test_predicates(r, u->conf->cache_bypass)) {

        case NGX_ERROR:
            return NGX_ERROR;

        case NGX_DECLINED:
            u->cache_status = NGX_HTTP_CACHE_BYPASS;
            return NGX_DECLINED;

        default: /* NGX_OK */
            break;
        }

        c = r->cache;

        c->min_uses = u->conf->cache_min_uses;
        c->body_start = u->conf->buffer_size;
        c->file_cache = u->conf->cache->data;

        c->lock = u->conf->cache_lock;
        c->lock_timeout = u->conf->cache_lock_timeout;

        u->cache_status = NGX_HTTP_CACHE_MISS;
    }

    rc = ngx_http_file_cache_open(r);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream cache: %i", rc);

    switch (rc) {

    case NGX_HTTP_CACHE_UPDATING:

        if (u->conf->cache_use_stale & NGX_HTTP_UPSTREAM_FT_UPDATING) {
            u->cache_status = rc;
            rc = NGX_OK;

        } else {
            rc = NGX_HTTP_CACHE_STALE;
        }

        break;

    case NGX_OK:
        u->cache_status = NGX_HTTP_CACHE_HIT;
    }

    switch (rc) {

    case NGX_OK:

        rc = ngx_http_upstream_cache_send(r, u);

        if (rc != NGX_HTTP_UPSTREAM_INVALID_HEADER) {
            return rc;
        }

        break;

    case NGX_HTTP_CACHE_STALE:

        c->valid_sec = 0;
        u->buffer.start = NULL;
        u->cache_status = NGX_HTTP_CACHE_EXPIRED;

        break;

    case NGX_DECLINED:

        if ((size_t) (u->buffer.end - u->buffer.start) < u->conf->buffer_size) {
            u->buffer.start = NULL;

        } else {
            u->buffer.pos = u->buffer.start + c->header_start;
            u->buffer.last = u->buffer.pos;
        }

        break;

    case NGX_HTTP_CACHE_SCARCE:

        u->cacheable = 0;

        break;

    case NGX_AGAIN:

        return NGX_BUSY;

    case NGX_ERROR:

        return NGX_ERROR;

    default:

        /* cached NGX_HTTP_BAD_GATEWAY, NGX_HTTP_GATEWAY_TIME_OUT, etc. */

        u->cache_status = NGX_HTTP_CACHE_HIT;

        return rc;
    }

    r->cached = 0;

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_upstream_cache_send(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t          rc;
    ngx_http_cache_t  *c;

    r->cached = 1;
    c = r->cache;

    if (c->header_start == c->body_start) {
        r->http_version = NGX_HTTP_VERSION_9;
        return ngx_http_cache_send(r);
    }

    /* TODO: cache stack */

    u->buffer = *c->buf;
    u->buffer.pos += c->header_start;

    ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;

    if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    rc = u->process_header(r);

    if (rc == NGX_OK) {

        if (ngx_http_upstream_process_headers(r, u) != NGX_OK) {
            return NGX_DONE;
        }

        return ngx_http_cache_send(r);
    }

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* rc == NGX_HTTP_UPSTREAM_INVALID_HEADER */

    /* TODO: delete file */

    return rc;
}

#endif


static void
ngx_http_upstream_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_connection_t              *c;
    ngx_http_request_t            *r;
    ngx_http_upstream_t           *u;
    ngx_http_upstream_resolved_t  *ur;

    r = ctx->data;
    c = r->connection;

    u = r->upstream;
    ur = u->resolved;

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &ctx->name, ctx->state,
                      ngx_resolver_strerror(ctx->state));

        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_BAD_GATEWAY);
        goto failed;
    }

    ur->naddrs = ctx->naddrs;
    ur->addrs = ctx->addrs;

#if (NGX_DEBUG)
    {
    in_addr_t   addr;
    ngx_uint_t  i;

    for (i = 0; i < ctx->naddrs; i++) {
        addr = ntohl(ur->addrs[i]);

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "name was resolved to %ud.%ud.%ud.%ud",
                       (addr >> 24) & 0xff, (addr >> 16) & 0xff,
                       (addr >> 8) & 0xff, addr & 0xff);
    }
    }
#endif

    if (ngx_http_upstream_create_round_robin_peer(r, ur) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        goto failed;
    }

    ngx_resolve_name_done(ctx);
    ur->ctx = NULL;

    ngx_http_upstream_connect(r, u);

failed:

    ngx_http_run_posted_requests(c);
}

//类似于第11章的ngx_http_request_handler方法
static void ngx_http_upstream_handler(ngx_event_t *ev)
{
    ngx_connection_t     *c;
    ngx_http_request_t   *r;
    ngx_http_log_ctx_t   *ctx;
    ngx_http_upstream_t  *u;
    c = ev->data;//由事件的data成员取得ngx_connection_t连接，这个连接是nginx与上游服务器的连接
    r = c->data;//由连接的data成员取得ngx_http_request_t结构体
    u = r->upstream;//由请求的upstream成员取得表示upstream机制的ngx_http_upstream_t结构体
    c = r->connection;//注意，ngx_http_request_t结构体中的这个connection连接是客户端与nginx间的连接
    ctx = c->log->data;
    ctx->current_request = r;
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0, "http upstream request: \"%V?%V\"", &r->uri, &r->args);
    //当nginx与上游服务器间TCP连接的可写事件被触发时，upstream的write_event_handler方法会被调用
    if (ev->write) 
	{
        u->write_event_handler(r, u);
    } 
    //当nginx与上游服务器间TCP连接的可读事件被触发时，upstream的read_event_handler方法会被调用
	else
	{
        u->read_event_handler(r, u);
    }
    ngx_http_run_posted_requests(c);//该方法正是图11-12所说的方法，这里的参数c时来自客户端的连接，post请求也与11-12一致
}


static void
ngx_http_upstream_rd_check_broken_connection(ngx_http_request_t *r)
{
    ngx_http_upstream_check_broken_connection(r, r->connection->read);
}


static void
ngx_http_upstream_wr_check_broken_connection(ngx_http_request_t *r)
{
    ngx_http_upstream_check_broken_connection(r, r->connection->write);
}


static void
ngx_http_upstream_check_broken_connection(ngx_http_request_t *r,
    ngx_event_t *ev)
{
    int                  n;
    char                 buf[1];
    ngx_err_t            err;
    ngx_int_t            event;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "http upstream check client, write event:%d, \"%V\"",
                   ev->write, &r->uri);

    c = r->connection;
    u = r->upstream;

    if (c->error) {
        if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {

            event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

            if (ngx_del_event(ev, event, 0) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
        }

        if (!u->cacheable) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#if (NGX_HTTP_SPDY)
    if (r->spdy_stream) {
        return;
    }
#endif

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {

        if (!ev->pending_eof) {
            return;
        }

        ev->eof = 1;
        c->error = 1;

        if (ev->kq_errno) {
            ev->error = 1;
        }

        if (!u->cacheable && u->peer.connection) {
            ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                          "kevent() reported that client prematurely closed "
                          "connection, so upstream connection is closed too");
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
            return;
        }

        ngx_log_error(NGX_LOG_INFO, ev->log, ev->kq_errno,
                      "kevent() reported that client prematurely closed "
                      "connection");

        if (u->peer.connection == NULL) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_CLIENT_CLOSED_REQUEST);
        }

        return;
    }

#endif

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, err,
                   "http upstream recv(): %d", n);

    if (ev->write && (n >= 0 || err == NGX_EAGAIN)) {
        return;
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {

        event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;

        if (ngx_del_event(ev, event, 0) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    if (n > 0) {
        return;
    }

    if (n == -1) {
        if (err == NGX_EAGAIN) {
            return;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;
    c->error = 1;

    if (!u->cacheable && u->peer.connection) {
        ngx_log_error(NGX_LOG_INFO, ev->log, err,
                      "client prematurely closed connection, "
                      "so upstream connection is closed too");
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    ngx_log_error(NGX_LOG_INFO, ev->log, err,
                  "client prematurely closed connection");

    if (u->peer.connection == NULL) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
    }
}

//与上游服务器建立连接，使用非阻塞的套接字
static void ngx_http_upstream_connect(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t          rc;
    ngx_time_t        *tp;
    ngx_connection_t  *c;
    r->connection->log->action = "connecting to upstream";
    if (u->state && u->state->response_sec)
    {
        tp = ngx_timeofday();
        u->state->response_sec = tp->sec - u->state->response_sec;
        u->state->response_msec = tp->msec - u->state->response_msec;
    }
    u->state = ngx_array_push(r->upstream_states);
    if (u->state == NULL)
    {
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_memzero(u->state, sizeof(ngx_http_upstream_state_t));
    tp = ngx_timeofday();
    u->state->response_sec = tp->sec;
    u->state->response_msec = tp->msec;
    //真正进行请求建立连接工作
    rc = ngx_event_connect_peer(&u->peer);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http upstream connect: %i", rc);
    if (rc == NGX_ERROR)
    {
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    u->state->peer = u->peer.name;
    if (rc == NGX_BUSY) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "no live upstreams");
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_NOLIVE);
        return;
    }
    if (rc == NGX_DECLINED)
    {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }
    /* rc == NGX_OK || rc == NGX_AGAIN */
    c = u->peer.connection;
    c->data = r;
	/* 将这个连接ngx_connection_t上的读写事件的handler回调方法都设置为ngx_http_upstream_handler方法 */
    c->write->handler = ngx_http_upstream_handler;
    c->read->handler = ngx_http_upstream_handler;
    //设置向上游服务器发送请求的方法为ngx_http_upstream_send_request_handler方法
    u->write_event_handler = ngx_http_upstream_send_request_handler;
    //设置由ngx_http_upstream_process_header方法接收上游服务器的响应
    u->read_event_handler = ngx_http_upstream_process_header;
    c->sendfile &= r->connection->sendfile;
    u->output.sendfile = c->sendfile;
    if (c->pool == NULL)
    {
        /* we need separate pool here to be able to cache SSL connections */
        c->pool = ngx_create_pool(128, r->connection->log);
        if (c->pool == NULL) {
            ngx_http_upstream_finalize_request(r, u,NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }
    c->log = r->connection->log;
    c->pool->log = c->log;
    c->read->log = c->log;
    c->write->log = c->log;
    /* init or reinit the ngx_output_chain() and ngx_chain_writer() contexts */
    u->writer.out = NULL;
    u->writer.last = &u->writer.out;
    u->writer.connection = c;
    u->writer.limit = 0;
    if (u->request_sent)
    {
        if (ngx_http_upstream_reinit(r, u) != NGX_OK)
        {
            ngx_http_upstream_finalize_request(r, u,NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }
    if (r->request_body && r->request_body->buf && r->request_body->temp_file && r == r->main)
    {
        /* the r->request_body->buf can be reused for one request only, the subrequests should allocate their own
         temporary bufs */
        u->output.free = ngx_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        u->output.free->buf = r->request_body->buf;
        u->output.free->next = NULL;
        u->output.allocated = 1;
        r->request_body->buf->pos = r->request_body->buf->start;
        r->request_body->buf->last = r->request_body->buf->start;
        r->request_body->buf->tag = u->output.tag;
    }
    u->request_sent = 0;
    /*这一步处理非阻塞的连接尚未成功建立时的动作，由于上面已经将套接字加入到epoll中监控了，因此，这一步将调用ngx_add_timer方法把写事件添加到
     定时器中*/
    if (rc == NGX_AGAIN) 
	{
        ngx_add_timer(c->write, u->conf->connect_timeout);
        return;
    }
#if (NGX_HTTP_SSL)
    if (u->ssl && c->ssl == NULL) {
        ngx_http_upstream_ssl_init_connection(r, u, c);
        return;
    }
#endif
    ngx_http_upstream_send_request(r, u);//如果连接已经成功，调用该方法向上游服务器发送请求
}

#if (NGX_HTTP_SSL)

static void
ngx_http_upstream_ssl_init_connection(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_connection_t *c)
{
    ngx_int_t   rc;

    if (ngx_ssl_create_connection(u->conf->ssl, c,
                                  NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        != NGX_OK)
    {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    c->sendfile = 0;
    u->output.sendfile = 0;

    if (u->conf->ssl_session_reuse) {
        if (u->peer.set_session(&u->peer, u->peer.data) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    r->connection->log->action = "SSL handshaking to upstream";

    rc = ngx_ssl_handshake(c);

    if (rc == NGX_AGAIN) {
        c->ssl->handler = ngx_http_upstream_ssl_handshake;
        return;
    }

    ngx_http_upstream_ssl_handshake(c);
}


static void
ngx_http_upstream_ssl_handshake(ngx_connection_t *c)
{
    ngx_http_request_t   *r;
    ngx_http_upstream_t  *u;

    r = c->data;
    u = r->upstream;

    if (c->ssl->handshaked) {

        if (u->conf->ssl_session_reuse) {
            u->peer.save_session(&u->peer, u->peer.data);
        }

        c->write->handler = ngx_http_upstream_handler;
        c->read->handler = ngx_http_upstream_handler;

        ngx_http_upstream_send_request(r, u);

        return;
    }

    ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);

}

#endif


static ngx_int_t
ngx_http_upstream_reinit(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_chain_t  *cl;

    if (u->reinit_request(r) != NGX_OK) {
        return NGX_ERROR;
    }

    u->keepalive = 0;
    u->upgrade = 0;

    ngx_memzero(&u->headers_in, sizeof(ngx_http_upstream_headers_in_t));
    u->headers_in.content_length_n = -1;

    if (ngx_list_init(&u->headers_in.headers, r->pool, 8,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* reinit the request chain */

    for (cl = u->request_bufs; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->start;
        cl->buf->file_pos = 0;
    }

    /* reinit the subrequest's ngx_output_chain() context */

    if (r->request_body && r->request_body->temp_file
        && r != r->main && u->output.buf)
    {
        u->output.free = ngx_alloc_chain_link(r->pool);
        if (u->output.free == NULL) {
            return NGX_ERROR;
        }

        u->output.free->buf = u->output.buf;
        u->output.free->next = NULL;

        u->output.buf->pos = u->output.buf->start;
        u->output.buf->last = u->output.buf->start;
    }

    u->output.buf = NULL;
    u->output.in = NULL;
    u->output.busy = NULL;

    /* reinit u->buffer */

    u->buffer.pos = u->buffer.start;

#if (NGX_HTTP_CACHE)

    if (r->cache) {
        u->buffer.pos += r->cache->header_start;
    }

#endif

    u->buffer.last = u->buffer.pos;

    return NGX_OK;
}

/* 在发送请求到后端服务器的这个阶段中，每当TCP连接上再次可以发送字符流时，虽然事件框架就会调用ngx_http_upstream_send_request_handler
方法处理写事件，但最终还是通过调用ngx_http_upstream_send_requet方法把请求发送出去的 */
static void ngx_http_upstream_send_request(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_int_t          rc;
    ngx_connection_t  *c;
    c = u->peer.connection;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,"http upstream send request");
    if (!u->request_sent && ngx_http_upstream_test_connect(c) != NGX_OK)
    {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }
    c->log->action = "sending request to upstream";
/* 调用ngx_output_chain方法向上游服务器发送ngx_http_upstream_t结构体中的request_bufs链表，这个方法对于发送缓冲区构成的ngx_chain_t结构
体链表非常有用，它会把未发送完成的链表缓冲区保存下来，这样就不用每次调用时都携带上request_bufs链表。怎么理解呢？当第一次调用该方法时，需要传递
request_bufs链表构成的请求，如下：rc = ngx_output_chain(&u->output,u->request_bufs);这里的u就是请求对应的ngx_http_requets_t结构体
中的upstream成员，如果ngx_output_chain一次无法发送完所有的request_bufs请求内容，ngx_out_chain_ctx_t类型的u->output会把未发送完的请求
保存在自己的成员中，同时返回NGX_AGAIN。当写事件再次触发时，发送请求就不需要在传递参数了，例如：rc = ngx_output_chain(&u->output,NULL);为
了标识这一点，ngx_http_upstream_t结构体中专门有一个标识位request_sent表示是否已经传递了request_bufs缓冲区。因此，在第一次以request_bufs
作为参数调用output_chain方法后，request_sent会置为1*/
    rc = ngx_output_chain(&u->output, u->request_sent ? NULL : u->request_bufs);
    u->request_sent = 1;
    if (rc == NGX_ERROR) {
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }
	/* timer_set为1表示写事件仍然在定时器中，那么首先把写事件由定时器中取出，再由ngx_output_chain的返回值决定是否向定时器再次加入写事件，
	那时超时时间也会重置*/
    if (c->write->timer_set) 
	{
        ngx_del_timer(c->write);
    }
	/* 表示还有请求未发送 */
    if (rc == NGX_AGAIN) 
	{
        ngx_add_timer(c->write, u->conf->send_timeout);//添加写事件到定时器，防止发送请求超时
		/* 将写事件添加到epoll中 */
        if (ngx_handle_write_event(c->write, u->conf->send_lowat) != NGX_OK) 
		{
            ngx_http_upstream_finalize_request(r, u,NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        return;
    }
    /* rc == NGX_OK：已经向上游服务器发送完全部请求，这时将准备开始处理响应 */
    if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) 
	{
        if (ngx_tcp_push(c->fd) == NGX_ERROR) 
		{
            ngx_log_error(NGX_LOG_CRIT, c->log, ngx_socket_errno,ngx_tcp_push_n " failed");
            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
    }
    ngx_add_timer(c->read, u->conf->read_timeout);//首先把读事件添加到定时器中检查接收响应是否超时
#if 1
	/* 表示有响应可以读出 */
    if (c->read->ready) 
	{
    	//接收上游服务器的响应
        ngx_http_upstream_process_header(r, u);
        return;
    }
#endif
	/* 如果暂时没有响应可读，由于此时请求已经全部发送到上游服务器了，所以要防止可写事件再次触发而又调用ngx_http_upstream_send_request方法。
	这时，把write_event_handler设置为ngx_http_upstream_dummy_handler方法，该方法不会做任何事情。这样即使与上游间的TCP连接上再次有可写
	事件时也不会有任何动作发生*/
    u->write_event_handler = ngx_http_upstream_dummy_handler;
	/* 将写事件添加到epoll中 */
    if (ngx_handle_write_event(c->write, 0) != NGX_OK) 
	{
        ngx_http_upstream_finalize_request(r, u,NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
}

//调用ngx_http_upstream_send_request方法向上游服务器发送请求
static void ngx_http_upstream_send_request_handler(ngx_http_request_t *r,ngx_http_upstream_t *u)
{
    ngx_connection_t  *c;
    c = u->peer.connection;//获取与上游服务器间表示连接的ngx_connection_t结构体
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http upstream send request handler");
    //向上游服务器发送的请求已经超时
    if (c->write->timedout) 
	{
    	/*将超时错误传递给ngx_http_upstream_next方法，该方法将会根据允许的错误重连策略决定：重新发起连接执行upstream请求或者结束upstream请求*/
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }
#if (NGX_HTTP_SSL)
    if (u->ssl && c->ssl == NULL) {
        ngx_http_upstream_ssl_init_connection(r, u, c);
        return;
    }
#endif
	/* hander_sent为1表明上游服务器的响应需要直接转发给客户端，而且此时nginx已经把响应包头转发给客户端了 */
    if (u->header_sent) 
	{
		/* 事实上，header_sent为1时一定是已经解析完全部的上游响应包头，并且开始向下游发送HTTP的包头了。到此，是不应该继续向上游发送请求的，所以把
		write_event_handler设置为任何工作都没做的方法*/
        u->write_event_handler = ngx_http_upstream_dummy_handler;
        (void) ngx_handle_write_event(c->write, 0);//将写事件添加到epoll中
        return;//因为不存在继续发送请求道上游的可能，所以直接返回
    }
    ngx_http_upstream_send_request(r, u);//调用该方法向上游服务器发送请求
}

/* 接收、解析上游服务器的响应头部 */
static void ngx_http_upstream_process_header(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ssize_t            n;
    ngx_int_t          rc;
    ngx_connection_t  *c;
    c = u->peer.connection;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,"http upstream process header");
    c->log->action = "reading response header from upstream";
	/* 读取响应已经超时 */
    if (c->read->timedout)
	{
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_TIMEOUT);
        return;
    }
	/* request_sent为0表示还没有发送请求到上游服务器就收到来自上游的响应，不符合upstream的设计场景 */
    if (!u->request_sent && ngx_http_upstream_test_connect(c) != NGX_OK) 
	{
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
        return;
    }
	/* 缓冲区还未分配内存，这时按照ngx_http_upstream_conf_t配置结构体中的buffer_size成员指定的大小来为buffer缓冲区分配内存*/
    if (u->buffer.start == NULL) 
	{
        u->buffer.start = ngx_palloc(r->pool, u->conf->buffer_size);
        if (u->buffer.start == NULL) {
            ngx_http_upstream_finalize_request(r, u,NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        u->buffer.pos = u->buffer.start;
        u->buffer.last = u->buffer.start;
        u->buffer.end = u->buffer.start + u->conf->buffer_size;
        u->buffer.temporary = 1;
        u->buffer.tag = u->output.tag;
        if (ngx_list_init(&u->headers_in.headers, r->pool, 8,sizeof(ngx_table_elt_t))!= NGX_OK)
        {
            ngx_http_upstream_finalize_request(r, u,NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
#if (NGX_HTTP_CACHE)
        if (r->cache) {
            u->buffer.pos += r->cache->header_start;
            u->buffer.last = u->buffer.pos;
        }
#endif
    }
    for ( ;; ) 
	{
		/* 调用recv方法在buffer缓冲区中读取上游服务器发来的响应 */
        n = c->recv(c, u->buffer.last, u->buffer.end - u->buffer.last);
		/* 表示还需要继续接收响应 */
        if (n == NGX_AGAIN) 
		{
#if 0
            ngx_add_timer(rev, u->read_timeout);
#endif
			/* 将读事件添加到epoll中，等待读事件的下次触发 */
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) 
			{
                ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
            return;
        }
        if (n == 0)
        {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,"upstream prematurely closed connection");
        }
        if (n == NGX_ERROR || n == 0) 
		{
            ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_ERROR);
            return;
        }
        u->buffer.last += n;//返回值为整数表示接收到的响应长度
#if 0
        u->valid_header_in = 0;
        u->peer.cached = 0;
#endif
        rc = u->process_header(r);//解析响应头部
		/* 还没有接收到完整的包头 */
        if (rc == NGX_AGAIN) 
		{
			/* 检测buffer缓冲区是否用尽，如果用尽，说明包头太大，超出了缓冲区允许的大小，则用参数
			NGX_HTTP_UPSTREAM_FT_INCALID_HEADER调用ngx_http_upstream_next方法。表示包头不合法 */
            if (u->buffer.last == u->buffer.end) 
			{
                ngx_log_error(NGX_LOG_ERR, c->log, 0, "upstream sent too big header");
                ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
                return;
            }
            continue;//如果还有空闲空间，则继续接收上游服务器的响应
        }
        break;
    }
    if (rc == NGX_HTTP_UPSTREAM_INVALID_HEADER) 
	{//包头不合法
        ngx_http_upstream_next(r, u, NGX_HTTP_UPSTREAM_FT_INVALID_HEADER);
        return;
    }
    if (rc == NGX_ERROR) 
	{//解析出现错误
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    /* rc == NGX_OK：解析到完整的包头 */
    if (u->headers_in.status_n > NGX_HTTP_SPECIAL_RESPONSE)
    {
        if (r->subrequest_in_memory) {
            u->buffer.last = u->buffer.pos;
        }
        if (ngx_http_upstream_test_next(r, u) == NGX_OK) {
            return;
        }
        if (ngx_http_upstream_intercept_errors(r, u) == NGX_OK) {
            return;
        }
    }
	/* 处理已经解析出的头部，该方法把已经解析出的头部设置到ngx_http_request_t结构体的headers_out成员中，这样在调用
	ngx_http_send_header方法发送响应包头给客户端时将会发送这些设置了的头部*/
    if (ngx_http_upstream_process_headers(r, u) != NGX_OK) 
	{
        return;
    }
	/* 检查是否需要转发响应，subrequest_in_memory为0表示需要转发响应到客户端 */
    if (!r->subrequest_in_memory) 
	{
        ngx_http_upstream_send_response(r, u);//开始转发响应给客户端
        return;
    }
	/* 不需要转发响应。如果没有实现用于处理包体的input_filter方法，使用默认方法ngx_http_upstream_non_buffered_filter处理包体 */
    if (u->input_filter == NULL) 
	{
        u->input_filter_init = ngx_http_upstream_non_buffered_filter_init;
        u->input_filter = ngx_http_upstream_non_buffered_filter;
        u->input_filter_ctx = r;//设置为ngx_http_request_t结构体指针
    }
	/* 用户实现了input_filter方法，表示用户希望自己处理包体，为处理包体做初始化工作 */
    if (u->input_filter_init(u->input_filter_ctx) == NGX_ERROR) 
	{
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
	/* 在上面的process_header方法中，如果解析完包头后缓冲区中还有多余的字符，则表示还接收到了包体，这时将调用input_filter
	方法第一次处理接收到的包体*/
    n = u->buffer.last - u->buffer.pos;
    if (n) 
	{
        u->buffer.last -= n;
        u->state->response_length += n;
        if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }
        if (u->length == 0) {
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
    }
	/* 表示再有上游服务器发来响应包体时，将由ngx_http_upstream_body_in_memory方法处理 */
    u->read_event_handler = ngx_http_upstream_process_body_in_memory;
    ngx_http_upstream_process_body_in_memory(r, u);//处理包体
}


static ngx_int_t
ngx_http_upstream_test_next(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_uint_t                 status;
    ngx_http_upstream_next_t  *un;

    status = u->headers_in.status_n;

    for (un = ngx_http_upstream_next_errors; un->status; un++) {

        if (status != un->status) {
            continue;
        }

        if (u->peer.tries > 1 && (u->conf->next_upstream & un->mask)) {
            ngx_http_upstream_next(r, u, un->mask);
            return NGX_OK;
        }

#if (NGX_HTTP_CACHE)

        if (u->cache_status == NGX_HTTP_CACHE_EXPIRED
            && (u->conf->cache_use_stale & un->mask))
        {
            ngx_int_t  rc;

            rc = u->reinit_request(r);

            if (rc == NGX_OK) {
                u->cache_status = NGX_HTTP_CACHE_STALE;
                rc = ngx_http_upstream_cache_send(r, u);
            }

            ngx_http_upstream_finalize_request(r, u, rc);
            return NGX_OK;
        }

#endif
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_upstream_intercept_errors(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_int_t                  status;
    ngx_uint_t                 i;
    ngx_table_elt_t           *h;
    ngx_http_err_page_t       *err_page;
    ngx_http_core_loc_conf_t  *clcf;

    status = u->headers_in.status_n;

    if (status == NGX_HTTP_NOT_FOUND && u->conf->intercept_404) {
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_NOT_FOUND);
        return NGX_OK;
    }

    if (!u->conf->intercept_errors) {
        return NGX_DECLINED;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->error_pages == NULL) {
        return NGX_DECLINED;
    }

    err_page = clcf->error_pages->elts;
    for (i = 0; i < clcf->error_pages->nelts; i++) {

        if (err_page[i].status == status) {

            if (status == NGX_HTTP_UNAUTHORIZED
                && u->headers_in.www_authenticate)
            {
                h = ngx_list_push(&r->headers_out.headers);

                if (h == NULL) {
                    ngx_http_upstream_finalize_request(r, u,
                                               NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return NGX_OK;
                }

                *h = *u->headers_in.www_authenticate;

                r->headers_out.www_authenticate = h;
            }

#if (NGX_HTTP_CACHE)

            if (r->cache) {
                time_t  valid;

                valid = ngx_http_file_cache_valid(u->conf->cache_valid, status);

                if (valid) {
                    r->cache->valid_sec = ngx_time() + valid;
                    r->cache->error = status;
                }

                ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
            }
#endif
            ngx_http_upstream_finalize_request(r, u, status);

            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_upstream_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)  {
        if (c->write->pending_eof || c->read->pending_eof) {
            if (c->write->pending_eof) {
                err = c->write->kq_errno;

            } else {
                err = c->read->kq_errno;
            }

            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err,
                                    "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        /*
         * BSDs and Linux return 0 and set a pending error in err
         * Solaris returns -1 and sets errno
         */

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len)
            == -1)
        {
            err = ngx_errno;
        }

        if (err) {
            c->log->action = "connecting to upstream";
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

/* 处理已经解析出的头部，该方法把已经解析出的头部设置到ngx_http_request_t结构体的headers_out成员中，这样在调用
ngx_http_send_header方法发送响应包头给客户端时将会发送这些设置了的头部*/
static ngx_int_t ngx_http_upstream_process_headers(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_str_t                      *uri, args;
    ngx_uint_t                      i, flags;
    ngx_list_part_t                *part;
    ngx_table_elt_t                *h;
    ngx_http_upstream_header_t     *hh;
    ngx_http_upstream_main_conf_t  *umcf;
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);
    if (u->headers_in.x_accel_redirect && !(u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT))
    {
        ngx_http_upstream_finalize_request(r, u, NGX_DECLINED);
        part = &u->headers_in.headers.part;
        h = part->elts;
        for (i = 0; /* void */; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }
                part = part->next;
                h = part->elts;
                i = 0;
            }
            hh = ngx_hash_find(&umcf->headers_in_hash, h[i].hash,h[i].lowcase_key, h[i].key.len);
            if (hh && hh->redirect) {
                if (hh->copy_handler(r, &h[i], hh->conf) != NGX_OK) {
                    ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                    return NGX_DONE;
                }
            }
        }
        uri = &u->headers_in.x_accel_redirect->value;
        ngx_str_null(&args);
        flags = NGX_HTTP_LOG_UNSAFE;
        if (ngx_http_parse_unsafe_uri(r, uri, &args, &flags) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_NOT_FOUND);
            return NGX_DONE;
        }
        if (r->method != NGX_HTTP_HEAD) {
            r->method = NGX_HTTP_GET;
        }
        ngx_http_internal_redirect(r, uri, &args);
        ngx_http_finalize_request(r, NGX_DONE);
        return NGX_DONE;
    }
    part = &u->headers_in.headers.part;
    h = part->elts;
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (ngx_hash_find(&u->conf->hide_headers_hash, h[i].hash, h[i].lowcase_key, h[i].key.len))
        {
            continue;
        }
        hh = ngx_hash_find(&umcf->headers_in_hash, h[i].hash, h[i].lowcase_key, h[i].key.len);
        if (hh) {
            if (hh->copy_handler(r, &h[i], hh->conf) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return NGX_DONE;
            }
            continue;
        }
        if (ngx_http_upstream_copy_header_line(r, &h[i], 0) != NGX_OK) {
            ngx_http_upstream_finalize_request(r, u, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NGX_DONE;
        }
    }
    if (r->headers_out.server && r->headers_out.server->value.data == NULL) {
        r->headers_out.server->hash = 0;
    }
    if (r->headers_out.date && r->headers_out.date->value.data == NULL) {
        r->headers_out.date->hash = 0;
    }
    r->headers_out.status = u->headers_in.status_n;
    r->headers_out.status_line = u->headers_in.status_line;
    r->headers_out.content_length_n = u->headers_in.content_length_n;
    u->length = u->headers_in.content_length_n;
    return NGX_OK;
}

/* 在upstream机制不转发响应时，作为读事件的回调方法在内存中处理上游服务器响应包体的。它会负责接收上游服务器的包体，同时调用HTTP模块实现的
input_filter方法处理包体*/
static void ngx_http_upstream_process_body_in_memory(ngx_http_request_t *r,ngx_http_upstream_t *u)
{
    size_t             size;
    ssize_t            n;
    ngx_buf_t         *b;
    ngx_event_t       *rev;
    ngx_connection_t  *c;
    c = u->peer.connection;
    rev = c->read;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,"http upstream process body on memory");
	/* 读取响应超时 */
    if (rev->timedout) 
	{
        ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
        ngx_http_upstream_finalize_request(r, u, NGX_ETIMEDOUT);
        return;
    }
    b = &u->buffer;
    for ( ;; ) 
	{
        size = b->end - b->last;
		/* 缓冲区已经用尽 */
        if (size == 0) 
		{
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,"upstream buffer is too small to read response");
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }
        n = c->recv(c, b->last, size);//接收包体，接收到的内容存放在buffer缓冲区的last成员指向的内存中
        if (n == NGX_AGAIN) 
		{//期待下一次的读事件
            break;
        }
		/* 返回ERROR或者上游服务器主动关闭连接 */
        if (n == 0 || n == NGX_ERROR) 
		{
            ngx_http_upstream_finalize_request(r, u, n);
            return;
        }
		/* 返回正数，表示接收到的响应长度，然后调用input_filter方法处理本次接收到的包体 */
        u->state->response_length += n;
        if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR) {
            ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
            return;
        }
        if (!rev->ready) 
		{
            break;
        }
    }
    if (u->length == 0) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }
	/* 将读事件添加到epoll中 */
    if (ngx_handle_read_event(rev, 0) != NGX_OK) 
	{
        ngx_http_upstream_finalize_request(r, u, NGX_ERROR);
        return;
    }
	/* 将读事件添加到定时器中 */
    if (rev->active) 
	{
        ngx_add_timer(rev, u->conf->read_timeout);

    } else if (rev->timer_set) {
        ngx_del_timer(rev);
    }
}

//转发响应包头
static void ngx_http_upstream_send_response(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    int                        tcp_nodelay;
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_event_pipe_t          *p;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;
	/* 向下游客户端发送HTTP包头:在接收后台服务器的响应包头时，HTTP模块会通过process_header方法解析包头，并将解析出的值设置到ngx_http_upstream_t
	结构体的headers_in成员中，然后，ngx_http_process_headers方法会把headers_in中的头部设置到将要发送给客户端的header_out结构体中，
	ngx_http_send_header方法就是用来把这些包头发送给客户端的，这一步同时会将header_sent标志位置为1，该标志位在发送请求道上游服务器时会使用 */
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->post_action) {
        ngx_http_upstream_finalize_request(r, u, rc);
        return;
    }
    if (u->upgrade) {
        ngx_http_upstream_upgrade(r, u);
        return;
    }
    c = r->connection;
    if (r->header_only)
    {
        if (u->cacheable || u->store)
        {
            if (ngx_shutdown_socket(c->fd, NGX_WRITE_SHUTDOWN) == -1) {
                ngx_connection_error(c, ngx_socket_errno,ngx_shutdown_socket_n " failed");
            }
            r->read_event_handler = ngx_http_request_empty_handler;
            r->write_event_handler = ngx_http_request_empty_handler;
            c->error = 1;
        }
        else
        {
            ngx_http_upstream_finalize_request(r, u, rc);
            return;
        }
    }
    u->header_sent = 1;
	/* 如果客户端请求中有HTTP包体，而且曾经调用过11.8.1节中的ngx_http_read_client_request_body方法接收HTTP包体并把包体存放在了临时文件中，
	这时就会调用ngx_http_run_cleanup_file方法清理临时文件，为什么要在这一步清理临时文件呢？因为后台服务器发送响应时肯定会使用到临时文件，之后
	收到响应解析响应包体时也不可以清理临时文件，而一旦开始向下游客户端转发HTTP响应时，则意味着肯定不会再需要客户端请求的包体了，这时可以关闭、转移
	或者删除临时文件，具体动作由HTTP模块实现的handler回调方法决定 */
    if (r->request_body && r->request_body->temp_file) 
	{
        ngx_pool_run_cleanup_file(r->pool, r->request_body->temp_file->file.fd);
        r->request_body->temp_file->file.fd = NGX_INVALID_FILE;
    }
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (!u->buffering) 
	{
		/* 如果HTTP模块没有实现过滤包体的input_filter方法，则设置默认的包体处理方法：ngx_http_upstream_non_buffered_filter，它的工作就
		在于使用out_bufs链表指向接收到的buffer缓冲区的内容 */
        if (u->input_filter == NULL) 
		{
            u->input_filter_init = ngx_http_upstream_non_buffered_filter_init;
            u->input_filter = ngx_http_upstream_non_buffered_filter;
            u->input_filter_ctx = r;
        }
		/* 设置读取上游服务器响应的方法，当上游服务器接收到响应时，通过ngx_http_upstream_handler方法可最终调用
		ngx_http_upstream_non_buffered_upstream方法来接收响应*/
        u->read_event_handler = ngx_http_upstream_process_non_buffered_upstream;
		/* 设置向下游客户端发送包体的方法，一旦TCP连接上可以向下游客户端发送数据时，会通过ngx_http_handler方法最终调用
		ngx_http_upstream_process_non_buffered_downstream来发送响应包体*/
        r->write_event_handler =ngx_http_upstream_process_non_buffered_downstream;
        r->limit_rate = 0;
		/* 调用HTTP模块实现的input_filter_init方法(当HTTP模块没有实现input_filter方法时，它是默认任何事情也不做的
		ngx_http_upstream_non_buffered_filter_init方法)，为input_filter方法处理包体做初始化准备 */
        if (u->input_filter_init(u->input_filter_ctx) == NGX_ERROR) 
		{
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
        if (clcf->tcp_nodelay && c->tcp_nodelay == NGX_TCP_NODELAY_UNSET)
        {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "tcp_nodelay");
            tcp_nodelay = 1;
            if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,(const void *) &tcp_nodelay, sizeof(int)) == -1)
            {
                ngx_connection_error(c, ngx_socket_errno,"setsockopt(TCP_NODELAY) failed");
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }
            c->tcp_nodelay = NGX_TCP_NODELAY_SET;
        }
		/* 检测buffer缓冲区在解析完包头后，是否还有已经接收到的包体 */
        n = u->buffer.last - u->buffer.pos;
		/* 如果已经接收到包体 */
        if (n) 
		{
            u->buffer.last = u->buffer.pos;
            u->state->response_length += n;
			/* 处理包体 */
            if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR) 
			{
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }
			/* 把本次接收到的包体向下游客户端发送 */
            ngx_http_upstream_process_non_buffered_downstream(r);
        } 
		else
		{
			/* 没有接收到包体，将buffer缓冲区清空：pos指针一般指向未经处理的响应，而last指针一般指向刚接收到的响应，这时把它们设为缓冲区起始
			地址即表示清空缓冲区*/
            u->buffer.pos = u->buffer.start;
            u->buffer.last = u->buffer.start;
			/* NGX_HTTP_PLUSH意味着如果请求r的out缓冲区中依然有等待发送的响应，则催促着发送他们 */
            if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }
			/* 如果与上游服务器的连接上有可读事件，则处理该响应，否则，当前流程结束，将控制权交还给nginx框架 */
            if (u->peer.connection->read->ready || u->length == 0) 
			{
                ngx_http_upstream_process_non_buffered_upstream(r, u);
            }
        }
        return;
    }
#if (NGX_HTTP_CACHE)
    if (r->cache && r->cache->file.fd != NGX_INVALID_FILE) {
        ngx_pool_run_cleanup_file(r->pool, r->cache->file.fd);
        r->cache->file.fd = NGX_INVALID_FILE;
    }
    switch (ngx_http_test_predicates(r, u->conf->no_cache)) {
    case NGX_ERROR:
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    case NGX_DECLINED:
        u->cacheable = 0;
        break;
    default: /* NGX_OK */
        if (u->cache_status == NGX_HTTP_CACHE_BYPASS) {
            r->cache->min_uses = u->conf->cache_min_uses;
            r->cache->body_start = u->conf->buffer_size;
            r->cache->file_cache = u->conf->cache->data;
            if (ngx_http_file_cache_create(r) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }
        }
        break;
    }
    if (u->cacheable) {
        time_t  now, valid;
        now = ngx_time();
        valid = r->cache->valid_sec;
        if (valid == 0) {
            valid = ngx_http_file_cache_valid(u->conf->cache_valid, u->headers_in.status_n);
            if (valid) {
                r->cache->valid_sec = now + valid;
            }
        }
        if (valid) {
            r->cache->last_modified = r->headers_out.last_modified_time;
            r->cache->date = now;
            r->cache->body_start = (u_short) (u->buffer.pos - u->buffer.start);
            ngx_http_file_cache_set_header(r, u->buffer.start);
        } else {
            u->cacheable = 0;
            r->headers_out.last_modified_time = -1;
        }
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,"http cacheable: %d", u->cacheable);
    if (u->cacheable == 0 && r->cache) {
        ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
    }
#endif

	/* 初始化ngx_http_upstream_t结构体中的匹配成员 */
    p = u->pipe;//这里是直接引用必须分配过内存的pipe成员
	/* 设置向下游客户端发送响应的方法 */
    p->output_filter = (ngx_event_pipe_output_filter_pt) ngx_http_output_filter;
	/* output_ctx指向当前请求的ngx_http_request_t结构体，这时应为接下来转发包体的方法都只接受ngx_event_pipe_t参数，且只能由
	output_ctx成员获取到表示请求的ngx_http_request_t结构体*/
    p->output_ctx = r;
    p->tag = u->output.tag;//设置转发响应时启用的每个缓冲区的tag标志位
    p->bufs = u->conf->bufs;//bufs指定了内存缓冲区的限制
    p->busy_size = u->conf->busy_buffers_size;//设置busy缓冲区中待发送的响应长度触发值
    p->upstream = u->peer.connection;//upstream被初始化为nginx与上游服务器之间的连接
    p->downstream = c;//初始化为nginx与下游客户端之间的连接
    p->pool = r->pool;//初始化用于分配内存缓冲区饿内存池
    p->log = c->log;
    p->cacheable = u->cacheable || u->store;
    p->temp_file = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
    if (p->temp_file == NULL) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }
    p->temp_file->file.fd = NGX_INVALID_FILE;
    p->temp_file->file.log = c->log;
    p->temp_file->path = u->conf->temp_path;
    p->temp_file->pool = r->pool;
    if (p->cacheable) {
        p->temp_file->persistent = 1;
    } else {
        p->temp_file->log_level = NGX_LOG_WARN;
        p->temp_file->warn = "an upstream response is buffered to a temporary file";
    }
    p->max_temp_file_size = u->conf->max_temp_file_size;//设置临时存放上游响应的单个缓存文件的最大长度
    p->temp_file_write_size = u->conf->temp_file_write_size;//设置一次写入文件时写入的最大长度
    p->preread_bufs = ngx_alloc_chain_link(r->pool);
    if (p->preread_bufs == NULL) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }
	/* 初始化preread_bufs预读缓冲区链表(所谓预读，就是在读取包头时也预先读取到了部分包体)，注意，该链表中的缓冲区都是不会分配内存来存放
上游响应内容的，而仅使用ngx_buf_t结构体指向实际存放的响应包体的内存，实际上就是把preread_bufs缓冲区指向存放头部的buffer缓冲区*/
    p->preread_bufs->buf = &u->buffer;
    p->preread_bufs->next = NULL;
    u->buffer.recycled = 1;
    p->preread_size = u->buffer.last - u->buffer.pos;
    if (u->cacheable) {
        p->buf_to_file = ngx_calloc_buf(r->pool);
        if (p->buf_to_file == NULL) {
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
        p->buf_to_file->start = u->buffer.start;
        p->buf_to_file->pos = u->buffer.start;
        p->buf_to_file->last = u->buffer.pos;
        p->buf_to_file->temporary = 1;
    }
    if (ngx_event_flags & NGX_USE_AIO_EVENT) {
        /* the posted aio operation may corrupt a shadow buffer */
        p->single_buf = 1;
    }/
    p->free_bufs = 1;
    /* event_pipe would do u->buffer.last += p->preread_size as though these bytes were read*/
    u->buffer.last = u->buffer.pos;
    if (u->conf->cyclic_temp_file) {
        /* we need to disable the use of sendfile() if we use cyclic temp file because the writing a new data may
        interfere with sendfile() that uses the same kernel file pages (at least on FreeBSD) */
        p->cyclic_temp_file = 1;
        c->sendfile = 0;

    } else {
        p->cyclic_temp_file = 0;
    }
    p->read_timeout = u->conf->read_timeout;//以当前location下的配置来设置读取上游响应的超时时间
    p->send_timeout = clcf->send_timeout;//以当前location下的配置来设置发送到下游的超时时间
    p->send_lowat = clcf->send_lowat;//设置客户端发送响应时TCP中的send_lowat水位
    p->length = -1;
    if (u->input_filter_init && u->input_filter_init(p->input_ctx) != NGX_OK)
    {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }
	/* 处理上游读事件和下游写事件的方法最终都是通过ngx_event_pipe_t方法实现缓存转发响应功能的 */
    u->read_event_handler = ngx_http_upstream_process_upstream;//设置处理上游读事件的回调方法
    r->write_event_handler = ngx_http_upstream_process_downstream;//设置处理下游写事件的回调方法
    ngx_http_upstream_process_upstream(r, u);//处理上游发来的响应包体
}


static void
ngx_http_upstream_upgrade(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    int                        tcp_nodelay;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    /* TODO: prevent upgrade if not requested or not possible */

    r->keepalive = 0;
    c->log->action = "proxying upgraded connection";

    u->read_event_handler = ngx_http_upstream_upgraded_read_upstream;
    u->write_event_handler = ngx_http_upstream_upgraded_write_upstream;
    r->read_event_handler = ngx_http_upstream_upgraded_read_downstream;
    r->write_event_handler = ngx_http_upstream_upgraded_write_downstream;

    if (clcf->tcp_nodelay) {
        tcp_nodelay = 1;

        if (c->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "tcp_nodelay");

            if (setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY,
                           (const void *) &tcp_nodelay, sizeof(int)) == -1)
            {
                ngx_connection_error(c, ngx_socket_errno,
                                     "setsockopt(TCP_NODELAY) failed");
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }

            c->tcp_nodelay = NGX_TCP_NODELAY_SET;
        }

        if (u->peer.connection->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, u->peer.connection->log, 0,
                           "tcp_nodelay");

            if (setsockopt(u->peer.connection->fd, IPPROTO_TCP, TCP_NODELAY,
                           (const void *) &tcp_nodelay, sizeof(int)) == -1)
            {
                ngx_connection_error(u->peer.connection, ngx_socket_errno,
                                     "setsockopt(TCP_NODELAY) failed");
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }

            u->peer.connection->tcp_nodelay = NGX_TCP_NODELAY_SET;
        }
    }

    if (ngx_http_send_special(r, NGX_HTTP_FLUSH) == NGX_ERROR) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

    if (u->peer.connection->read->ready
        || u->buffer.pos != u->buffer.last)
    {
        ngx_http_upstream_process_upgraded(r, 1, 1);
    }

    if (c->read->ready
        || r->header_in->pos != r->header_in->last)
    {
        ngx_http_upstream_process_upgraded(r, 0, 1);
    }
}


static void
ngx_http_upstream_upgraded_read_downstream(ngx_http_request_t *r)
{
    ngx_http_upstream_process_upgraded(r, 0, 0);
}


static void
ngx_http_upstream_upgraded_write_downstream(ngx_http_request_t *r)
{
    ngx_http_upstream_process_upgraded(r, 1, 1);
}


static void
ngx_http_upstream_upgraded_read_upstream(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_http_upstream_process_upgraded(r, 1, 0);
}


static void
ngx_http_upstream_upgraded_write_upstream(ngx_http_request_t *r,
    ngx_http_upstream_t *u)
{
    ngx_http_upstream_process_upgraded(r, 0, 1);
}


static void
ngx_http_upstream_process_upgraded(ngx_http_request_t *r,
    ngx_uint_t from_upstream, ngx_uint_t do_write)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_connection_t          *c, *downstream, *upstream, *dst, *src;
    ngx_http_upstream_t       *u;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    u = r->upstream;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process upgraded, fu:%ui", from_upstream);

    downstream = c;
    upstream = u->peer.connection;

    if (downstream->write->timedout) {
        c->timedout = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    if (upstream->read->timedout || upstream->write->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

    if (from_upstream) {
        src = upstream;
        dst = downstream;
        b = &u->buffer;

    } else {
        src = downstream;
        dst = upstream;
        b = &u->from_client;

        if (r->header_in->last > r->header_in->pos) {
            b = r->header_in;
            b->end = b->last;
            do_write = 1;
        }

        if (b->start == NULL) {
            b->start = ngx_palloc(r->pool, u->conf->buffer_size);
            if (b->start == NULL) {
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }

            b->pos = b->start;
            b->last = b->start;
            b->end = b->start + u->conf->buffer_size;
            b->temporary = 1;
            b->tag = u->output.tag;
        }
    }

    for ( ;; ) {

        if (do_write) {

            size = b->last - b->pos;

            if (size && dst->write->ready) {

                n = dst->send(dst, b->pos, size);

                if (n == NGX_ERROR) {
                    ngx_http_upstream_finalize_request(r, u, 0);
                    return;
                }

                if (n > 0) {
                    b->pos += n;

                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

        size = b->end - b->last;

        if (size && src->read->ready) {

            n = src->recv(src, b->last, size);

            if (n == NGX_AGAIN || n == 0) {
                break;
            }

            if (n > 0) {
                do_write = 1;
                b->last += n;

                continue;
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

    if ((upstream->read->eof && u->buffer.pos == u->buffer.last)
        || (downstream->read->eof && u->from_client.pos == u->from_client.last)
        || (downstream->read->eof && upstream->read->eof))
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http upstream upgraded done");
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (ngx_handle_write_event(upstream->write, u->conf->send_lowat)
        != NGX_OK)
    {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

    if (upstream->write->active && !upstream->write->ready) {
        ngx_add_timer(upstream->write, u->conf->send_timeout);

    } else if (upstream->write->timer_set) {
        ngx_del_timer(upstream->write);
    }

    if (ngx_handle_read_event(upstream->read, 0) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

    if (upstream->read->active && !upstream->read->ready) {
        ngx_add_timer(upstream->read, u->conf->read_timeout);

    } else if (upstream->read->timer_set) {
        ngx_del_timer(upstream->read);
    }

    if (ngx_handle_write_event(downstream->write, clcf->send_lowat)
        != NGX_OK)
    {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

    if (ngx_handle_read_event(downstream->read, 0) != NGX_OK) {
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }

    if (downstream->write->active && !downstream->write->ready) {
        ngx_add_timer(downstream->write, clcf->send_timeout);

    } else if (downstream->write->timer_set) {
        ngx_del_timer(downstream->write);
    }
}

/* 向下游客户端发送响应时调用该方法 */
static void ngx_http_upstream_process_non_buffered_downstream(ngx_http_request_t *r)
{
    ngx_event_t          *wev;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    c = r->connection;//获得nginx与客户端之间的TCP连接
    u = r->upstream;
    wev = c->write;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process non buffered downstream");

    c->log->action = "sending to client";

	/* 发送超时，结束请求 */
    if (wev->timedout) 
	{
        c->timedout = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
        ngx_http_upstream_finalize_request(r, u, NGX_HTTP_REQUEST_TIME_OUT);//传递的参数是NGX_HTTP_REQUEST_TIME_OUT
        return;
    }

	/* 调用该方法向客户端发送响应包体，传递的第二个参数是1 */
    ngx_http_upstream_process_non_buffered_request(r, 1);
}

/* 当接收到上游服务器的响应时，调用该方法处理这个读事件 */
static void ngx_http_upstream_process_non_buffered_upstream(ngx_http_request_t *r,ngx_http_upstream_t *u)
{
    ngx_connection_t  *c;
    c = u->peer.connection;//获取nginx与上游服务器间的TCP连接
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,"http upstream process non buffered upstream");
    c->log->action = "reading upstream";
	/* 如果读取响应超时，则需要结束请求 */
    if (c->read->timedout) 
	{
        ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }
	/* 这个方法才是真正决定以固定内存块作为缓存时如何转发响应的，注意，第二个参数为0 */
    ngx_http_upstream_process_non_buffered_request(r, 0);
}

/* 无论是接收上游服务器的响应还是向下客户端发送响应，最终都是调用该方法，唯一的区别就是第二个参数不同:当需要
读取上游的响应时传递的是0.当需要向下游发送响应时传递的是1 */
static void ngx_http_upstream_process_non_buffered_request(ngx_http_request_t *r,ngx_uint_t do_write)
{
    size_t                     size;
    ssize_t                    n;
    ngx_buf_t                 *b;
    ngx_int_t                  rc;
    ngx_connection_t          *downstream, *upstream;
    ngx_http_upstream_t       *u;
    ngx_http_core_loc_conf_t  *clcf;
    u = r->upstream;
    downstream = r->connection;
    upstream = u->peer.connection;
    b = &u->buffer;
	/* 这里的length表示还需要接收的上游包体的长度，当length为0时，说明不再需要接收上游的响应，那只能继续向
	下游发送响应，因此，do_write只能为1，do_write表示本次是否向下游发送响应*/
    do_write = do_write || u->length == 0;
	/* 这是在一个大循环中执行的，也就是说，与上下游间的通信可能反复执行 */
    for ( ;; ) 
	{
        if (do_write)//向下游发送响应
		{
			/* 检查缓冲区中来自上游的响应包体是否还有未转发给下游的。这个过程很简单，因为每当在缓冲区中接收到上游的响应时，都会调用input_filter方法来处理，当
			HTTP模块没有实现该方法时，调用默认方法来处理响应，该方法会在out_bufs链表中增加ngx_buf_t缓冲区，从而将已经发送出去的ngx_buf_t成员回收到free_bufs
			链表中。那为什么处理out_bufs缓冲区还要检查busy_bufs呢？这时因为下面在向下游发送out_bufs指向的响应时，未必可以一次性发完。这时，会使用busy_bufs
			缓冲区(没有实际分配内存)指向buffer中接收到的响应。因此，在向下游发送包体时，直接发送out_bufs缓冲区指向的内容即可，每当发送成功时，则会在下面更新
			busy_bufs指向out_bufs中的内容，同时将out_bufs置为空，使得它在继续处理接收到的响应包体的ngx_http_upstream_non_buffered_filter方法中指向
			新收到的响应，因此，只有两个链表都为空时，才表示没有响应需要转发到下游*/
            if (u->out_bufs || u->busy_bufs) 
			{
				/* 向下游发送out_bufs指向的内容,读者在这里可能会有疑问，在busy_bufs不为空时，不是也有内容要发送吗？注意，busy_bufs指向的是上一次
				ngx_http_output_filter未发送完的缓存，这时请求ngx_http_request_t结构体的out缓冲区已经保存了它的内容，不需要再次发送busy_bufs了*/
                rc = ngx_http_output_filter(r, u->out_bufs);
                if (rc == NGX_ERROR)
                {
                    ngx_http_upstream_finalize_request(r, u, 0);
                    return;
                }
				/* 更新上面说过的free_bufs、busy_bufs、out_bufs这3个缓冲区链表，实际上做了3件事：1)清空out_bufs链表2)把out_bufs中已经发送完的
				ngx_buf_t结构体清空重置(即把pos和last成员指向start)，同时把他们追加到free_bufs链表中3):如果out_bufs中还有未发送完的ngx_buf_t结构体，
				那么添加到busy_bufs链表中，这一步与ngx_http_upstream_non_buffered_filter方法的执行时对应的*/
                ngx_chain_update_chains(r->pool, &u->free_bufs, &u->busy_bufs,&u->out_bufs, u->output.tag);
            }
			/* 当busy_bufs链表为空时，表示到目前为止需要向下游转发的响应包体都已经全部发送完了(也就是说，ngx_http_request_t结构体中的out缓冲区都发送完了)，
			这时将把buffer接收缓冲区清空，这样，buffer接收缓冲区中的内容释放后，才能继续接收更多的响应包体*/
            if (u->busy_bufs == NULL) 
			{
                if (u->length == 0 || upstream->read->eof || upstream->read->error)
                {
                    ngx_http_upstream_finalize_request(r, u, 0);
                    return;
                }
                b->pos = b->start;
                b->last = b->start;
            }
        }
		/* do_write为0，表示需要由上游读取响应 */

        size = b->end - b->last;//获取buffer缓冲区中还有多少剩余空间
		/* 当size大于0且与上游的连接上确实有可读事件 */
        if (size && upstream->read->ready) 
		{
            n = upstream->recv(upstream, b->last, size);//将上游的响应接收到buffer缓冲区中
            if (n == NGX_AGAIN) 
			{//期待epoll下次有读事件时再继续调度
                break;
            }
            if (n > 0) 
			{
                u->state->response_length += n;
				/* 处理包体 */
                if (u->input_filter(u->input_filter_ctx, n) == NGX_ERROR)
                {
                    ngx_http_upstream_finalize_request(r, u, 0);
                    return;
                }
            }
			/* 读取到来自上游的响应，这时设置do_write为1，准备向下游转发刚收到的响应 */
            do_write = 1;
            continue;
        }
        break;
    }
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    if (downstream->data == r) 
	{
		/* 将nginx与下游之间连接上的写事件添加到epoll中 */
        if (ngx_handle_write_event(downstream->write, clcf->send_lowat)!= NGX_OK)
        {
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
    }
    if (downstream->write->active && !downstream->write->ready)
	{
        ngx_add_timer(downstream->write, clcf->send_timeout);//将nginx与下游之间连接上的写事件添加到定时器中

    }
    else if (downstream->write->timer_set)
    {
        ngx_del_timer(downstream->write);
    }
	/* 将nginx与上游服务器之间的连接上的读事件添加到epoll中 */
    if (ngx_handle_read_event(upstream->read, 0) != NGX_OK)
	{
        ngx_http_upstream_finalize_request(r, u, 0);
        return;
    }
	/* 将nginx与上游服务器之间连接上的读事件添加到定时器中 */
    if (upstream->read->active && !upstream->read->ready) 
	{
        ngx_add_timer(upstream->read, u->conf->read_timeout);

    }
    else if (upstream->read->timer_set)
    {
        ngx_del_timer(upstream->read);
    }
}


static ngx_int_t
ngx_http_upstream_non_buffered_filter_init(void *data)
{
    return NGX_OK;
}

//默认的input_filter方法，这个默认的方法会试图在buffer缓冲区中存放全部的响应包体
static ngx_int_t ngx_http_upstream_non_buffered_filter(void *data, ssize_t bytes)
{
	/* data参数就是ngx_http_upstream_t结构体中的input_filter_ctx，当HTTP模块未实现input_filter方法时，
	input_filter_ctx成员会指向请求的ngx_http_request_t结构体*/
    ngx_http_request_t  *r = data;

    ngx_buf_t            *b;
    ngx_chain_t          *cl, **ll;
    ngx_http_upstream_t  *u;

    u = r->upstream;

	/* 找到out_bufs链表的末尾，其中cl指向链表中最后一个ngx_chain_t元素的next成员，所以cl最后一定是NULL,而
	ll指向最后一个缓冲区的地址，它用来在后面的代码中向out_bufs链表添加新的缓冲区*/
    for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) 
	{
        ll = &cl->next;
    }

	/* free_bufs指向空闲的ngx_buf_t结构体构成的链表，如果为空，那么将会重新由r->pool内存池中分配一个
	ngx_buf_t结构体给cl；如果不为空，则直接由free_bufs中获取一个ngx_buf_t结构体给cl*/
    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    *ll = cl;//将新分配的ngx_buf_t结构体添加到out_bufs链表的末尾

	/* 修改新分配缓冲区的标志位，表明在内存中，flush标志位为可能发送缓冲区到客户端服务 */
    cl->buf->flush = 1;
    cl->buf->memory = 1;

    b = &u->buffer;//buffer缓冲区才是真正接收上游服务器响应包体的缓冲区

    cl->buf->pos = b->last;//last实际指向本次接收到的包体首地址
    b->last += bytes;//last向后移动bytes字节，意味着buffer需要保存这次收到的包体
    cl->buf->last = b->last;//last和post成员确定了out_bufs链表中每个缓冲区的包体数据
    cl->buf->tag = u->output.tag;

    if (u->length == -1) {
        return NGX_OK;
    }

    u->length -= bytes;//更新length，需要接收到的包体长度减少bytes字节

    return NGX_OK;
}


static void
ngx_http_upstream_process_downstream(ngx_http_request_t *r)
{
    ngx_event_t          *wev;
    ngx_connection_t     *c;
    ngx_event_pipe_t     *p;
    ngx_http_upstream_t  *u;

    c = r->connection;
    u = r->upstream;
    p = u->pipe;
    wev = c->write;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process downstream");

    c->log->action = "sending to client";

    if (wev->timedout) {

        if (wev->delayed) {

            wev->timedout = 0;
            wev->delayed = 0;

            if (!wev->ready) {
                ngx_add_timer(wev, p->send_timeout);

                if (ngx_handle_write_event(wev, p->send_lowat) != NGX_OK) {
                    ngx_http_upstream_finalize_request(r, u, 0);
                }

                return;
            }

            if (ngx_event_pipe(p, wev->write) == NGX_ABORT) {
                ngx_http_upstream_finalize_request(r, u, 0);
                return;
            }

        } else {
            p->downstream_error = 1;
            c->timedout = 1;
            ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
        }

    } else {

        if (wev->delayed) {

            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http downstream delayed");

            if (ngx_handle_write_event(wev, p->send_lowat) != NGX_OK) {
                ngx_http_upstream_finalize_request(r, u, 0);
            }

            return;
        }

        if (ngx_event_pipe(p, 1) == NGX_ABORT) {
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
    }

    ngx_http_upstream_process_request(r);
}

//读取后端服务器发送的数据
static void ngx_http_upstream_process_upstream(ngx_http_request_t *r,ngx_http_upstream_t *u)
{
    ngx_connection_t  *c;

    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http upstream process upstream");

    c->log->action = "reading upstream";

    if (c->read->timedout) {
        u->pipe->upstream_error = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "upstream timed out");

    } else {
        if (ngx_event_pipe(u->pipe, 0) == NGX_ABORT) {
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
    }

    ngx_http_upstream_process_request(r);
}


static void
ngx_http_upstream_process_request(ngx_http_request_t *r)
{
    ngx_temp_file_t      *tf;
    ngx_event_pipe_t     *p;
    ngx_http_upstream_t  *u;

    u = r->upstream;
    p = u->pipe;

    if (u->peer.connection) {

        if (u->store) {

            if (p->upstream_eof || p->upstream_done) {

                tf = u->pipe->temp_file;

                if (u->headers_in.status_n == NGX_HTTP_OK
                    && (u->headers_in.content_length_n == -1
                        || (u->headers_in.content_length_n == tf->offset)))
                {
                    ngx_http_upstream_store(r, u);
                    u->store = 0;
                }
            }
        }

#if (NGX_HTTP_CACHE)

        if (u->cacheable) {

            if (p->upstream_done) {
                ngx_http_file_cache_update(r, u->pipe->temp_file);

            } else if (p->upstream_eof) {

                tf = u->pipe->temp_file;

                if (u->headers_in.content_length_n == -1
                    || u->headers_in.content_length_n
                       == tf->offset - (off_t) r->cache->body_start)
                {
                    ngx_http_file_cache_update(r, tf);

                } else {
                    ngx_http_file_cache_free(r->cache, tf);
                }

            } else if (p->upstream_error) {
                ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
            }
        }

#endif

        if (p->upstream_done || p->upstream_eof || p->upstream_error) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "http upstream exit: %p", p->out);
#if 0
            ngx_http_busy_unlock(u->conf->busy_lock, &u->busy_lock);
#endif
            ngx_http_upstream_finalize_request(r, u, 0);
            return;
        }
    }

    if (p->downstream_error) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream downstream error");

        if (!u->cacheable && !u->store && u->peer.connection) {
            ngx_http_upstream_finalize_request(r, u, 0);
        }
    }
}


static void
ngx_http_upstream_store(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    size_t                  root;
    time_t                  lm;
    ngx_str_t               path;
    ngx_temp_file_t        *tf;
    ngx_ext_rename_file_t   ext;

    tf = u->pipe->temp_file;

    if (tf->file.fd == NGX_INVALID_FILE) {

        /* create file for empty 200 response */

        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return;
        }

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = u->conf->temp_path;
        tf->pool = r->pool;
        tf->persistent = 1;

        if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                 tf->persistent, tf->clean, tf->access)
            != NGX_OK)
        {
            return;
        }

        u->pipe->temp_file = tf;
    }

    ext.access = u->conf->store_access;
    ext.path_access = u->conf->store_access;
    ext.time = -1;
    ext.create_path = 1;
    ext.delete_file = 1;
    ext.log = r->connection->log;

    if (u->headers_in.last_modified) {

        lm = ngx_http_parse_time(u->headers_in.last_modified->value.data,
                                 u->headers_in.last_modified->value.len);

        if (lm != NGX_ERROR) {
            ext.time = lm;
            ext.fd = tf->file.fd;
        }
    }

    if (u->conf->store_lengths == NULL) {

        ngx_http_map_uri_to_path(r, &path, &root, 0);

    } else {
        if (ngx_http_script_run(r, &path, u->conf->store_lengths->elts, 0,
                                u->conf->store_values->elts)
            == NULL)
        {
            return;
        }
    }

    path.len--;

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "upstream stores \"%s\" to \"%s\"",
                   tf->file.name.data, path.data);

    (void) ngx_ext_rename_file(&tf->file.name, &path, &ext);
}


static void
ngx_http_upstream_dummy_handler(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http upstream dummy handler");
}

/* 当处理请求出现错误时，调用该方法，这是因为：当与上游的交互出现错误时，nginx并不想立刻认为这个请求处理失败，
而是给上游服务器多一些机会，可以重新向这台或者另一台上游服务器发起连接、发送请求、接收响应，以避免网络故障，
这个功能可以帮助HTTP模块实现简单的负载均衡机制 */
static void ngx_http_upstream_next(ngx_http_request_t *r, ngx_http_upstream_t *u,
    ngx_uint_t ft_type)
{
    ngx_uint_t  status, state;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http next upstream, %xi", ft_type);

#if 0
    ngx_http_busy_unlock(u->conf->busy_lock, &u->busy_lock);
#endif

    if (u->peer.sockaddr) {

        if (ft_type == NGX_HTTP_UPSTREAM_FT_HTTP_404) {
            state = NGX_PEER_NEXT;
        } else {
            state = NGX_PEER_FAILED;
        }

        u->peer.free(&u->peer, u->peer.data, state);
        u->peer.sockaddr = NULL;
    }

    if (ft_type == NGX_HTTP_UPSTREAM_FT_TIMEOUT) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, NGX_ETIMEDOUT,
                      "upstream timed out");
    }

    if (u->peer.cached && ft_type == NGX_HTTP_UPSTREAM_FT_ERROR) {
        status = 0;

        /* TODO: inform balancer instead */

        u->peer.tries++;

    } else {
        switch(ft_type) {

        case NGX_HTTP_UPSTREAM_FT_TIMEOUT:
            status = NGX_HTTP_GATEWAY_TIME_OUT;
            break;

        case NGX_HTTP_UPSTREAM_FT_HTTP_500:
            status = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;

        case NGX_HTTP_UPSTREAM_FT_HTTP_404:
            status = NGX_HTTP_NOT_FOUND;
            break;

        /*
         * NGX_HTTP_UPSTREAM_FT_BUSY_LOCK and NGX_HTTP_UPSTREAM_FT_MAX_WAITING
         * never reach here
         */

        default:
            status = NGX_HTTP_BAD_GATEWAY;
        }
    }

    if (r->connection->error) {
        ngx_http_upstream_finalize_request(r, u,
                                           NGX_HTTP_CLIENT_CLOSED_REQUEST);
        return;
    }

    if (status) 
	{
        u->state->status = status;

		/* 只有向这台上游服务器的重试次数tries减为0时，才会真正调用ngx_http_upstream_finalize_request方法结束请求，否则
		会再次试图重新与上游服务器交互，这个功能将帮助感兴趣的HTTP模块实现简单的负载均衡机制。u->conf->next->upstream是
		一个错误码组合，表示当出现这些错误码时不能直接结束请求，需要向下一台上游服务器再次重发*/
        if (u->peer.tries == 0 || !(u->conf->next_upstream & ft_type)) {

#if (NGX_HTTP_CACHE)

            if (u->cache_status == NGX_HTTP_CACHE_EXPIRED
                && (u->conf->cache_use_stale & ft_type))
            {
                ngx_int_t  rc;

                rc = u->reinit_request(r);

                if (rc == NGX_OK) {
                    u->cache_status = NGX_HTTP_CACHE_STALE;
                    rc = ngx_http_upstream_cache_send(r, u);
                }

                ngx_http_upstream_finalize_request(r, u, rc);
                return;
            }
#endif

            ngx_http_upstream_finalize_request(r, u, status);
            return;
        }
    }

	/* 如果与上游间的TVP连接还存在，那么需要关闭 */
    if (u->peer.connection) 
	{
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);
#if (NGX_HTTP_SSL)

        if (u->peer.connection->ssl) {
            u->peer.connection->ssl->no_wait_shutdown = 1;
            u->peer.connection->ssl->no_send_shutdown = 1;

            (void) ngx_ssl_shutdown(u->peer.connection);
        }
#endif

        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
        }

        ngx_close_connection(u->peer.connection);
        u->peer.connection = NULL;
    }

#if 0
    if (u->conf->busy_lock && !u->busy_locked) {
        ngx_http_upstream_busy_lock(p);
        return;
    }
#endif

    ngx_http_upstream_connect(r, u);
}

/* 在启动upstream机制时，该方法会挂载到请求的cleanup链表中，这样，HTTP框架在请求结束时就会调用该方法(参见11.10.2节ngx_http_free_request方法的流程)，
这保证了该方法一定会被调用，而该方法会调用ngx_http_upstream_finalize_request来结束请求 */
static void ngx_http_upstream_cleanup(void *data)
{
    ngx_http_request_t *r = data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "cleanup http upstream request: \"%V\"", &r->uri);

    ngx_http_upstream_finalize_request(r, r->upstream, NGX_DONE);
}

/* 最终调用HTTP框架提供的ngx_http_finalize_request方法释放请求，但在这之前需要释放与上游交互时分配的资源，如文件句柄、TCP连接等 */
static void ngx_http_upstream_finalize_request(ngx_http_request_t *r,
    ngx_http_upstream_t *u, ngx_int_t rc)
{
    ngx_time_t  *tp;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http upstream request: %i", rc);

	/* 将cleanup指向的清理资源回调方法置为NULL */
    if (u->cleanup) 
	{
        *u->cleanup = NULL;
        u->cleanup = NULL;
    }

	/* 释放解析主机域名时分配的资源 */
    if (u->resolved && u->resolved->ctx) 
	{
        ngx_resolve_name_done(u->resolved->ctx);
        u->resolved->ctx = NULL;
    }

	/* 设置当前时间为HTTP响应结束时间 */
    if (u->state && u->state->response_sec)
	{
        tp = ngx_timeofday();
        u->state->response_sec = tp->sec - u->state->response_sec;
        u->state->response_msec = tp->msec - u->state->response_msec;

        if (u->pipe && u->pipe->read_length) {
            u->state->response_length = u->pipe->read_length;
        }
    }

	/* 调用HTTP模块负责实现的finalize_request方法，HTTP模块可能会在upstream请求结束时执行一些操作 */
    u->finalize_request(r, rc);

	/* 如果使用了TCP连接池实现了free方法，那么调用free方法释放连接资源 */
    if (u->peer.free && u->peer.sockaddr) 
	{
        u->peer.free(&u->peer, u->peer.data, 0);
        u->peer.sockaddr = NULL;
    }

	/* 如果与上游间的TCP连接还在，则关闭这个TCP连接 */
    if (u->peer.connection) 
	{

#if (NGX_HTTP_SSL)

        /* TODO: do not shutdown persistent connection */

        if (u->peer.connection->ssl) {

            /*
             * We send the "close notify" shutdown alert to the upstream only
             * and do not wait its "close notify" shutdown alert.
             * It is acceptable according to the TLS standard.
             */

            u->peer.connection->ssl->no_wait_shutdown = 1;

            (void) ngx_ssl_shutdown(u->peer.connection);
        }
#endif

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "close http upstream connection: %d",
                       u->peer.connection->fd);

        if (u->peer.connection->pool) {
            ngx_destroy_pool(u->peer.connection->pool);
        }

        ngx_close_connection(u->peer.connection);
    }

    u->peer.connection = NULL;

    if (u->pipe && u->pipe->temp_file) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http upstream temp fd: %d",
                       u->pipe->temp_file->file.fd);
    }

    if (u->store && u->pipe && u->pipe->temp_file&& u->pipe->temp_file->file.fd != NGX_INVALID_FILE)
    {
		/* 如果使用了磁盘文件作为缓存来向下游转发响应，则需要删除用于缓存响应的临时文件 */
        if (ngx_delete_file(u->pipe->temp_file->file.name.data)== NGX_FILE_ERROR)
        {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, ngx_errno,
                          ngx_delete_file_n " \"%s\" failed",
                          u->pipe->temp_file->file.name.data);
        }
    }

#if (NGX_HTTP_CACHE)

    if (r->cache) {

        if (u->cacheable) {

            if (rc == NGX_HTTP_BAD_GATEWAY || rc == NGX_HTTP_GATEWAY_TIME_OUT) {
                time_t  valid;

                valid = ngx_http_file_cache_valid(u->conf->cache_valid, rc);

                if (valid) {
                    r->cache->valid_sec = ngx_time() + valid;
                    r->cache->error = rc;
                }
            }
        }

        ngx_http_file_cache_free(r->cache, u->pipe->temp_file);
    }

#endif

    if (u->header_sent&& rc != NGX_HTTP_REQUEST_TIME_OUT&& (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE))
    {
        rc = 0;
    }

    if (rc == NGX_DECLINED) {
        return;
    }

    r->connection->log->action = "sending to client";

    if (rc == 0
        && !r->header_only
#if (NGX_HTTP_CACHE)
        && !r->cached
#endif
       )
    {
		/* 如果已经向下游客户端发送了HTTP响应头部，却出现了错误，那么调用该方法将头部发送完毕 */
        rc = ngx_http_send_special(r, NGX_HTTP_LAST);
    }

	/* 最后还是通过调用HTTP框架提供的结束方法来结束请求 */
    ngx_http_finalize_request(r, rc);
}


static ngx_int_t
ngx_http_upstream_process_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  **ph;

    ph = (ngx_table_elt_t **) ((char *) &r->upstream->headers_in + offset);

    if (*ph == NULL) {
        *ph = h;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_ignore_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_content_length(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_http_upstream_t  *u;

    u = r->upstream;

    u->headers_in.content_length = h;
    u->headers_in.content_length_n = ngx_atoof(h->value.data, h->value.len);

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_set_cookie(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
#if (NGX_HTTP_CACHE)
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (!(u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_SET_COOKIE)) {
        u->cacheable = 0;
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_cache_control(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_array_t          *pa;
    ngx_table_elt_t     **ph;
    ngx_http_upstream_t  *u;

    u = r->upstream;
    pa = &u->headers_in.cache_control;

    if (pa->elts == NULL) {
       if (ngx_array_init(pa, r->pool, 2, sizeof(ngx_table_elt_t *)) != NGX_OK)
       {
           return NGX_ERROR;
       }
    }

    ph = ngx_array_push(pa);
    if (ph == NULL) {
        return NGX_ERROR;
    }

    *ph = h;

#if (NGX_HTTP_CACHE)
    {
    u_char     *p, *last;
    ngx_int_t   n;

    if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL) {
        return NGX_OK;
    }

    if (r->cache == NULL) {
        return NGX_OK;
    }

    if (r->cache->valid_sec != 0) {
        return NGX_OK;
    }

    p = h->value.data;
    last = p + h->value.len;

    if (ngx_strlcasestrn(p, last, (u_char *) "no-cache", 8 - 1) != NULL
        || ngx_strlcasestrn(p, last, (u_char *) "no-store", 8 - 1) != NULL
        || ngx_strlcasestrn(p, last, (u_char *) "private", 7 - 1) != NULL)
    {
        u->cacheable = 0;
        return NGX_OK;
    }

    p = ngx_strlcasestrn(p, last, (u_char *) "max-age=", 8 - 1);

    if (p == NULL) {
        return NGX_OK;
    }

    n = 0;

    for (p += 8; p < last; p++) {
        if (*p == ',' || *p == ';' || *p == ' ') {
            break;
        }

        if (*p >= '0' && *p <= '9') {
            n = n * 10 + *p - '0';
            continue;
        }

        u->cacheable = 0;
        return NGX_OK;
    }

    if (n == 0) {
        u->cacheable = 0;
        return NGX_OK;
    }

    r->cache->valid_sec = ngx_time() + n;
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_expires(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_http_upstream_t  *u;

    u = r->upstream;
    u->headers_in.expires = h;

#if (NGX_HTTP_CACHE)
    {
    time_t  expires;

    if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_EXPIRES) {
        return NGX_OK;
    }

    if (r->cache == NULL) {
        return NGX_OK;
    }

    if (r->cache->valid_sec != 0) {
        return NGX_OK;
    }

    expires = ngx_http_parse_time(h->value.data, h->value.len);

    if (expires == NGX_ERROR || expires < ngx_time()) {
        u->cacheable = 0;
        return NGX_OK;
    }

    r->cache->valid_sec = expires;
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_accel_expires(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_http_upstream_t  *u;

    u = r->upstream;
    u->headers_in.x_accel_expires = h;

#if (NGX_HTTP_CACHE)
    {
    u_char     *p;
    size_t      len;
    ngx_int_t   n;

    if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES) {
        return NGX_OK;
    }

    if (r->cache == NULL) {
        return NGX_OK;
    }

    len = h->value.len;
    p = h->value.data;

    if (p[0] != '@') {
        n = ngx_atoi(p, len);

        switch (n) {
        case 0:
            u->cacheable = 0;
            /* fall through */

        case NGX_ERROR:
            return NGX_OK;

        default:
            r->cache->valid_sec = ngx_time() + n;
            return NGX_OK;
        }
    }

    p++;
    len--;

    n = ngx_atoi(p, len);

    if (n != NGX_ERROR) {
        r->cache->valid_sec = n;
    }
    }
#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_limit_rate(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_int_t             n;
    ngx_http_upstream_t  *u;

    u = r->upstream;
    u->headers_in.x_accel_limit_rate = h;

    if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE) {
        return NGX_OK;
    }

    n = ngx_atoi(h->value.data, h->value.len);

    if (n != NGX_ERROR) {
        r->limit_rate = (size_t) n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_buffering(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    u_char                c0, c1, c2;
    ngx_http_upstream_t  *u;

    u = r->upstream;

    if (u->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING) {
        return NGX_OK;
    }

    if (u->conf->change_buffering) {

        if (h->value.len == 2) {
            c0 = ngx_tolower(h->value.data[0]);
            c1 = ngx_tolower(h->value.data[1]);

            if (c0 == 'n' && c1 == 'o') {
                u->buffering = 0;
            }

        } else if (h->value.len == 3) {
            c0 = ngx_tolower(h->value.data[0]);
            c1 = ngx_tolower(h->value.data[1]);
            c2 = ngx_tolower(h->value.data[2]);

            if (c0 == 'y' && c1 == 'e' && c2 == 's') {
                u->buffering = 1;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_charset(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    if (r->upstream->conf->ignore_headers & NGX_HTTP_UPSTREAM_IGN_XA_CHARSET) {
        return NGX_OK;
    }

    r->headers_out.override_charset = &h->value;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_connection(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    r->upstream->headers_in.connection = h;

    if (ngx_strlcasestrn(h->value.data, h->value.data + h->value.len,
                         (u_char *) "close", 5 - 1)
        != NULL)
    {
        r->upstream->headers_in.connection_close = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_process_transfer_encoding(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    r->upstream->headers_in.transfer_encoding = h;

    if (ngx_strlcasestrn(h->value.data, h->value.data + h->value.len,
                         (u_char *) "chunked", 7 - 1)
        != NULL)
    {
        r->upstream->headers_in.chunked = 1;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_copy_header_line(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  *ho, **ph;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    if (offset) {
        ph = (ngx_table_elt_t **) ((char *) &r->headers_out + offset);
        *ph = ho;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_copy_multi_header_lines(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_array_t      *pa;
    ngx_table_elt_t  *ho, **ph;

    pa = (ngx_array_t *) ((char *) &r->headers_out + offset);

    if (pa->elts == NULL) {
        if (ngx_array_init(pa, r->pool, 2, sizeof(ngx_table_elt_t *)) != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ph = ngx_array_push(pa);
    if (ph == NULL) {
        return NGX_ERROR;
    }

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;
    *ph = ho;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_copy_content_type(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    u_char  *p, *last;

    r->headers_out.content_type_len = h->value.len;
    r->headers_out.content_type = h->value;
    r->headers_out.content_type_lowcase = NULL;

    for (p = h->value.data; *p; p++) {

        if (*p != ';') {
            continue;
        }

        last = p;

        while (*++p == ' ') { /* void */ }

        if (*p == '\0') {
            return NGX_OK;
        }

        if (ngx_strncasecmp(p, (u_char *) "charset=", 8) != 0) {
            continue;
        }

        p += 8;

        r->headers_out.content_type_len = last - h->value.data;

        if (*p == '"') {
            p++;
        }

        last = h->value.data + h->value.len;

        if (*(last - 1) == '"') {
            last--;
        }

        r->headers_out.charset.len = last - p;
        r->headers_out.charset.data = p;

        return NGX_OK;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_copy_last_modified(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    r->headers_out.last_modified = ho;

#if (NGX_HTTP_CACHE)

    if (r->upstream->cacheable) {
        r->headers_out.last_modified_time = ngx_http_parse_time(h->value.data,
                                                                h->value.len);
    }

#endif

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_rewrite_location(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_int_t         rc;
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    if (r->upstream->rewrite_redirect) {
        rc = r->upstream->rewrite_redirect(r, ho, 0);

        if (rc == NGX_DECLINED) {
            return NGX_OK;
        }

        if (rc == NGX_OK) {
            r->headers_out.location = ho;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten location: \"%V\"", &ho->value);
        }

        return rc;
    }

    if (ho->value.data[0] != '/') {
        r->headers_out.location = ho;
    }

    /*
     * we do not set r->headers_out.location here to avoid the handling
     * the local redirects without a host name by ngx_http_header_filter()
     */

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_rewrite_refresh(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    u_char           *p;
    ngx_int_t         rc;
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    if (r->upstream->rewrite_redirect) {

        p = ngx_strcasestrn(ho->value.data, "url=", 4 - 1);

        if (p) {
            rc = r->upstream->rewrite_redirect(r, ho, p + 4 - ho->value.data);

        } else {
            return NGX_OK;
        }

        if (rc == NGX_DECLINED) {
            return NGX_OK;
        }

        if (rc == NGX_OK) {
            r->headers_out.refresh = ho;

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten refresh: \"%V\"", &ho->value);
        }

        return rc;
    }

    r->headers_out.refresh = ho;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_rewrite_set_cookie(ngx_http_request_t *r, ngx_table_elt_t *h,
    ngx_uint_t offset)
{
    ngx_int_t         rc;
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    if (r->upstream->rewrite_cookie) {
        rc = r->upstream->rewrite_cookie(r, ho);

        if (rc == NGX_DECLINED) {
            return NGX_OK;
        }

#if (NGX_DEBUG)
        if (rc == NGX_OK) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "rewritten cookie: \"%V\"", &ho->value);
        }
#endif

        return rc;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_copy_allow_ranges(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_table_elt_t  *ho;

#if (NGX_HTTP_CACHE)

    if (r->cached) {
        r->allow_ranges = 1;
        return NGX_OK;

    }

#endif

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    r->headers_out.accept_ranges = ho;

    return NGX_OK;
}


#if (NGX_HTTP_GZIP)

static ngx_int_t
ngx_http_upstream_copy_content_encoding(ngx_http_request_t *r,
    ngx_table_elt_t *h, ngx_uint_t offset)
{
    ngx_table_elt_t  *ho;

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    *ho = *h;

    r->headers_out.content_encoding = ho;

    return NGX_OK;
}

#endif


static ngx_int_t
ngx_http_upstream_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_upstream_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_addr_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    ngx_uint_t                  i;
    ngx_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = 0;
    state = r->upstream_states->elts;

    for (i = 0; i < r->upstream_states->nelts; i++) {
        if (state[i].peer) {
            len += state[i].peer->len + 2;

        } else {
            len += 3;
        }
    }

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;

    for ( ;; ) {
        if (state[i].peer) {
            p = ngx_cpymem(p, state[i].peer->data, state[i].peer->len);
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_status_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    ngx_uint_t                  i;
    ngx_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = r->upstream_states->nelts * (3 + 2);

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {
        if (state[i].status) {
            p = ngx_sprintf(p, "%ui", state[i].status);

        } else {
            *p++ = '-';
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_response_time_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    ngx_uint_t                  i;
    ngx_msec_int_t              ms;
    ngx_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = r->upstream_states->nelts * (NGX_TIME_T_LEN + 4 + 2);

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {
        if (state[i].status) {
            ms = (ngx_msec_int_t)
                     (state[i].response_sec * 1000 + state[i].response_msec);
            ms = ngx_max(ms, 0);
            p = ngx_sprintf(p, "%d.%03d", ms / 1000, ms % 1000);

        } else {
            *p++ = '-';
        }

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_response_length_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    u_char                     *p;
    size_t                      len;
    ngx_uint_t                  i;
    ngx_http_upstream_state_t  *state;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    if (r->upstream_states == NULL || r->upstream_states->nelts == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = r->upstream_states->nelts * (NGX_OFF_T_LEN + 2);

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->data = p;

    i = 0;
    state = r->upstream_states->elts;

    for ( ;; ) {
        p = ngx_sprintf(p, "%O", state[i].response_length);

        if (++i == r->upstream_states->nelts) {
            break;
        }

        if (state[i].peer) {
            *p++ = ',';
            *p++ = ' ';

        } else {
            *p++ = ' ';
            *p++ = ':';
            *p++ = ' ';

            if (++i == r->upstream_states->nelts) {
                break;
            }

            continue;
        }
    }

    v->len = p - v->data;

    return NGX_OK;
}


ngx_int_t
ngx_http_upstream_header_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    if (r->upstream == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    return ngx_http_variable_unknown_header(v, (ngx_str_t *) data,
                                         &r->upstream->headers_in.headers.part,
                                         sizeof("upstream_http_") - 1);
}


#if (NGX_HTTP_CACHE)

ngx_int_t
ngx_http_upstream_cache_status(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_uint_t  n;

    if (r->upstream == NULL || r->upstream->cache_status == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    n = r->upstream->cache_status - 1;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ngx_http_cache_status[n].len;
    v->data = ngx_http_cache_status[n].data;

    return NGX_OK;
}

#endif

/* upstream配置项的回调处理函数 */
static char * ngx_http_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy)
{
    char                          *rv;
    void                          *mconf;
    ngx_str_t                     *value;
    ngx_url_t                      u;
    ngx_uint_t                     m;
    ngx_conf_t                     pcf;
    ngx_http_module_t             *module;
    ngx_http_conf_ctx_t           *ctx, *http_ctx;
    ngx_http_upstream_srv_conf_t  *uscf;

    ngx_memzero(&u, sizeof(ngx_url_t));

    value = cf->args->elts;
    u.host = value[1];
    u.no_resolve = 1;
    u.no_port = 1;

    uscf = ngx_http_upstream_add(cf, &u, NGX_HTTP_UPSTREAM_CREATE
                                         |NGX_HTTP_UPSTREAM_WEIGHT
                                         |NGX_HTTP_UPSTREAM_MAX_FAILS
                                         |NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
                                         |NGX_HTTP_UPSTREAM_DOWN
                                         |NGX_HTTP_UPSTREAM_BACKUP);
    if (uscf == NULL) {
        return NGX_CONF_ERROR;
    }


    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    http_ctx = cf->ctx;
    ctx->main_conf = http_ctx->main_conf;

    /* the upstream{}'s srv_conf */

    ctx->srv_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->srv_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    ctx->srv_conf[ngx_http_upstream_module.ctx_index] = uscf;

    uscf->srv_conf = ctx->srv_conf;


    /* the upstream{}'s loc_conf */

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[m]->ctx;

        if (module->create_srv_conf) {
            mconf = module->create_srv_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->srv_conf[ngx_modules[m]->ctx_index] = mconf;
        }

        if (module->create_loc_conf) {
            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                return NGX_CONF_ERROR;
            }

            ctx->loc_conf[ngx_modules[m]->ctx_index] = mconf;
        }
    }


    /* parse inside upstream{} */

    pcf = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_UPS_CONF;

    //进行配置项的解析
    rv = ngx_conf_parse(cf, NULL);

    *cf = pcf;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (uscf->servers == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "no servers are inside upstream");
        return NGX_CONF_ERROR;
    }

    return rv;
}

/* server配置项的处理函数 */
static char * ngx_http_upstream_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_srv_conf_t  *uscf = conf;

    time_t                       fail_timeout;
    ngx_str_t                   *value, s;
    ngx_url_t                    u;
    ngx_int_t                    weight, max_fails;
    ngx_uint_t                   i;
    ngx_http_upstream_server_t  *us;

    if (uscf->servers == NULL) {
        uscf->servers = ngx_array_create(cf->pool, 4,
                                         sizeof(ngx_http_upstream_server_t));
        if (uscf->servers == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    us = ngx_array_push(uscf->servers);
    if (us == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(us, sizeof(ngx_http_upstream_server_t));

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];
    u.default_port = 80;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in upstream \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    weight = 1;
    max_fails = 1;
    fail_timeout = 10;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "weight=", 7) == 0) {

            if (!(uscf->flags & NGX_HTTP_UPSTREAM_WEIGHT)) {
                goto invalid;
            }

            weight = ngx_atoi(&value[i].data[7], value[i].len - 7);

            if (weight == NGX_ERROR || weight == 0) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "max_fails=", 10) == 0) {

            if (!(uscf->flags & NGX_HTTP_UPSTREAM_MAX_FAILS)) {
                goto invalid;
            }

            max_fails = ngx_atoi(&value[i].data[10], value[i].len - 10);

            if (max_fails == NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "fail_timeout=", 13) == 0) {

            if (!(uscf->flags & NGX_HTTP_UPSTREAM_FAIL_TIMEOUT)) {
                goto invalid;
            }

            s.len = value[i].len - 13;
            s.data = &value[i].data[13];

            fail_timeout = ngx_parse_time(&s, 1);

            if (fail_timeout == (time_t) NGX_ERROR) {
                goto invalid;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "backup", 6) == 0) {

            if (!(uscf->flags & NGX_HTTP_UPSTREAM_BACKUP)) {
                goto invalid;
            }

            us->backup = 1;

            continue;
        }

        if (ngx_strncmp(value[i].data, "down", 4) == 0) {

            if (!(uscf->flags & NGX_HTTP_UPSTREAM_DOWN)) {
                goto invalid;
            }

            us->down = 1;

            continue;
        }

        goto invalid;
    }

    us->addrs = u.addrs;
    us->naddrs = u.naddrs;
    us->weight = weight;
    us->max_fails = max_fails;
    us->fail_timeout = fail_timeout;

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid parameter \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


ngx_http_upstream_srv_conf_t *
ngx_http_upstream_add(ngx_conf_t *cf, ngx_url_t *u, ngx_uint_t flags)
{
    ngx_uint_t                      i;
    ngx_http_upstream_server_t     *us;
    ngx_http_upstream_srv_conf_t   *uscf, **uscfp;
    ngx_http_upstream_main_conf_t  *umcf;

    if (!(flags & NGX_HTTP_UPSTREAM_CREATE)) {

        if (ngx_parse_url(cf->pool, u) != NGX_OK) {
            if (u->err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "%s in upstream \"%V\"", u->err, &u->url);
            }

            return NULL;
        }
    }

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        if (uscfp[i]->host.len != u->host.len
            || ngx_strncasecmp(uscfp[i]->host.data, u->host.data, u->host.len)
               != 0)
        {
            continue;
        }

        if ((flags & NGX_HTTP_UPSTREAM_CREATE)
             && (uscfp[i]->flags & NGX_HTTP_UPSTREAM_CREATE))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate upstream \"%V\"", &u->host);
            return NULL;
        }

        if ((uscfp[i]->flags & NGX_HTTP_UPSTREAM_CREATE) && !u->no_port) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "upstream \"%V\" may not have port %d",
                               &u->host, u->port);
            return NULL;
        }

        if ((flags & NGX_HTTP_UPSTREAM_CREATE) && !uscfp[i]->no_port) {
            ngx_log_error(NGX_LOG_WARN, cf->log, 0,
                          "upstream \"%V\" may not have port %d in %s:%ui",
                          &u->host, uscfp[i]->port,
                          uscfp[i]->file_name, uscfp[i]->line);
            return NULL;
        }

        if (uscfp[i]->port && u->port
            && uscfp[i]->port != u->port)
        {
            continue;
        }

        if (uscfp[i]->default_port && u->default_port
            && uscfp[i]->default_port != u->default_port)
        {
            continue;
        }

        if (flags & NGX_HTTP_UPSTREAM_CREATE) {
            uscfp[i]->flags = flags;
        }

        return uscfp[i];
    }

    uscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_srv_conf_t));
    if (uscf == NULL) {
        return NULL;
    }

    uscf->flags = flags;
    uscf->host = u->host;
    uscf->file_name = cf->conf_file->file.name.data;
    uscf->line = cf->conf_file->line;
    uscf->port = u->port;
    uscf->default_port = u->default_port;
    uscf->no_port = u->no_port;

    if (u->naddrs == 1) {
        uscf->servers = ngx_array_create(cf->pool, 1,
                                         sizeof(ngx_http_upstream_server_t));
        if (uscf->servers == NULL) {
            return NULL;
        }

        us = ngx_array_push(uscf->servers);
        if (us == NULL) {
            return NULL;
        }

        ngx_memzero(us, sizeof(ngx_http_upstream_server_t));

        us->addrs = u->addrs;
        us->naddrs = 1;
    }

    uscfp = ngx_array_push(&umcf->upstreams);
    if (uscfp == NULL) {
        return NULL;
    }

    *uscfp = uscf;

    return uscf;
}


char *
ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    ngx_int_t                           rc;
    ngx_str_t                          *value;
    ngx_http_complex_value_t            cv;
    ngx_http_upstream_local_t         **plocal, *local;
    ngx_http_compile_complex_value_t    ccv;

    plocal = (ngx_http_upstream_local_t **) (p + cmd->offset);

    if (*plocal != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "off") == 0) {
        *plocal = NULL;
        return NGX_CONF_OK;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    local = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_local_t));
    if (local == NULL) {
        return NGX_CONF_ERROR;
    }

    *plocal = local;

    if (cv.lengths) {
        local->value = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
        if (local->value == NULL) {
            return NGX_CONF_ERROR;
        }

        *local->value = cv;

        return NGX_CONF_OK;
    }

    local->addr = ngx_palloc(cf->pool, sizeof(ngx_addr_t));
    if (local->addr == NULL) {
        return NGX_CONF_ERROR;
    }

    rc = ngx_parse_addr(cf->pool, local->addr, value[1].data, value[1].len);

    switch (rc) {
    case NGX_OK:
        local->addr->name = value[1];
        return NGX_CONF_OK;

    case NGX_DECLINED:
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid address \"%V\"", &value[1]);
        /* fall through */

    default:
        return NGX_CONF_ERROR;
    }
}


static ngx_addr_t *
ngx_http_upstream_get_local(ngx_http_request_t *r,
    ngx_http_upstream_local_t *local)
{
    ngx_int_t    rc;
    ngx_str_t    val;
    ngx_addr_t  *addr;

    if (local == NULL) {
        return NULL;
    }

    if (local->value == NULL) {
        return local->addr;
    }

    if (ngx_http_complex_value(r, local->value, &val) != NGX_OK) {
        return NULL;
    }

    if (val.len == 0) {
        return NULL;
    }

    addr = ngx_palloc(r->pool, sizeof(ngx_addr_t));
    if (addr == NULL) {
        return NULL;
    }

    rc = ngx_parse_addr(r->pool, addr, val.data, val.len);

    switch (rc) {
    case NGX_OK:
        addr->name = val;
        return addr;

    case NGX_DECLINED:
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "invalid local address \"%V\"", &val);
        /* fall through */

    default:
        return NULL;
    }
}


char *
ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *p = conf;

    ngx_str_t                   *value;
    ngx_array_t                **a;
    ngx_http_upstream_param_t   *param;

    a = (ngx_array_t **) (p + cmd->offset);

    if (*a == NULL) {
        *a = ngx_array_create(cf->pool, 4, sizeof(ngx_http_upstream_param_t));
        if (*a == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    param = ngx_array_push(*a);
    if (param == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    param->key = value[1];
    param->value = value[2];
    param->skip_empty = 0;

    if (cf->args->nelts == 4) {
        if (ngx_strcmp(value[3].data, "if_not_empty") != 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[3]);
            return NGX_CONF_ERROR;
        }

        param->skip_empty = 1;
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash)
{
    ngx_str_t       *h;
    ngx_uint_t       i, j;
    ngx_array_t      hide_headers;
    ngx_hash_key_t  *hk;

    if (conf->hide_headers == NGX_CONF_UNSET_PTR
        && conf->pass_headers == NGX_CONF_UNSET_PTR)
    {
        conf->hide_headers = prev->hide_headers;
        conf->pass_headers = prev->pass_headers;

        conf->hide_headers_hash = prev->hide_headers_hash;

        if (conf->hide_headers_hash.buckets
#if (NGX_HTTP_CACHE)
            && ((conf->cache == NULL) == (prev->cache == NULL))
#endif
           )
        {
            return NGX_OK;
        }

    } else {
        if (conf->hide_headers == NGX_CONF_UNSET_PTR) {
            conf->hide_headers = prev->hide_headers;
        }

        if (conf->pass_headers == NGX_CONF_UNSET_PTR) {
            conf->pass_headers = prev->pass_headers;
        }
    }

    if (ngx_array_init(&hide_headers, cf->temp_pool, 4, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    for (h = default_hide_headers; h->len; h++) {
        hk = ngx_array_push(&hide_headers);
        if (hk == NULL) {
            return NGX_ERROR;
        }

        hk->key = *h;
        hk->key_hash = ngx_hash_key_lc(h->data, h->len);
        hk->value = (void *) 1;
    }

    if (conf->hide_headers != NGX_CONF_UNSET_PTR) {

        h = conf->hide_headers->elts;

        for (i = 0; i < conf->hide_headers->nelts; i++) {

            hk = hide_headers.elts;

            for (j = 0; j < hide_headers.nelts; j++) {
                if (ngx_strcasecmp(h[i].data, hk[j].key.data) == 0) {
                    goto exist;
                }
            }

            hk = ngx_array_push(&hide_headers);
            if (hk == NULL) {
                return NGX_ERROR;
            }

            hk->key = h[i];
            hk->key_hash = ngx_hash_key_lc(h[i].data, h[i].len);
            hk->value = (void *) 1;

        exist:

            continue;
        }
    }

    if (conf->pass_headers != NGX_CONF_UNSET_PTR) {

        h = conf->pass_headers->elts;
        hk = hide_headers.elts;

        for (i = 0; i < conf->pass_headers->nelts; i++) {
            for (j = 0; j < hide_headers.nelts; j++) {

                if (hk[j].key.data == NULL) {
                    continue;
                }

                if (ngx_strcasecmp(h[i].data, hk[j].key.data) == 0) {
                    hk[j].key.data = NULL;
                    break;
                }
            }
        }
    }

    hash->hash = &conf->hide_headers_hash;
    hash->key = ngx_hash_key_lc;
    hash->pool = cf->pool;
    hash->temp_pool = NULL;

    return ngx_hash_init(hash, hide_headers.elts, hide_headers.nelts);
}


static void *
ngx_http_upstream_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_main_conf_t  *umcf;

    umcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upstream_main_conf_t));
    if (umcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&umcf->upstreams, cf->pool, 4,
                       sizeof(ngx_http_upstream_srv_conf_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return umcf;
}


static char *
ngx_http_upstream_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_upstream_main_conf_t  *umcf = conf;

    ngx_uint_t                      i;
    ngx_array_t                     headers_in;
    ngx_hash_key_t                 *hk;
    ngx_hash_init_t                 hash;
    ngx_http_upstream_init_pt       init;
    ngx_http_upstream_header_t     *header;
    ngx_http_upstream_srv_conf_t  **uscfp;

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        init = uscfp[i]->peer.init_upstream ? uscfp[i]->peer.init_upstream:
                                            ngx_http_upstream_init_round_robin;

        if (init(cf, uscfp[i]) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }


    /* upstream_headers_in_hash */

    if (ngx_array_init(&headers_in, cf->temp_pool, 32, sizeof(ngx_hash_key_t))
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    for (header = ngx_http_upstream_headers_in; header->name.len; header++) {
        hk = ngx_array_push(&headers_in);
        if (hk == NULL) {
            return NGX_CONF_ERROR;
        }

        hk->key = header->name;
        hk->key_hash = ngx_hash_key_lc(header->name.data, header->name.len);
        hk->value = header;
    }

    hash.hash = &umcf->headers_in_hash;
    hash.key = ngx_hash_key_lc;
    hash.max_size = 512;
    hash.bucket_size = ngx_align(64, ngx_cacheline_size);
    hash.name = "upstream_headers_in_hash";
    hash.pool = cf->pool;
    hash.temp_pool = NULL;

    if (ngx_hash_init(&hash, headers_in.elts, headers_in.nelts) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}
