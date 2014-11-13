
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_mail.h>


typedef struct {
    ngx_flag_t  enable;
    ngx_flag_t  pass_error_message;
    ngx_flag_t  xclient;
    size_t      buffer_size;
    ngx_msec_t  timeout;
} ngx_mail_proxy_conf_t;


static void ngx_mail_proxy_block_read(ngx_event_t *rev);
static void ngx_mail_proxy_pop3_handler(ngx_event_t *rev);
static void ngx_mail_proxy_imap_handler(ngx_event_t *rev);
static void ngx_mail_proxy_smtp_handler(ngx_event_t *rev);
static void ngx_mail_proxy_dummy_handler(ngx_event_t *ev);
static ngx_int_t ngx_mail_proxy_read_response(ngx_mail_session_t *s,
    ngx_uint_t state);
static void ngx_mail_proxy_handler(ngx_event_t *ev);
static void ngx_mail_proxy_upstream_error(ngx_mail_session_t *s);
static void ngx_mail_proxy_internal_server_error(ngx_mail_session_t *s);
static void ngx_mail_proxy_close_session(ngx_mail_session_t *s);
static void *ngx_mail_proxy_create_conf(ngx_conf_t *cf);
static char *ngx_mail_proxy_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_command_t  ngx_mail_proxy_commands[] = {

    { ngx_string("proxy"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, enable),
      NULL },

    { ngx_string("proxy_buffer"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, buffer_size),
      NULL },

    { ngx_string("proxy_timeout"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, timeout),
      NULL },

    { ngx_string("proxy_pass_error_message"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, pass_error_message),
      NULL },

    { ngx_string("xclient"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_proxy_conf_t, xclient),
      NULL },

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_proxy_module_ctx = {
    NULL,                                  /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_proxy_create_conf,            /* create server configuration */
    ngx_mail_proxy_merge_conf              /* merge server configuration */
};


ngx_module_t  ngx_mail_proxy_module = {
    NGX_MODULE_V1,
    &ngx_mail_proxy_module_ctx,            /* module context */
    ngx_mail_proxy_commands,               /* module directives */
    NGX_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static u_char  smtp_auth_ok[] = "235 2.0.0 OK" CRLF;

/* 启动nginx与上游邮件服务器间的交互 */
void ngx_mail_proxy_init(ngx_mail_session_t *s, ngx_addr_t *peer)
{
    int                        keepalive;
    ngx_int_t                  rc;
    ngx_mail_proxy_ctx_t      *p;
    ngx_mail_proxy_conf_t     *pcf;
    ngx_mail_core_srv_conf_t  *cscf;

    s->connection->log->action = "connecting to upstream";

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    if (cscf->so_keepalive) {
        keepalive = 1;

        if (setsockopt(s->connection->fd, SOL_SOCKET, SO_KEEPALIVE,
                       (const void *) &keepalive, sizeof(int))
                == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, s->connection->log, ngx_socket_errno,
                          "setsockopt(SO_KEEPALIVE) failed");
        }
    }

    p = ngx_pcalloc(s->connection->pool, sizeof(ngx_mail_proxy_ctx_t));//创建ngx_mail_proxy_t结构体
    if (p == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    s->proxy = p;

    p->upstream.sockaddr = peer->sockaddr;
    p->upstream.socklen = peer->socklen;
    p->upstream.name = &peer->name;
    p->upstream.get = ngx_event_get_peer;
    p->upstream.log = s->connection->log;
    p->upstream.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&p->upstream);//向上游邮件服务器发起无阻塞的TCP连接

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

	/* 需要监控接收邮件服务器的响应是否超时，于是把与上游连接的读事件添加到定时器中 */
    ngx_add_timer(p->upstream.connection->read, cscf->timeout);

    p->upstream.connection->data = s;//设置连接的data成员指向ngx_mail_session_t结构体
    p->upstream.connection->pool = s->connection->pool;

	/* 设置nginx于客户端间连接读事件的回调方法为不会读取内容的ngx_mail_proxy_block_read方法，因为当前阶段nginx不会与客户端交互 */ 
    s->connection->read->handler = ngx_mail_proxy_block_read;

	/* 设置nginx与上游间的连接写事件回调方法为什么都不做的ngx_mail_proxy_dummy_handler方法，这意味着
	接下来向上游发送TCP流时，将不再通过epoll这个事件框架来调度*/
    p->upstream.connection->write->handler = ngx_mail_proxy_dummy_handler;

    pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);

	/* 建立nginx与邮件服务器间的内存缓冲区 */
    s->proxy->buffer = ngx_create_temp_buf(s->connection->pool,pcf->buffer_size);
    if (s->proxy->buffer == NULL) {
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    s->out.len = 0;//设置out为空，表示不会通过out向客户端发送响应

	/* 根据用户请求的协议设置实际的邮件认证方法 */
    switch (s->protocol) 
	{
    case NGX_MAIL_POP3_PROTOCOL://设置POP3协议进行邮件交互认证的方法
        p->upstream.connection->read->handler = ngx_mail_proxy_pop3_handler;
        s->mail_state = ngx_pop3_start;
        break;

    case NGX_MAIL_IMAP_PROTOCOL:
        p->upstream.connection->read->handler = ngx_mail_proxy_imap_handler;
        s->mail_state = ngx_imap_start;
        break;

    default: /* NGX_MAIL_SMTP_PROTOCOL */
        p->upstream.connection->read->handler = ngx_mail_proxy_smtp_handler;
        s->mail_state = ngx_smtp_start;
        break;
    }
}


static void
ngx_mail_proxy_block_read(ngx_event_t *rev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy block read");

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c = rev->data;
        s = c->data;

        ngx_mail_proxy_close_session(s);
    }
}

/* 与POP3邮件服务器认证交互的过程 */
static void ngx_mail_proxy_pop3_handler(ngx_event_t *rev)
{
    u_char                 *p;
    ngx_int_t               rc;
    ngx_str_t               line;//保存发往上游邮件服务器的消息
    ngx_connection_t       *c;
    ngx_mail_session_t     *s;
    ngx_mail_proxy_conf_t  *pcf;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy pop3 auth handler");

    c = rev->data;//获取nginx与上游的连接
    s = c->data;//获取ngx_mail_session_t结构体

	/* 如果读取上游邮件服务器响应超时，则向客户端发送错误响应 */
    if (rev->timedout) 
	{
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    rc = ngx_mail_proxy_read_response(s, 0);//读取上游邮件服务器发来的响应到buffer缓冲区中

	/* 还需要继续接收邮件服务器的消息 */
    if (rc == NGX_AGAIN) 
	{
        return;
    }

	/* 消息不合法或者邮件服务器没有通过验证，则返回错误给客户端 */
    if (rc == NGX_ERROR) 
	{
        ngx_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) 
	{
    case ngx_pop3_start://构造发送给邮件服务器的用户消息
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send user");

        s->connection->log->action = "sending user name to upstream";

        line.len = sizeof("USER ")  - 1 + s->login.len + 2;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, "USER ", sizeof("USER ") - 1);
        p = ngx_cpymem(p, s->login.data, s->login.len);
        *p++ = CR; *p = LF;

        s->mail_state = ngx_pop3_user;
        break;

    case ngx_pop3_user://构造发送给邮件服务器的密码信息
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send pass");

        s->connection->log->action = "sending password to upstream";

        line.len = sizeof("PASS ")  - 1 + s->passwd.len + 2;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, "PASS ", sizeof("PASS ") - 1);
        p = ngx_cpymem(p, s->passwd.data, s->passwd.len);
        *p++ = CR; *p = LF;

        s->mail_state = ngx_pop3_passwd;
        break;

		/* 在收到服务器返回的密码验证通过信息后，将nginx与下游客户端间、nginx与上游邮件服务器间的TCP连接上读写事件
		的回调方法都设置为ngx_main_proxy_handler方法*/
    case ngx_pop3_passwd:
        s->connection->read->handler = ngx_mail_proxy_handler;
        s->connection->write->handler = ngx_mail_proxy_handler;
        rev->handler = ngx_mail_proxy_handler;
        c->write->handler = ngx_mail_proxy_handler;

        pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
        ngx_add_timer(s->connection->read, pcf->timeout);
        ngx_del_timer(c->read);

        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");

        ngx_mail_proxy_handler(s->connection->write);//进入透传上下游TCP阶段

        return;

    default:
#if (NGX_SUPPRESS_WARN)
        ngx_str_null(&line);
#endif
        break;
    }

	/* 向上游的邮件服务器发送验证消息，注意，这里向邮件服务器发送TCP流与以前情况不同，它不再通过epoll检测到TCP连接上出现可写事件而触发。
	事实上，它是由连接上出现的可读事件触发的，因为读取到了邮件服务器的消息，才向邮件服务器发送消息，之所以可以这么做的一个原因在于，当前
	阶段发送的TCP消息包都非常短小*/
    if (c->send(c, line.data, line.len) < (ssize_t) line.len) 
	{
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

	/* 清空buffer缓冲区 */
    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
ngx_mail_proxy_imap_handler(ngx_event_t *rev)
{
    u_char                 *p;
    ngx_int_t               rc;
    ngx_str_t               line;
    ngx_connection_t       *c;
    ngx_mail_session_t     *s;
    ngx_mail_proxy_conf_t  *pcf;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy imap auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    rc = ngx_mail_proxy_read_response(s, s->mail_state);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) {

    case ngx_imap_start:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send login");

        s->connection->log->action = "sending LOGIN command to upstream";

        line.len = s->tag.len + sizeof("LOGIN ") - 1
                   + 1 + NGX_SIZE_T_LEN + 1 + 2;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = ngx_sprintf(line.data, "%VLOGIN {%uz}" CRLF,
                               &s->tag, s->login.len)
                   - line.data;

        s->mail_state = ngx_imap_login;
        break;

    case ngx_imap_login:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send user");

        s->connection->log->action = "sending user name to upstream";

        line.len = s->login.len + 1 + 1 + NGX_SIZE_T_LEN + 1 + 2;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = ngx_sprintf(line.data, "%V {%uz}" CRLF,
                               &s->login, s->passwd.len)
                   - line.data;

        s->mail_state = ngx_imap_user;
        break;

    case ngx_imap_user:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send passwd");

        s->connection->log->action = "sending password to upstream";

        line.len = s->passwd.len + 2;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, s->passwd.data, s->passwd.len);
        *p++ = CR; *p = LF;

        s->mail_state = ngx_imap_passwd;
        break;

    case ngx_imap_passwd:
        s->connection->read->handler = ngx_mail_proxy_handler;
        s->connection->write->handler = ngx_mail_proxy_handler;
        rev->handler = ngx_mail_proxy_handler;
        c->write->handler = ngx_mail_proxy_handler;

        pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
        ngx_add_timer(s->connection->read, pcf->timeout);
        ngx_del_timer(c->read);

        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");

        ngx_mail_proxy_handler(s->connection->write);

        return;

    default:
#if (NGX_SUPPRESS_WARN)
        ngx_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
ngx_mail_proxy_smtp_handler(ngx_event_t *rev)
{
    u_char                    *p;
    ngx_int_t                  rc;
    ngx_str_t                  line;
    ngx_buf_t                 *b;
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_proxy_conf_t     *pcf;
    ngx_mail_core_srv_conf_t  *cscf;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                   "mail proxy smtp auth handler");

    c = rev->data;
    s = c->data;

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                      "upstream timed out");
        c->timedout = 1;
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    rc = ngx_mail_proxy_read_response(s, s->mail_state);

    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_mail_proxy_upstream_error(s);
        return;
    }

    switch (s->mail_state) {

    case ngx_smtp_start:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0, "mail proxy send ehlo");

        s->connection->log->action = "sending HELO/EHLO to upstream";

        cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

        line.len = sizeof("HELO ")  - 1 + cscf->server_name.len + 2;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);

        p = ngx_cpymem(line.data,
                       ((s->esmtp || pcf->xclient) ? "EHLO " : "HELO "),
                       sizeof("HELO ") - 1);

        p = ngx_cpymem(p, cscf->server_name.data, cscf->server_name.len);
        *p++ = CR; *p = LF;

        if (pcf->xclient) {
            s->mail_state = ngx_smtp_helo_xclient;

        } else if (s->auth_method == NGX_MAIL_AUTH_NONE) {
            s->mail_state = ngx_smtp_helo_from;

        } else {
            s->mail_state = ngx_smtp_helo;
        }

        break;

    case ngx_smtp_helo_xclient:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send xclient");

        s->connection->log->action = "sending XCLIENT to upstream";

        line.len = sizeof("XCLIENT ADDR= LOGIN= NAME="
                          CRLF) - 1
                   + s->connection->addr_text.len + s->login.len + s->host.len;

        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = ngx_sprintf(line.data,
                       "XCLIENT ADDR=%V%s%V NAME=%V" CRLF,
                       &s->connection->addr_text,
                       (s->login.len ? " LOGIN=" : ""), &s->login, &s->host)
                   - line.data;

        if (s->smtp_helo.len) {
            s->mail_state = ngx_smtp_xclient_helo;

        } else if (s->auth_method == NGX_MAIL_AUTH_NONE) {
            s->mail_state = ngx_smtp_xclient_from;

        } else {
            s->mail_state = ngx_smtp_xclient;
        }

        break;

    case ngx_smtp_xclient_helo:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send client ehlo");

        s->connection->log->action = "sending client HELO/EHLO to upstream";

        line.len = sizeof("HELO " CRLF) - 1 + s->smtp_helo.len;

        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        line.len = ngx_sprintf(line.data,
                       ((s->esmtp) ? "EHLO %V" CRLF : "HELO %V" CRLF),
                       &s->smtp_helo)
                   - line.data;

        s->mail_state = (s->auth_method == NGX_MAIL_AUTH_NONE) ?
                            ngx_smtp_helo_from : ngx_smtp_helo;

        break;

    case ngx_smtp_helo_from:
    case ngx_smtp_xclient_from:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send mail from");

        s->connection->log->action = "sending MAIL FROM to upstream";

        line.len = s->smtp_from.len + sizeof(CRLF) - 1;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, s->smtp_from.data, s->smtp_from.len);
        *p++ = CR; *p = LF;

        s->mail_state = ngx_smtp_from;

        break;

    case ngx_smtp_from:
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, rev->log, 0,
                       "mail proxy send rcpt to");

        s->connection->log->action = "sending RCPT TO to upstream";

        line.len = s->smtp_to.len + sizeof(CRLF) - 1;
        line.data = ngx_pnalloc(c->pool, line.len);
        if (line.data == NULL) {
            ngx_mail_proxy_internal_server_error(s);
            return;
        }

        p = ngx_cpymem(line.data, s->smtp_to.data, s->smtp_to.len);
        *p++ = CR; *p = LF;

        s->mail_state = ngx_smtp_to;

        break;

    case ngx_smtp_helo:
    case ngx_smtp_xclient:
    case ngx_smtp_to:

        b = s->proxy->buffer;

        if (s->auth_method == NGX_MAIL_AUTH_NONE) {
            b->pos = b->start;

        } else {
            ngx_memcpy(b->start, smtp_auth_ok, sizeof(smtp_auth_ok) - 1);
            b->last = b->start + sizeof(smtp_auth_ok) - 1;
        }

        s->connection->read->handler = ngx_mail_proxy_handler;
        s->connection->write->handler = ngx_mail_proxy_handler;
        rev->handler = ngx_mail_proxy_handler;
        c->write->handler = ngx_mail_proxy_handler;

        pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
        ngx_add_timer(s->connection->read, pcf->timeout);
        ngx_del_timer(c->read);

        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "client logged in");

        ngx_mail_proxy_handler(s->connection->write);

        return;

    default:
#if (NGX_SUPPRESS_WARN)
        ngx_str_null(&line);
#endif
        break;
    }

    if (c->send(c, line.data, line.len) < (ssize_t) line.len) {
        /*
         * we treat the incomplete sending as NGX_ERROR
         * because it is very strange here
         */
        ngx_mail_proxy_internal_server_error(s);
        return;
    }

    s->proxy->buffer->pos = s->proxy->buffer->start;
    s->proxy->buffer->last = s->proxy->buffer->start;
}


static void
ngx_mail_proxy_dummy_handler(ngx_event_t *wev)
{
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, wev->log, 0, "mail proxy dummy handler");

    if (ngx_handle_write_event(wev, 0) != NGX_OK) {
        c = wev->data;
        s = c->data;

        ngx_mail_proxy_close_session(s);
    }
}


static ngx_int_t
ngx_mail_proxy_read_response(ngx_mail_session_t *s, ngx_uint_t state)
{
    u_char                 *p;
    ssize_t                 n;
    ngx_buf_t              *b;
    ngx_mail_proxy_conf_t  *pcf;

    s->connection->log->action = "reading response from upstream";

    b = s->proxy->buffer;

    n = s->proxy->upstream.connection->recv(s->proxy->upstream.connection,
                                            b->last, b->end - b->last);

    if (n == NGX_ERROR || n == 0) {
        return NGX_ERROR;
    }

    if (n == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    b->last += n;

    if (b->last - b->pos < 4) {
        return NGX_AGAIN;
    }

    if (*(b->last - 2) != CR || *(b->last - 1) != LF) {
        if (b->last == b->end) {
            *(b->last - 1) = '\0';
            ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                          "upstream sent too long response line: \"%s\"",
                          b->pos);
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    p = b->pos;

    switch (s->protocol) {

    case NGX_MAIL_POP3_PROTOCOL:
        if (p[0] == '+' && p[1] == 'O' && p[2] == 'K') {
            return NGX_OK;
        }
        break;

    case NGX_MAIL_IMAP_PROTOCOL:
        switch (state) {

        case ngx_imap_start:
            if (p[0] == '*' && p[1] == ' ' && p[2] == 'O' && p[3] == 'K') {
                return NGX_OK;
            }
            break;

        case ngx_imap_login:
        case ngx_imap_user:
            if (p[0] == '+') {
                return NGX_OK;
            }
            break;

        case ngx_imap_passwd:
            if (ngx_strncmp(p, s->tag.data, s->tag.len) == 0) {
                p += s->tag.len;
                if (p[0] == 'O' && p[1] == 'K') {
                    return NGX_OK;
                }
            }
            break;
        }

        break;

    default: /* NGX_MAIL_SMTP_PROTOCOL */
        switch (state) {

        case ngx_smtp_start:
            if (p[0] == '2' && p[1] == '2' && p[2] == '0') {
                return NGX_OK;
            }
            break;

        case ngx_smtp_helo:
        case ngx_smtp_helo_xclient:
        case ngx_smtp_helo_from:
        case ngx_smtp_from:
            if (p[0] == '2' && p[1] == '5' && p[2] == '0') {
                return NGX_OK;
            }
            break;

        case ngx_smtp_xclient:
        case ngx_smtp_xclient_from:
        case ngx_smtp_xclient_helo:
            if (p[0] == '2' && (p[1] == '2' || p[1] == '5') && p[2] == '0') {
                return NGX_OK;
            }
            break;

        case ngx_smtp_to:
            return NGX_OK;
        }

        break;
    }

    pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);

    if (pcf->pass_error_message == 0) {
        *(b->last - 2) = '\0';
        ngx_log_error(NGX_LOG_ERR, s->connection->log, 0,
                      "upstream sent invalid response: \"%s\"", p);
        return NGX_ERROR;
    }

    s->out.len = b->last - p - 2;
    s->out.data = p;

    ngx_log_error(NGX_LOG_INFO, s->connection->log, 0,
                  "upstream sent invalid response: \"%V\"", &s->out);

    s->out.len = b->last - b->pos;
    s->out.data = b->pos;

    return NGX_ERROR;
}

/* 透传上游邮件服务器与客户端间的流 */
static void ngx_mail_proxy_handler(ngx_event_t *ev)
{
    char                   *action, *recv_action, *send_action;
    size_t                  size;//读取消息时，size表示recv中空闲缓冲区的大小；发送消息时，表示将要发送的消息长度
    ssize_t                 n;
    ngx_buf_t              *b;
    ngx_uint_t              do_write;//决定本次到底是发送还是接收TCP消息

	/* 每次透传TCP，上、下游的客户端与邮件服务器之间必然有一个负责提供消息，另一个负责接收nginx转发的消息。
	src表示nginx与提供消息一方的连接，dst表示nginx与接收消息一方之间的连接*/
    ngx_connection_t       *c, *src, *dst;
    ngx_mail_session_t     *s;
    ngx_mail_proxy_conf_t  *pcf;

	/* 注意，事件ev既可能属于nginx与下游间的连接，也可能属于nginx与上游间的连接，此时无法判断c究竟是来自上游还是下游 */
    c = ev->data;
    s = c->data;//无论是在上游连接还是下游连接，ngx_connection_t结构体的data成员都指向ngx_mail_session_t结构体

	/* 无论上下游，只要接收或者发送消息出现了超时，都需要终止透传 */
    if (ev->timedout) 
	{
        c->log->action = "proxying";

        if (c == s->connection) {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "client timed out");
            c->timedout = 1;

        } else {
            ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT,
                          "upstream timed out");
        }

        ngx_mail_proxy_close_session(s);//同时关闭上下游的TCP连接
        return;
    }

	/* ngx_mail_session_t结构体中的connection成员一定指向nginx与下游客户端间的TCP连接 */
	/* 以下意味着收到了下游连接上的事件 */
    if (c == s->connection) 
	{
		/* 当下游可写事件被触发时，意味着本次nginx将负责把接收自上游的缓存消息发给下游 */
        if (ev->write) 
		{
            recv_action = "proxying and reading from upstream";
            send_action = "proxying and sending to client";
            src = s->proxy->upstream.connection;//设src来源连接为上游连接
            dst = c;//设dst目标连接为下游连接
            b = s->proxy->buffer;//设置用于向下游发送的消息缓冲区

        }
		/* 当下游可读事件被触发时，意味着本次nginx将负责先读取下游的响应到缓存中，为下一步转发给上游做准备 */
		else
		{
            recv_action = "proxying and reading from client";
            send_action = "proxying and sending to upstream";
            src = c;//设置src来源链接为下游连接
            dst = s->proxy->upstream.connection;//设置dst目标连接为上游连接
            b = s->buffer;//设置用于接收下游消息的缓冲区
        }

    }
	/* 以下意味着收到了上游连接上的事件 */
	else
	{
		/* 当上游可写事件被触发时，意味着本次nginx将负责把接收自下游的缓存消息发送给上游 */
        if (ev->write) 
		{
            recv_action = "proxying and reading from client";
            send_action = "proxying and sending to upstream";
            src = s->connection;//设置src来源连接为下游连接
            dst = c;//设置dst目标连接为上游连接
            b = s->buffer;//设置用于向上游发送消息的缓冲区

        }
		/* 当上游可读事件被触发时，意味着本次nginx将负责接收上游的消息到缓存中，为下一步把这个消息发送给下游做准备 */
		else 
		{
            recv_action = "proxying and reading from upstream";
            send_action = "proxying and sending to client";
            src = c;//设src来源连接为上游连接
            dst = s->connection;//设dst目标连接为下游连接
            b = s->proxy->buffer;//设置用于接收上游消息的缓冲区
        }
    }

	/* 当前触发事件的write标志位将决定do_write本次是发送还是接收消息 */
    do_write = ev->write ? 1 : 0;

    ngx_log_debug3(NGX_LOG_DEBUG_MAIL, ev->log, 0,
                   "mail proxy handler: %d, #%d > #%d",
                   do_write, src->fd, dst->fd);

	/* 进入向dst连接发送消息或者由src连接接收消息的循环，直到套接字上暂无可读或可写事件时才退出 */
    for ( ;; ) 
	{
		/* 如果本次将发送消息，那么首先计算出要发送的消息长度 */
        if (do_write) 
		{
            size = b->last - b->pos;

            /* 目标连接是否可写 */
			if (size && dst->write->ready) 
			{
                c->log->action = send_action;

                n = dst->send(dst, b->pos, size);//向目标连接发送TCP消息

                if (n == NGX_ERROR) {
                    ngx_mail_proxy_close_session(s);
                    return;
                }

				/* 更新消息缓冲区 */
                if (n > 0) 
				{
                    b->pos += n;

					/* 如果缓冲区中的消息全部发送完，则清空缓冲区以复用 */
                    if (b->pos == b->last) {
                        b->pos = b->start;
                        b->last = b->start;
                    }
                }
            }
        }

		/* 下面为读取TCP准备，先计算接收缓冲区上的空闲空间大小 */
        size = b->end - b->last;

		/* 检查源连接上当前是否可读 */
        if (size && src->read->ready) 
		{
            c->log->action = recv_action;

            n = src->recv(src, b->last, size);//由src源连接上接收TCP消息

			/* 没有读取到内容或者对方主动关闭了TCP连接，则跳出循环 */
            if (n == NGX_AGAIN || n == 0) 
			{
                break;
            }

			/* 如果读取到消息，则应试图在本次ngx_mail_proxy_handler方法的执行中将它立即发送出去 */
            if (n > 0) 
			{
                do_write = 1;
                b->last += n;//更新消息缓冲区

                continue;//重新执行循环，检查是否可以立即转发出去
            }

            if (n == NGX_ERROR) {
                src->read->eof = 1;
            }
        }

        break;
    }

    c->log->action = "proxying";

	/* 如果上下游间的连接中断，则结束透传流程 */
    if ((s->connection->read->eof && s->buffer->pos == s->buffer->last)
        || (s->proxy->upstream.connection->read->eof
            && s->proxy->buffer->pos == s->proxy->buffer->last)
        || (s->connection->read->eof
            && s->proxy->upstream.connection->read->eof))
    {
        action = c->log->action;
        c->log->action = NULL;
        ngx_log_error(NGX_LOG_INFO, c->log, 0, "proxied session done");
        c->log->action = action;

        ngx_mail_proxy_close_session(s);
        return;
    }

	/* 下面将会把nginx与上下游TCP连接上的4个读写事件再次添加到epoll中监控 */
    if (ngx_handle_write_event(dst->write, 0) != NGX_OK) {
        ngx_mail_proxy_close_session(s);
        return;
    }

    if (ngx_handle_read_event(dst->read, 0) != NGX_OK) {
        ngx_mail_proxy_close_session(s);
        return;
    }

    if (ngx_handle_write_event(src->write, 0) != NGX_OK) {
        ngx_mail_proxy_close_session(s);
        return;
    }

    if (ngx_handle_read_event(src->read, 0) != NGX_OK) {
        ngx_mail_proxy_close_session(s);
        return;
    }

	/* 接收下游客户端的消息时还是需要检查超时的，防止僵死客户端占用nginx服务器资源 */
    if (c == s->connection) 
	{
        pcf = ngx_mail_get_module_srv_conf(s, ngx_mail_proxy_module);
        ngx_add_timer(c->read, pcf->timeout);
    }
}


static void
ngx_mail_proxy_upstream_error(ngx_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        ngx_close_connection(s->proxy->upstream.connection);
    }

    if (s->out.len == 0) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    s->quit = 1;
    ngx_mail_send(s->connection->write);
}


static void
ngx_mail_proxy_internal_server_error(ngx_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        ngx_close_connection(s->proxy->upstream.connection);
    }

    ngx_mail_session_internal_server_error(s);
}


static void
ngx_mail_proxy_close_session(ngx_mail_session_t *s)
{
    if (s->proxy->upstream.connection) {
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, s->connection->log, 0,
                       "close mail proxy connection: %d",
                       s->proxy->upstream.connection->fd);

        ngx_close_connection(s->proxy->upstream.connection);
    }

    ngx_mail_close_connection(s->connection);
}


static void *
ngx_mail_proxy_create_conf(ngx_conf_t *cf)
{
    ngx_mail_proxy_conf_t  *pcf;

    pcf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_proxy_conf_t));
    if (pcf == NULL) {
        return NULL;
    }

    pcf->enable = NGX_CONF_UNSET;
    pcf->pass_error_message = NGX_CONF_UNSET;
    pcf->xclient = NGX_CONF_UNSET;
    pcf->buffer_size = NGX_CONF_UNSET_SIZE;
    pcf->timeout = NGX_CONF_UNSET_MSEC;

    return pcf;
}


static char *
ngx_mail_proxy_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_proxy_conf_t *prev = parent;
    ngx_mail_proxy_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->pass_error_message, prev->pass_error_message, 0);
    ngx_conf_merge_value(conf->xclient, prev->xclient, 1);
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              (size_t) ngx_pagesize);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 24 * 60 * 60000);

    return NGX_CONF_OK;
}
