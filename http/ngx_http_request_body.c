
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static void ngx_http_read_client_request_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_write_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_read_discarded_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_discard_request_body_filter(ngx_http_request_t *r,
    ngx_buf_t *b);
static ngx_int_t ngx_http_test_expect(ngx_http_request_t *r);

static ngx_int_t ngx_http_request_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_request_body_length_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_request_body_chunked_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_request_body_save_filter(ngx_http_request_t *r,
    ngx_chain_t *in);

/*接收到包体时调用的方法,该方法供handle模块调用，如ngx_http_fastcgi_module，它提供的post_handler方法是ngx_http_upstream_init*/
ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r,ngx_http_client_body_handler_pt post_handler)
{
    size_t                     preread;
    ssize_t                    size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t                out, *cl;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;
	//把该请求对应的原始请求的引用计数加1
    r->main->count++;
#if (NGX_HTTP_SPDY)
    if (r->spdy_stream) {
        rc = ngx_http_spdy_read_request_body(r, post_handler);
        goto done;
    }
#endif
	//已经读取过HTTP包体了或者曾经执行过丢弃包体的方法了或现在包体正在被丢弃
    if (r != r->main || r->request_body || r->discard_body)
	{	
		//执行各HTTP模块提供的post_handler回调方法
        post_handler(r);
        return NGX_OK;
    }
    if (ngx_http_test_expect(r) != NGX_OK)
    {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }
	//分配请求的ngx_http_request_t结构体中的request_body成员
    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }
    rb->rest = -1;
    rb->post_handler = post_handler;
    r->request_body = rb;
	//content-length字段<=0,不用继续接收包体
    if (r->headers_in.content_length_n < 0 && !r->headers_in.chunked)
	{
        post_handler(r);
        return NGX_OK;
    }
	/*在11.5节描述的接收HTTP头部的流程中，是有可能接收到HTTP包体,preread表示接收到的未解析的头部，即包体*/
    preread = r->header_in->last - r->header_in->pos;
    if (preread) 
	{
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http client request body preread %uz", preread);
        out.buf = r->header_in;
        out.next = NULL;
		//把链表out中的数据添加到r->request_body中
        rc = ngx_http_request_body_filter(r, &out);
        if (rc != NGX_OK) {
            goto done;
        }
        r->request_length += preread - (r->header_in->last - r->header_in->pos);
		/* 检查header_in缓冲区的剩余空间是否可以存放下全部的包体，如果可以，就不用分配新的包体缓冲区了*/
        if (!r->headers_in.chunked && rb->rest > 0 && rb->rest <= (off_t) (r->header_in->end - r->header_in->last))
        {
            /* header_in缓冲区的剩余空间可以存放下全部的包体 */
            b = ngx_calloc_buf(r->pool);
            if (b == NULL)
            {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }
            b->temporary = 1;
            b->start = r->header_in->pos;
            b->pos = r->header_in->pos;
            b->last = r->header_in->last;
            b->end = r->header_in->end;
            rb->buf = b;
            r->read_event_handler = ngx_http_read_client_request_body_handler;
            r->write_event_handler = ngx_http_request_empty_handler;
            rc = ngx_http_do_read_client_request_body(r);
            goto done;
        }
    }
	else
	{
        /* set rb->rest */
        if (ngx_http_request_body_filter(r, NULL) != NGX_OK)
        {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }
    }
	//已经全部接收完body
    if (rb->rest == 0) 
	{
        /* the whole request body was pre-read */
        if (r->request_body_in_file_only) 
		{
            if (ngx_http_write_request_body(r) != NGX_OK)
            {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }
            cl = ngx_chain_get_free_buf(r->pool, &rb->free);
            if (cl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            b = cl->buf;
            ngx_memzero(b, sizeof(ngx_buf_t));
            b->in_file = 1;
            b->file_last = rb->temp_file->file.offset;
            b->file = &rb->temp_file->file;
            rb->bufs = cl;
        }
        post_handler(r);
        return NGX_OK;
    }
    if (rb->rest < 0)
    {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,"negative request body rest");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    size = clcf->client_body_buffer_size;
    size += size >> 2;
    /* TODO: honor r->request_body_in_single_buf */
    if (!r->headers_in.chunked && rb->rest < size)
	{
        size = (ssize_t) rb->rest;
        if (r->request_body_in_single_buf) {
            size += preread;
        }
    }
	else 
	{
        size = clcf->client_body_buffer_size;
    }
    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL)
    {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }
	/*意味着如果epoll再次检测到可读事件或者读事件定时器超时，HTTP框架将调用ngx_http_read_client_request_body_handler方法处理*/
    r->read_event_handler = ngx_http_read_client_request_body_handler;
    r->write_event_handler = ngx_http_request_empty_handler;
	//调用该方法接收包体
    rc = ngx_http_do_read_client_request_body(r);
done:
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        r->main->count--;
    }
    return rc;
}

/* 第一次接收包体没有接收完时，调用该方法 */
static void ngx_http_read_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;
    if (r->connection->read->timedout) 
	{
        r->connection->timedout = 1;
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }
	//接收包体
    rc = ngx_http_do_read_client_request_body(r);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) 
	{
        ngx_http_finalize_request(r, rc);
    }
}

/* 该方法的意义在于把客户端与nginx之间TCP连接上套接字缓冲区中的当前字符流全部读出来，并判断是否需要写入文件，以及是否接收到全部的包体，同时在接收到完整
包体后激活post_handler方法 */
static ngx_int_t ngx_http_do_read_client_request_body(ngx_http_request_t *r)
{
    off_t                      rest;
    size_t                     size;
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, out;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;
    c = r->connection;
    rb = r->request_body;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,"http read client request body");
    for ( ;; ) 
	{
        for ( ;; ) 
		{	
			//请求的request_body成员中的buf缓冲区已写满
            if (rb->buf->last == rb->buf->end) 
			{
                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;
                rc = ngx_http_request_body_filter(r, &out);
                if (rc != NGX_OK) {
                    return rc;
                }
                //把缓冲区中的字符写入文件
                if (ngx_http_write_request_body(r) != NGX_OK) 
				{
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                /* update chains */
                rc = ngx_http_request_body_filter(r, NULL);
                if (rc != NGX_OK) {
                    return rc;
                }
                if (rb->busy != NULL)
                {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
				//由于已经把缓冲区的内容写入文件，所有缓冲区可以重复使用了
                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
            }
            size = rb->buf->end - rb->buf->last;
            rest = rb->rest - (rb->buf->last - rb->buf->pos);
            if ((off_t) size > rest)
            {
                size = (size_t) rest;
            }
			//从套接字缓冲区读取包体到缓冲区中
            n = c->recv(c, rb->buf->last, size);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,"http client request body recv %z", n);
            if (n == NGX_AGAIN) {
                break;
            }
            if (n == 0)
            {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,"client prematurely closed connection");
            }
            if (n == 0 || n == NGX_ERROR)
            {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }
			//根据接收到的TCP流长度，修改缓冲区参数
            rb->buf->last += n;
            r->request_length += n;
            if (n == rest) 
			{
                /* pass buffer to request body filter chain */
                out.buf = rb->buf;
                out.next = NULL;
                rc = ngx_http_request_body_filter(r, &out);
                if (rc != NGX_OK) {
                    return rc;
                }
            }
            if (rb->rest == 0) {
                break;
            }
            if (rb->buf->last < rb->buf->end) {
                break;
            }
        }
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,"http client request body rest %O", rb->rest);
		//已经接收到了完整的包体
        if (rb->rest == 0) 
		{
            break;
        }
		/* 如果当前已经没有可读的字符流，同时还没有接收到完整的包体，则说明需要把读事件添加到事件模块，等待可读事件的发生，事件框架可以再次调度到这个
		方法接收包体*/
        if (!c->read->ready) 
		{
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) 
			{
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            return NGX_AGAIN;
        }
    }
	/* 到此表明接收到完整的包体，需要做一些收尾的工作了 */
    if (c->read->timer_set) 
	{	
		//不需要检查是否接收到HTTP包体超时了
        ngx_del_timer(c->read);
    }
	//如果缓冲区还有未写入文件的内容，则把最后的包体写入文件
    if (rb->temp_file || r->request_body_in_file_only) 
	{
        if (ngx_http_write_request_body(r) != NGX_OK) 
		{
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        cl = ngx_chain_get_free_buf(r->pool, &rb->free);
        if (cl == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        b = cl->buf;
        ngx_memzero(b, sizeof(ngx_buf_t));
        b->in_file = 1;
        b->file_last = rb->temp_file->file.offset;
        b->file = &rb->temp_file->file;
        rb->bufs = cl;
    }
	/*在图11-13的第5步中曾经把请求的read_event_handler成员设置为ngx_http_read_client_request_body_handler方法，现在既然已经接收到完整的包体了，
	就会把read_event_handler设为ngx_http_block_reading方法，表示连接上再有读事件将不做任何处理*/
    r->read_event_handler = ngx_http_block_reading;
	//执行HTTP模块提供的post_handler回调方法
    rb->post_handler(r);
    return NGX_OK;
}


//把缓冲区中的字符写入文件
static ngx_int_t ngx_http_write_request_body(ngx_http_request_t *r)
{
    ssize_t                    n;
    ngx_chain_t               *cl;
    ngx_temp_file_t           *tf;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http write client request body, bufs %p", rb->bufs);

    if (rb->temp_file == NULL) {
        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return NGX_ERROR;
        }

        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

        tf->file.fd = NGX_INVALID_FILE;
        tf->file.log = r->connection->log;
        tf->path = clcf->client_body_temp_path;
        tf->pool = r->pool;
        tf->warn = "a client request body is buffered to a temporary file";
        tf->log_level = r->request_body_file_log_level;
        tf->persistent = r->request_body_in_persistent_file;
        tf->clean = r->request_body_in_clean_file;

        if (r->request_body_file_group_access) {
            tf->access = 0660;
        }

        rb->temp_file = tf;

        if (rb->bufs == NULL) {
            /* empty body with r->request_body_in_file_only */

            if (ngx_create_temp_file(&tf->file, tf->path, tf->pool,
                                     tf->persistent, tf->clean, tf->access)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    if (rb->bufs == NULL) {
        return NGX_OK;
    }

    n = ngx_write_chain_to_temp_file(rb->temp_file, rb->bufs);

    /* TODO: n == 0 or not complete and level event */

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    rb->temp_file->offset += n;

    /* mark all buffers as written */

    for (cl = rb->bufs; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->last;
    }

    rb->bufs = NULL;

    return NGX_OK;
}

/*第一次启动丢弃包体的动作，被handler模块调用，用于丢弃包体，例如ngx_http_static_module */
ngx_int_t ngx_http_discard_request_body(ngx_http_request_t *r)
{
    ssize_t       size;
    ngx_int_t     rc;
    ngx_event_t  *rev;
#if (NGX_HTTP_SPDY)
    if (r->spdy_stream && r == r->main) 
	{
        r->spdy_stream->skip_data = NGX_SPDY_DATA_DISCARD;
        return NGX_OK;
    }
#endif
	/* 检查当前请求是一个子请求还是原始请求，因为对于子请求而言，它不是来自客户端请求，所以不存在处理HTTP请求包体的概念*/

	//子请求或者正在丢弃包体或者正在请求包体
    if (r != r->main || r->discard_body || r->request_body) 
	{
        return NGX_OK;
    }
    if (ngx_http_test_expect(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    rev = r->connection->read;
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "http set discard body");
	//丢弃包体不需要考虑超时问题
    if (rev->timer_set)
	{
        ngx_del_timer(rev);
    }
    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        return NGX_OK;
    }
    size = r->header_in->last - r->header_in->pos;
    if (size || r->headers_in.chunked)
	{
        rc = ngx_http_discard_request_body_filter(r, r->header_in);
        if (rc != NGX_OK) {
            return rc;
        }
        if (r->headers_in.content_length_n == 0) {
            return NGX_OK;
        }
    }
    rc = ngx_http_read_discarded_request_body(r);
	//已接收到完整的包体,如果包体很小，那么这是非常可能的
    if (rc == NGX_OK) 
	{
        r->lingering_close = 0;
        return NGX_OK;
    }
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    /* rc == NGX_AGAIN */

	//表示需要多次调度才能完成丢弃包体这一动作，设置请求的read_event_handler
    r->read_event_handler = ngx_http_discarded_request_body_handler;
	//把读事件添加到epoll中
    if (ngx_handle_read_event(rev, 0) != NGX_OK) 
	{
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
	//防止这边还在丢弃包体，而其他事件却已让请求意外销毁
    r->count++;
	//表示正在丢弃包体
    r->discard_body = 1;
	//这时的OK不表示已经成功的接收完包体，只是说明ng_http_discard_request_body执行完毕
    return NGX_OK;
}

//在丢弃包体时，由新的可读事件被触发时，调用该方法继续处理丢弃工作
void ngx_http_discarded_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t                  rc;
    ngx_msec_t                 timer;
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_http_core_loc_conf_t  *clcf;
    c = r->connection;
    rev = c->read;
    if (rev->timedout) 
	{
        c->timedout = 1;
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }
    if (r->lingering_time)
    {
        timer = (ngx_msec_t) (r->lingering_time - ngx_time());
        if (timer <= 0)
        {
            r->discard_body = 0;
            r->lingering_close = 0;
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }
    }
    else
    {
        timer = 0;
    }
	//进行丢弃
    rc = ngx_http_read_discarded_request_body(r);
	//成功丢弃所有包体
    if (rc == NGX_OK) 
	{
        r->discard_body = 0;
        r->lingering_close = 0;
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }
    /* rc == NGX_AGAIN */

	//仍然需要把读事件添加到epoll中，期待新的可读事件到来
    if (ngx_handle_read_event(rev, 0) != NGX_OK) 
	{
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }
    if (timer) 
	{
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        timer *= 1000;
        if (timer > clcf->lingering_timeout) {
            timer = clcf->lingering_timeout;
        }
        ngx_add_timer(rev, timer);
    }
}

//真正的丢包处理
static ngx_int_t ngx_http_read_discarded_request_body(ngx_http_request_t *r)
{
    size_t     size;
    ssize_t    n;
    ngx_int_t  rc;
    ngx_buf_t  b;
    u_char     buffer[NGX_HTTP_DISCARD_BUFFER_SIZE];
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http read discarded body");
    ngx_memzero(&b, sizeof(ngx_buf_t));
    b.temporary = 1;
    for ( ;; ) 
	{
		/* 丢弃包体时请求的request_body成员为NULL，此时用ngx_http_request_t结构体headers_in成员里的content_length_n表示已经丢弃的包体的大小，
		它最初等于content-length头部，而每丢弃一部分包体，就会减去相应的大小*/

		//表示已经接收完整的包体
		if (r->headers_in.content_length_n == 0) 
		{	
			//表示如果再有可读事件被触发，不做任何处理
            r->read_event_handler = ngx_http_block_reading;
            return NGX_OK;
        }
		//连接套接字缓冲区上没有可读内容，返回NGX_AGAIN等待读事件的触发
        if (!r->connection->read->ready) 
		{
            return NGX_AGAIN;
        }
        size = (size_t) ngx_min(r->headers_in.content_length_n, NGX_HTTP_DISCARD_BUFFER_SIZE);
		/*读取包体，每次读取的数据放入buffer中，然后用	r->headers_in.content_length_n减去该size，下次仍然把数据添加到buffer的开头，覆盖上次
		buffer的内容，直到r->headers_in.content_length_n的值为0，表示包体读取完毕*/
        n = r->connection->recv(r->connection, buffer, size);
        if (n == NGX_ERROR) 
		{
            r->connection->error = 1;
            return NGX_OK;
        }
        if (n == NGX_AGAIN) 
		{
            return NGX_AGAIN;
        }
        if (n == 0) 
		{
            return NGX_OK;
        }
        b.pos = buffer;
        b.last = buffer + n;
		//接收到包体后，更新请求的content_length_n成员，继续循环接收包体
        rc = ngx_http_discard_request_body_filter(r, &b);
        if (rc != NGX_OK) {
            return rc;
        }
    }
}

/* 对接收到的数据进行解吗等处理，更新请求的 content_length_n成员，继续循环接收包体并丢弃*/
static ngx_int_t ngx_http_discard_request_body_filter(ngx_http_request_t *r, ngx_buf_t *b)
{
    size_t                    size;
    ngx_int_t                 rc;
    ngx_http_request_body_t  *rb;
	//需要进行解吗
    if (r->headers_in.chunked) 
	{
        rb = r->request_body;
        if (rb == NULL)
        {
            rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
            if (rb == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
            if (rb->chunked == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            r->request_body = rb;
        }
        for ( ;; )
        {
            rc = ngx_http_parse_chunked(r, b, rb->chunked);//进行chunked解码，获得每一个chunked块的大小和内容
            if (rc == NGX_OK)
            {
                /* a chunk has been parsed successfully */
                size = b->last - b->pos;
                if ((off_t) size > rb->chunked->size)
                {
                    b->pos += rb->chunked->size;
                    rb->chunked->size = 0;
                }
                else
                {
                    rb->chunked->size -= size;
                    b->pos = b->last;
                }
                continue;
            }
            if (rc == NGX_DONE)
            {
                /* a whole response has been parsed successfully */
                r->headers_in.content_length_n = 0;
                break;
            }
            if (rc == NGX_AGAIN)
            {
                /* set amount of data we want to see next time */
                r->headers_in.content_length_n = rb->chunked->length;
                break;
            }
            /* invalid */
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"client sent invalid chunked body");
            return NGX_HTTP_BAD_REQUEST;
        }
    }
	else 
	{
        size = b->last - b->pos;
        if ((off_t) size > r->headers_in.content_length_n) 
		{
            b->pos += r->headers_in.content_length_n;
            r->headers_in.content_length_n = 0;
        }
		else 
		{
            b->pos = b->last;
            r->headers_in.content_length_n -= size;
        }
    }
    return NGX_OK;
}


static ngx_int_t
ngx_http_test_expect(ngx_http_request_t *r)
{
    ngx_int_t   n;
    ngx_str_t  *expect;

    if (r->expect_tested
        || r->headers_in.expect == NULL
        || r->http_version < NGX_HTTP_VERSION_11)
    {
        return NGX_OK;
    }

    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    if (expect->len != sizeof("100-continue") - 1
        || ngx_strncasecmp(expect->data, (u_char *) "100-continue",
                           sizeof("100-continue") - 1)
           != 0)
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "send 100 Continue");

    n = r->connection->send(r->connection,
                            (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
                            sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NGX_OK;
    }

    /* we assume that such small packet should be send successfully */

    return NGX_ERROR;
}


static ngx_int_t ngx_http_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    if (r->headers_in.chunked) 
	{
        return ngx_http_request_body_chunked_filter(r, in);
    } 
	else 
	{
        return ngx_http_request_body_length_filter(r, in);
    }
}

//把链表in中的数据添加到r->request_body中
static ngx_int_t ngx_http_request_body_length_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *tl, *out, **ll;
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

    if (rb->rest == -1) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http request body content length filter");

        rb->rest = r->headers_in.content_length_n;
    }

    out = NULL;
    ll = &out;

	//把链表in中的数据复制到out中
    for (cl = in; cl; cl = cl->next) 
	{
        tl = ngx_chain_get_free_buf(r->pool, &rb->free);
        if (tl == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b = tl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->temporary = 1;
        b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
        b->start = cl->buf->pos;
        b->pos = cl->buf->pos;
        b->last = cl->buf->last;
        b->end = cl->buf->end;

        size = cl->buf->last - cl->buf->pos;

        if ((off_t) size < rb->rest) {
            cl->buf->pos = cl->buf->last;
            rb->rest -= size;

        } else {
            cl->buf->pos += rb->rest;
            rb->rest = 0;
            b->last = cl->buf->pos;
            b->last_buf = 1;
        }

        *ll = tl;
        ll = &tl->next;
    }

	//把out中的数据添加到r->request_body->bufs后面
    rc = ngx_http_request_body_save_filter(r, out);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}


static ngx_int_t ngx_http_request_body_chunked_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *out, *tl, **ll;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    rb = r->request_body;

    if (rb->rest == -1) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"http request body chunked filter");

        rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t));
        if (rb->chunked == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_in.content_length_n = 0;
        rb->rest = 3;
    }

    out = NULL;
    ll = &out;

    for (cl = in; cl; cl = cl->next) {

        for ( ;; ) {

            ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                           "http body chunked buf "
                           "t:%d f:%d %p, pos %p, size: %z file: %O, size: %z",
                           cl->buf->temporary, cl->buf->in_file,
                           cl->buf->start, cl->buf->pos,
                           cl->buf->last - cl->buf->pos,
                           cl->buf->file_pos,
                           cl->buf->file_last - cl->buf->file_pos);

            rc = ngx_http_parse_chunked(r, cl->buf, rb->chunked);

            if (rc == NGX_OK) {

                /* a chunk has been parsed successfully */

                clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

                if (clcf->client_max_body_size
                    && clcf->client_max_body_size
                       < r->headers_in.content_length_n + rb->chunked->size)
                {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                  "client intended to send too large chunked "
                                  "body: %O bytes",
                                  r->headers_in.content_length_n
                                  + rb->chunked->size);

                    r->lingering_close = 1;

                    return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
                }

                tl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->temporary = 1;
                b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
                b->start = cl->buf->pos;
                b->pos = cl->buf->pos;
                b->last = cl->buf->last;
                b->end = cl->buf->end;

                *ll = tl;
                ll = &tl->next;

                size = cl->buf->last - cl->buf->pos;

                if ((off_t) size > rb->chunked->size) {
                    cl->buf->pos += rb->chunked->size;
                    r->headers_in.content_length_n += rb->chunked->size;
                    rb->chunked->size = 0;

                } else {
                    rb->chunked->size -= size;
                    r->headers_in.content_length_n += size;
                    cl->buf->pos = cl->buf->last;
                }

                b->last = cl->buf->pos;

                continue;
            }

            if (rc == NGX_DONE) {

                /* a whole response has been parsed successfully */

                rb->rest = 0;

                tl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (tl == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                b = tl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->last_buf = 1;

                *ll = tl;
                ll = &tl->next;

                break;
            }

            if (rc == NGX_AGAIN) {

                /* set rb->rest, amount of data we want to see next time */

                rb->rest = rb->chunked->length;

                break;
            }

            /* invalid */

            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "client sent invalid chunked body");

            return NGX_HTTP_BAD_REQUEST;
        }
    }

    rc = ngx_http_request_body_save_filter(r, out);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
                            (ngx_buf_tag_t) &ngx_http_read_client_request_body);

    return rc;
}

//把in中的body数据添加到r->request_body->bufs后面
static ngx_int_t ngx_http_request_body_save_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
#if (NGX_DEBUG)
    ngx_chain_t               *cl;
#endif
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

#if (NGX_DEBUG)

    for (cl = rb->bufs; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body old buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %z",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = in; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                       "http body new buf t:%d f:%d %p, pos %p, size: %z "
                       "file: %O, size: %z",
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

#endif

    /* TODO: coalesce neighbouring buffers */

	//把数据接到rb->bufs后面
    if (ngx_chain_add_copy(r->pool, &rb->bufs, in) != NGX_OK)
	{
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}
