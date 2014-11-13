
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_pipe.h>


static ngx_int_t ngx_event_pipe_read_upstream(ngx_event_pipe_t *p);
static ngx_int_t ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p);

static ngx_int_t ngx_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p);
static ngx_inline void ngx_event_pipe_remove_shadow_links(ngx_buf_t *buf);
static ngx_int_t ngx_event_pipe_drain_chains(ngx_event_pipe_t *p);

/* 实现缓存转发响应功能,其中p是负责转发响应的ngx_event_pipe_t结构体，do_write为1时表示需要向下游客户端发送响应，
为0时表示仅需要由上游客户端接收响应 */
ngx_int_t ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write)
{
    u_int         flags;
    ngx_int_t     rc;
    ngx_event_t  *rev, *wev;

    for ( ;; ) 
	{
        if (do_write) 
		{
            p->log->action = "sending to client";

            rc = ngx_event_pipe_write_to_downstream(p);//向下游客户端发送响应包体

            if (rc == NGX_ABORT) 
			{
                return NGX_ABORT;//表示请求处理失败
            }

            if (rc == NGX_BUSY) 
			{
                return NGX_OK;//表示本次暂不往下执行
            }
        }

        p->read = 0;
        p->upstream_blocked = 0;

        p->log->action = "reading upstream";

		/* 读取上游服务器的响应 */
        if (ngx_event_pipe_read_upstream(p) == NGX_ABORT)
		{
            return NGX_ABORT;
        }

        if (!p->read && !p->upstream_blocked) {
            break;
        }

		/* 需要向下游发送读到的响应 */
        do_write = 1;
    }

    if (p->upstream->fd != -1) {
        rev = p->upstream->read;

        flags = (rev->eof || rev->error) ? NGX_CLOSE_EVENT : 0;

		/* 将上游的读事件添加到epoll中，等待下一次接收到上游响应的事件出现 */
        if (ngx_handle_read_event(rev, flags) != NGX_OK) 
		{
            return NGX_ABORT;
        }

        if (rev->active && !rev->ready) 
		{
            ngx_add_timer(rev, p->read_timeout);

        } else if (rev->timer_set) {
            ngx_del_timer(rev);
        }
    }

    if (p->downstream->fd != -1 && p->downstream->data == p->output_ctx) {
        wev = p->downstream->write;

		/* 将下游的写事件添加到epoll中，等待下一次可以向下游发送响应的事件出现 */
        if (ngx_handle_write_event(wev, p->send_lowat) != NGX_OK) 
		{
            return NGX_ABORT;
        }

        if (!wev->delayed) {
            if (wev->active && !wev->ready) {
                ngx_add_timer(wev, p->send_timeout);

            } else if (wev->timer_set) {
                ngx_del_timer(wev);
            }
        }
    }

    return NGX_OK;
}

/* 负责接收上游的响应，在这个过程中会涉及以下4种情况：1)接收响应头部时可能接收到部分包体；2)如果没有达到bufs.num上限，那么可以分配
bufs.size大小的内存块充当接收缓冲区；3)如果恰好下游的连接处于可惜状态，则应该优先发送响应来清理出空闲缓冲区；4)如果缓冲区全部写满，
则应该写入临时文件 */
static ngx_int_t ngx_event_pipe_read_upstream(ngx_event_pipe_t *p)
{
    ssize_t       n, size;
    ngx_int_t     rc;
    ngx_buf_t    *b;
    ngx_chain_t  *chain, *cl, *ln;

    if (p->upstream_eof || p->upstream_error || p->upstream_done) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe read upstream: %d", p->upstream->read->ready);

    for ( ;; ) 
	{
		/* 检查上游连接是否结束，以及与上游的读事件是否已经准备就绪，下面3个标志位的任一个为1都表示上游连接需要结束 */
        if (p->upstream_eof || p->upstream_error || p->upstream_done) {
            break;
        }

		/* 如果读事件的ready为0，说明没有上游响应可以接收；preread_bufs预读缓冲区为空，表示接收包头时没有收到包体或者收到过包体已经
		 处理过了 */
        if (p->preread_bufs == NULL && !p->upstream->read->ready) 
		{
            break;
        }
		/* 将read置为1，表示接收到的包体待处理 */
        if (p->preread_bufs) {

            /* use the pre-read bufs if they exist */

            chain = p->preread_bufs;

            //将包体设置为已经处理过了
            p->preread_bufs = NULL;
            n = p->preread_size;

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe preread: %z", n);

            if (n) {
                p->read = 1;
            }

        } else {

#if (NGX_HAVE_KQUEUE)

            /*
             * kqueue notifies about the end of file or a pending error.
             * This test allows not to allocate a buf on these conditions
             * and not to call c->recv_chain().
             */

            if (p->upstream->read->available == 0
                && p->upstream->read->pending_eof)
            {
                p->upstream->read->ready = 0;
                p->upstream->read->eof = 1;
                p->upstream_eof = 1;
                p->read = 1;

                if (p->upstream->read->kq_errno) {
                    p->upstream->read->error = 1;
                    p->upstream_error = 1;
                    p->upstream_eof = 0;

                    ngx_log_error(NGX_LOG_ERR, p->log,
                                  p->upstream->read->kq_errno,
                                  "kevent() reported that upstream "
                                  "closed connection");
                }

                break;
            }
#endif
			/* 从接收到的缓冲区链表中取出一块ngx_buf_t缓冲区 */

			/* free_raw_bufs用来表示一次ngx_event_pipe_read_upstream方法调用过程中接收到的上游响应，如果该缓冲区不为空，
			 那么可以直接使用 ，注意该链表中缓冲区 的顺序与接收顺序是相反的，每次使用缓冲区接收到上游发来的响应后，都会把该缓冲区添加到
			 free_raw_bufs末尾*/
            if (p->free_raw_bufs) 
			{
                /* use the free bufs if they exist */

                chain = p->free_raw_bufs;
                if (p->single_buf) {
                    p->free_raw_bufs = p->free_raw_bufs->next;
                    chain->next = NULL;
                } else {
                    p->free_raw_bufs = NULL;
                }

            } 
            //缓冲区已空，并且已经分配的缓冲区数量小于bufs.num
			else if (p->allocated < p->bufs.num) 
			{
                /* allocate a new buf if it's still allowed */

                b = ngx_create_temp_buf(p->pool, p->bufs.size);//可以从内存池中分配到一块新的缓冲区
                if (b == NULL) {
                    return NGX_ABORT;
                }

                p->allocated++;

                chain = ngx_alloc_chain_link(p->pool);
                if (chain == NULL) {
                    return NGX_ABORT;
                }

                chain->buf = b;
                chain->next = NULL;

            }
			/* 分配的缓冲区已经达到上限 */
			else if (!p->cacheable
                       && p->downstream->data == p->output_ctx
                       && p->downstream->write->ready//可以向下游发送响应
                       && !p->downstream->write->delayed /* 表示并不是因为限速才使得写事件准备好 */)
            {//应当由向下游发送响应来释放缓冲区，以期可以使用释放出的空闲缓冲区再接收上游响应
                /*
                 * if the bufs are not needed to be saved in a cache and
                 * a downstream is ready then write the bufs to a downstream
                 */

                p->upstream_blocked = 1;

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe downstream ready");

                break;

            } 
			/* 当不能通过向下游发送响应来释放缓冲区时，如果临时文件中已经写入的响应内容长度没有达到配置上限 */
			else if (p->cacheable|| p->temp_file->offset < p->max_temp_file_size)
            {

                /*
                 * if it is allowed, then save some bufs from r->in
                 * to a temporary file, and add them to a r->out chain
                 */

                rc = ngx_event_pipe_write_chain_to_temp_file(p);//将响应文件写入临时文件中

                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe temp offset: %O", p->temp_file->offset);

                if (rc == NGX_BUSY) {
                    break;
                }

                if (rc == NGX_AGAIN) {
                    if (ngx_event_flags & NGX_USE_LEVEL_EVENT
                        && p->upstream->read->active
                        && p->upstream->read->ready)
                    {
                        if (ngx_del_event(p->upstream->read, NGX_READ_EVENT, 0)
                            == NGX_ERROR)
                        {
                            return NGX_ABORT;
                        }
                    }
                }

                if (rc != NGX_OK) {
                    return rc;
                }

                chain = p->free_raw_bufs;
                if (p->single_buf) {
                    p->free_raw_bufs = p->free_raw_bufs->next;
                    chain->next = NULL;
                } else {
                    p->free_raw_bufs = NULL;
                }

            } else {

                /* there are no bufs to read in */

                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "no pipe bufs to read in");

                break;
            }

            //接收上游的响应
            n = p->upstream->recv_chain(p->upstream, chain);

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe recv chain: %z", n);

            if (p->free_raw_bufs) 
			{
                chain->next = p->free_raw_bufs;//将新接收到的缓冲区置到free_raw_bufs链表的最后
            }
            p->free_raw_bufs = chain;

            if (n == NGX_ERROR) {
                p->upstream_error = 1;
                return NGX_ERROR;
            }

            if (n == NGX_AGAIN)
			{
                if (p->single_buf) 
				{
                    ngx_event_pipe_remove_shadow_links(chain->buf);
                }

                break;
            }

            p->read = 1;

            if (n == 0) {
                p->upstream_eof = 1;
                break;
            }
        }

        p->read_length += n;
        cl = chain;
        p->free_raw_bufs = NULL;

        while (cl && n > 0)
		{
			//将这块缓冲区中的shadow域释放掉，因为刚刚接收到缓冲区，必然不存在多次引用的情况，所以shadow成员要指向空指针
            ngx_event_pipe_remove_shadow_links(cl->buf);

			/* 检查本次读取到的包体是否大于或等于缓冲区的剩余空间大小，这一步的意义在于，如果当前接收到的长度小于缓冲区
			长度，则说明这个缓冲区还可以再次接收响应，否则，这个缓冲区已满，则应该调用input_filter方法处理，当然，默认的
			input_filter方法就是ngx_event_pipe_copy_filter，它所做的事情就是在in链表中添加这个缓冲区，然后继续循环执行，
			遍历本次收到的所有缓冲区*/
            size = cl->buf->end - cl->buf->last;

            if (n >= size)
			{
                cl->buf->last = cl->buf->end;

                /* STUB */ cl->buf->num = p->num++;

                //调用对应的过滤方法，对收到的后端服务器数据进行过滤
                if (p->input_filter(p, cl->buf) == NGX_ERROR) {
                    return NGX_ABORT;
                }

                n -= size;
                ln = cl;
                cl = cl->next;
                ngx_free_chain(p->pool, ln);

            } else {
                cl->buf->last += n;
                n = 0;
            }
        }

		/* 将本次接收到的缓冲区添加到free_raw_bufs链表末尾，继续执行大循环 */
        if (cl)
		{
            for (ln = cl; ln->next; ln = ln->next) { /* void */ }

            ln->next = p->free_raw_bufs;
            p->free_raw_bufs = cl;
        }
    }

#if (NGX_DEBUG)

    for (cl = p->busy; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf busy s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %z",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->out; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf out  s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %z",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->in; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf in   s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %z",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = p->free_raw_bufs; cl; cl = cl->next) {
        ngx_log_debug8(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe buf free s:%d t:%d f:%d "
                       "%p, pos %p, size: %z "
                       "file: %O, size: %z",
                       (cl->buf->shadow ? 1 : 0),
                       cl->buf->temporary, cl->buf->in_file,
                       cl->buf->start, cl->buf->pos,
                       cl->buf->last - cl->buf->pos,
                       cl->buf->file_pos,
                       cl->buf->file_last - cl->buf->file_pos);
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe length: %O", p->length);

#endif

    if (p->free_raw_bufs && p->length != -1) {
        cl = p->free_raw_bufs;

        if (cl->buf->last - cl->buf->pos >= p->length) {

            p->free_raw_bufs = cl->next;

            /* STUB */ cl->buf->num = p->num++;

            if (p->input_filter(p, cl->buf) == NGX_ERROR) {
                 return NGX_ABORT;
            }

            ngx_free_chain(p->pool, cl);
        }
    }

    if (p->length == 0) {
        p->upstream_done = 1;
        p->read = 1;
    }

	/* 两个标志位任一个为1，说明上游连接已经结束，这时如果free_raw_bufs缓冲区链表不为空 */
    if ((p->upstream_eof || p->upstream_error) && p->free_raw_bufs) 
	{
        /* STUB */ p->free_raw_bufs->buf->num = p->num++;

		/* 再次调用input_filter方法处理free_raw_bufs中的缓冲区 */
        if (p->input_filter(p, p->free_raw_bufs->buf) == NGX_ERROR) 
		{
            return NGX_ABORT;
        }

        p->free_raw_bufs = p->free_raw_bufs->next;

        if (p->free_bufs && p->buf_to_file == NULL) {
            for (cl = p->free_raw_bufs; cl; cl = cl->next) {
                if (cl->buf->shadow == NULL) 
				{
                    ngx_pfree(p->pool, cl->buf->start);//释放shadow域为空的缓冲区
                }
            }
        }
    }

    if (p->cacheable && p->in) {
        if (ngx_event_pipe_write_chain_to_temp_file(p) == NGX_ABORT) {
            return NGX_ABORT;
        }
    }

    return NGX_OK;
}

/* 负责把in链表和out链表中管理的缓冲区发送给客户端，因为out链表中的缓冲区内容在响应中的位置要比in链表靠前，所以out需要优先发送给下游 */
static ngx_int_t ngx_event_pipe_write_to_downstream(ngx_event_pipe_t *p)
{
    u_char            *prev;
    size_t             bsize;
    ngx_int_t          rc;
    ngx_uint_t         flush, flushed, prev_last_shadow;
    ngx_chain_t       *out, **ll, *cl, file;
    ngx_connection_t  *downstream;

    downstream = p->downstream;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                   "pipe write downstream: %d", downstream->write->ready);

    flushed = 0;

    for ( ;; ) 
	{
        if (p->downstream_error) {
            return ngx_event_pipe_drain_chains(p);
        }

		/* 检查上游连接是否结束，下面三个任何一个为1表示上游连接不会再收到响应了 */
        if (p->upstream_eof || p->upstream_error || p->upstream_done) 
		{
            /* pass the p->out and p->in chains to the output filter */

            for (cl = p->busy; cl; cl = cl->next) {
                cl->buf->recycled = 0;
            }

            if (p->out) 
			{
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush out");

                for (cl = p->out; cl; cl = cl->next) {
                    cl->buf->recycled = 0;
                }

                //把out链表中的缓冲区发送到下游客户端
                rc = p->output_filter(p->output_ctx, p->out);

                if (rc == NGX_ERROR) {
                    p->downstream_error = 1;
                    return ngx_event_pipe_drain_chains(p);
                }

                p->out = NULL;
            }

            if (p->in) 
			{
                ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write downstream flush in");

                for (cl = p->in; cl; cl = cl->next) {
                    cl->buf->recycled = 0;
                }

                rc = p->output_filter(p->output_ctx, p->in);//把in链表中的缓冲区发送到下游客户端

                if (rc == NGX_ERROR) {
                    p->downstream_error = 1;
                    return ngx_event_pipe_drain_chains(p);
                }

                p->in = NULL;
            }

            if (p->cacheable && p->buf_to_file) {

                file.buf = p->buf_to_file;
                file.next = NULL;

                if (ngx_write_chain_to_temp_file(p->temp_file, &file)
                    == NGX_ERROR)
                {
                    return NGX_ABORT;
                }
            }

            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe write downstream done");

            /* TODO: free unused bufs */

            p->downstream_done = 1;
            break;
        }

        if (downstream->data != p->output_ctx
            || !downstream->write->ready
            || downstream->write->delayed)
        {
            break;
        }

        /* bsize is the size of the busy recycled bufs */

        prev = NULL;
        bsize = 0;

		/* 计算busy缓冲区中待发送的响应长度，检查是否超过busy_size配置 */
        for (cl = p->busy; cl; cl = cl->next) {

            if (cl->buf->recycled) {
                if (prev == cl->buf->start) {
                    continue;
                }

                bsize += cl->buf->end - cl->buf->start;
                prev = cl->buf->start;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write busy: %uz", bsize);

        out = NULL;

		/* 当ngx_http_request_t结构体中out缓冲区中待发送内容已经超过了busy_size，就不再发送out和in缓冲区的内容，
		跳到flush处，优先把ngx_http_request_t结构体中的out中的内容发送出去*/
        if (bsize >= (size_t) p->busy_size) 
		{
            flush = 1;
            goto flush;
        }

        flush = 0;
        ll = NULL;
        prev_last_shadow = 1;

		/* 发送out或者in缓冲区中的内容 */
        for ( ;; ) 
		{
            if (p->out) 
			{
                cl = p->out;//取出out链表首部的第一个缓冲区

                if (cl->buf->recycled) {
                    ngx_log_error(NGX_LOG_ALERT, p->log, 0,
                                  "recycled buffer in pipe out chain");
                }

                p->out = p->out->next;//out指向下一个ngx_chain_t元素

            } 
			else if (!p->cacheable && p->in) 
			{//取出in链表首部的第一个缓冲区准备发送，和out类似
                cl = p->in;

                ngx_log_debug3(NGX_LOG_DEBUG_EVENT, p->log, 0,
                               "pipe write buf ls:%d %p %z",
                               cl->buf->last_shadow,
                               cl->buf->pos,
                               cl->buf->last - cl->buf->pos);

                if (cl->buf->recycled && prev_last_shadow) {
                    if (bsize + cl->buf->end - cl->buf->start > p->busy_size) {
                        flush = 1;
                        break;
                    }

                    bsize += cl->buf->end - cl->buf->start;
                }

                prev_last_shadow = cl->buf->last_shadow;

                p->in = p->in->next;

            }
			else
			{//out和in都为空，说明这次调用中没有需要发送的响应
                break;
            }

            cl->next = NULL;

            if (out) {
                *ll = cl;
            } else {
                out = cl;
            }
            ll = &cl->next;
        }

    flush:

        ngx_log_debug2(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe write: out:%p, f:%d", out, flush);

		/*检查out链表以及之前各个步骤中是否有需要发送的内容  */
        if (out == NULL) 
		{//没有待发送的内容
            if (!flush) 
			{
                break;
            }

            /* a workaround for AIO */
            if (flushed++ > 10) {
                return NGX_BUSY;
            }
        }

		/* 由需要发送的内容 */
        rc = p->output_filter(p->output_ctx, out);//发送

        ngx_chain_update_chains(p->pool, &p->free, &p->busy, &out, p->tag);//更新free、busy、out缓冲区

        if (rc == NGX_ERROR) 
		{
            p->downstream_error = 1;
            return ngx_event_pipe_drain_chains(p);
        }

		/* 遍历free链表中的缓冲区，释放缓冲区中的shadow域，这样，这些暂时不使用的缓冲区才可以继续用来接收新的来自上游服务器的响应 */
        for (cl = p->free; cl; cl = cl->next) {

            if (cl->buf->temp_file) {
                if (p->cacheable || !p->cyclic_temp_file) {
                    continue;
                }

                /* reset p->temp_offset if all bufs had been sent */

                if (cl->buf->file_last == p->temp_file->offset) {
                    p->temp_file->offset = 0;
                }
            }

            /* TODO: free buf if p->free_bufs && upstream done */

            /* add the free shadow raw buf to p->free_raw_bufs */

            if (cl->buf->last_shadow) {
                if (ngx_event_pipe_add_free_buf(p, cl->buf->shadow) != NGX_OK) {
                    return NGX_ABORT;
                }

                cl->buf->last_shadow = 0;
            }

            cl->buf->shadow = NULL;
        }
    }

    return NGX_OK;
}


static ngx_int_t ngx_event_pipe_write_chain_to_temp_file(ngx_event_pipe_t *p)
{
    ssize_t       size, bsize, n;
    ngx_buf_t    *b;
    ngx_uint_t    prev_last_shadow;
    ngx_chain_t  *cl, *tl, *next, *out, **ll, **last_out, **last_free, fl;

    if (p->buf_to_file) {
        fl.buf = p->buf_to_file;
        fl.next = p->in;
        out = &fl;

    } else {
        out = p->in;
    }

    if (!p->cacheable) {

        size = 0;
        cl = out;
        ll = NULL;
        prev_last_shadow = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0,
                       "pipe offset: %O", p->temp_file->offset);

        do {
            bsize = cl->buf->last - cl->buf->pos;

            ngx_log_debug4(NGX_LOG_DEBUG_EVENT, p->log, 0,
                           "pipe buf ls:%d %p, pos %p, size: %z",
                           cl->buf->last_shadow, cl->buf->start,
                           cl->buf->pos, bsize);

            if (prev_last_shadow
                && ((size + bsize > p->temp_file_write_size)
                    || (p->temp_file->offset + size + bsize
                        > p->max_temp_file_size)))
            {
                break;
            }

            prev_last_shadow = cl->buf->last_shadow;

            size += bsize;
            ll = &cl->next;
            cl = cl->next;

        } while (cl);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "size: %z", size);

        if (ll == NULL) {
            return NGX_BUSY;
        }

        if (cl) {
           p->in = cl;
           *ll = NULL;

        } else {
           p->in = NULL;
           p->last_in = &p->in;
        }

    } else {
        p->in = NULL;
        p->last_in = &p->in;
    }

    n = ngx_write_chain_to_temp_file(p->temp_file, out);

    if (n == NGX_ERROR) {
        return NGX_ABORT;
    }

    if (p->buf_to_file) {
        p->temp_file->offset = p->buf_to_file->last - p->buf_to_file->pos;
        n -= p->buf_to_file->last - p->buf_to_file->pos;
        p->buf_to_file = NULL;
        out = out->next;
    }

    if (n > 0) {
        /* update previous buffer or add new buffer */

        if (p->out) {
            for (cl = p->out; cl->next; cl = cl->next) { /* void */ }

            b = cl->buf;

            if (b->file_last == p->temp_file->offset) {
                p->temp_file->offset += n;
                b->file_last = p->temp_file->offset;
                goto free;
            }

            last_out = &cl->next;

        } else {
            last_out = &p->out;
        }

        cl = ngx_chain_get_free_buf(p->pool, &p->free);
        if (cl == NULL) {
            return NGX_ABORT;
        }

        b = cl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->tag = p->tag;

        b->file = &p->temp_file->file;
        b->file_pos = p->temp_file->offset;
        p->temp_file->offset += n;
        b->file_last = p->temp_file->offset;

        b->in_file = 1;
        b->temp_file = 1;

        *last_out = cl;
    }

free:

    for (last_free = &p->free_raw_bufs;
         *last_free != NULL;
         last_free = &(*last_free)->next)
    {
        /* void */
    }

    for (cl = out; cl; cl = next) {
        next = cl->next;

        cl->next = p->free;
        p->free = cl;

        b = cl->buf;

        if (b->last_shadow) {

            tl = ngx_alloc_chain_link(p->pool);
            if (tl == NULL) {
                return NGX_ABORT;
            }

            tl->buf = b->shadow;
            tl->next = NULL;

            *last_free = tl;
            last_free = &tl->next;

            b->shadow->pos = b->shadow->start;
            b->shadow->last = b->shadow->start;

            ngx_event_pipe_remove_shadow_links(b->shadow);
        }
    }

    return NGX_OK;
}


/* the copy input filter */

ngx_int_t
ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    if (buf->pos == buf->last) {
        return NGX_OK;
    }

    if (p->free) {
        cl = p->free;
        b = cl->buf;
        p->free = cl->next;
        ngx_free_chain(p->pool, cl);

    } else {
        b = ngx_alloc_buf(p->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }
    }

    ngx_memcpy(b, buf, sizeof(ngx_buf_t));
    b->shadow = buf;
    b->tag = p->tag;
    b->last_shadow = 1;
    b->recycled = 1;
    buf->shadow = b;

    cl = ngx_alloc_chain_link(p->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = b;
    cl->next = NULL;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, p->log, 0, "input buf #%d", b->num);

    if (p->in) {
        *p->last_in = cl;
    } else {
        p->in = cl;
    }
    p->last_in = &cl->next;

    if (p->length == -1) {
        return NGX_OK;
    }

    p->length -= b->last - b->pos;

    return NGX_OK;
}


static ngx_inline void
ngx_event_pipe_remove_shadow_links(ngx_buf_t *buf)
{
    ngx_buf_t  *b, *next;

    b = buf->shadow;

    if (b == NULL) {
        return;
    }

    while (!b->last_shadow) {
        next = b->shadow;

        b->temporary = 0;
        b->recycled = 0;

        b->shadow = NULL;
        b = next;
    }

    b->temporary = 0;
    b->recycled = 0;
    b->last_shadow = 0;

    b->shadow = NULL;

    buf->shadow = NULL;
}


ngx_int_t
ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b)
{
    ngx_chain_t  *cl;

    cl = ngx_alloc_chain_link(p->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    if (p->buf_to_file && b->start == p->buf_to_file->start) {
        b->pos = p->buf_to_file->last;
        b->last = p->buf_to_file->last;

    } else {
        b->pos = b->start;
        b->last = b->start;
    }

    b->shadow = NULL;

    cl->buf = b;

    if (p->free_raw_bufs == NULL) {
        p->free_raw_bufs = cl;
        cl->next = NULL;

        return NGX_OK;
    }

    if (p->free_raw_bufs->buf->pos == p->free_raw_bufs->buf->last) {

        /* add the free buf to the list start */

        cl->next = p->free_raw_bufs;
        p->free_raw_bufs = cl;

        return NGX_OK;
    }

    /* the first free buf is partially filled, thus add the free buf after it */

    cl->next = p->free_raw_bufs->next;
    p->free_raw_bufs->next = cl;

    return NGX_OK;
}


static ngx_int_t
ngx_event_pipe_drain_chains(ngx_event_pipe_t *p)
{
    ngx_chain_t  *cl, *tl;

    for ( ;; ) {
        if (p->busy) {
            cl = p->busy;
            p->busy = NULL;

        } else if (p->out) {
            cl = p->out;
            p->out = NULL;

        } else if (p->in) {
            cl = p->in;
            p->in = NULL;

        } else {
            return NGX_OK;
        }

        while (cl) {
            if (cl->buf->last_shadow) {
                if (ngx_event_pipe_add_free_buf(p, cl->buf->shadow) != NGX_OK) {
                    return NGX_ABORT;
                }

                cl->buf->last_shadow = 0;
            }

            cl->buf->shadow = NULL;
            tl = cl->next;
            cl->next = p->free;
            p->free = cl;
            cl = tl;
        }
    }
}
