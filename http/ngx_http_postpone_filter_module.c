
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static ngx_int_t ngx_http_postpone_filter_add(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_postpone_filter_init(ngx_conf_t *cf);


static ngx_http_module_t  ngx_http_postpone_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_postpone_filter_init,         /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_postpone_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_postpone_filter_module_ctx,  /* module context */
    NULL,                                  /* module directives */
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


static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_int_t ngx_http_postpone_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_connection_t              *c;
    ngx_http_postponed_request_t  *pr;

    c = r->connection;//c是nginx与下游客户端间的连接,c->data保存的是原始请求

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, c->log, 0,"http postpone filter \"%V?%V\" %p", &r->uri, &r->args, in);

    /*如果当前请求不是排在最前面，因此不能向out_chain写入数据 */
    if (r != c->data) 
	{
    	/*如果待发送的in包不空,调用ngx_http_postpone_filter_add则把in加到postponed链表中属于当前请求的
    	 * ngx_http_postponed_request_t结构体的out链表中，同时返回NGX_OK，这意味着本次不会把包体发给客户端*/
        if (in) 
		{
            ngx_http_postpone_filter_add(r, in);
            return NGX_OK;
        }

#if 0
        /* TODO: SSI may pass NULL */
        ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                      "http postpone filter NULL inactive request",
                      &r->uri, &r->args);
#endif

        return NGX_OK;//如果当前请求是子请求，而in包体又为空，那么直接返回
    }

    /* 以下是表示当前请求正好排在最前面的情况 */

    /*如果postponed为空，表示没有子请求，也没有之前缓存的数据，那么，有数据就发，没有就直接返回*/
    if (r->postponed == NULL) 
	{
        if (in || c->buffered) 
		{//调用下一个HTTP过滤模块继续处理in包体即可。如果没有错误的话，就会开始向下游客户发送响应
            return ngx_http_next_body_filter(r->main, in);
        }

        return NGX_OK;
    }

    /* 以下是表示当前请求正好排在最前面但其postponed不为空的情况*/

    /*至此，说明postponed链表中是有子请求产生的响应需要转发的(即in既不是子请求，而且又有子请求需要发送)，可以先把in包体加到待转发响应
     * 的末尾*/
    if (in)
	{
        ngx_http_postpone_filter_add(r, in);
    }

    //循环处理postponed链表中所有子请求待转发的包体
    do 
	{
        pr = r->postponed;

        /* pr->request不为空，表示当前节点是子请求，则加入到原始请求的post_requests队列中，等待HTTP框架下次调用这个请求时再处理*/
        if (pr->request) 
		{
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter wake \"%V?%V\"",
                           &pr->request->uri, &pr->request->args);
            /* 先把该请求对象从父请求的postponed链表里移除*/
            r->postponed = pr->next;

            /* 把排列最前的请求对象改为该氢气 */
            c->data = pr->request;

            /* 把该请求加入到待处理链表r->main->posted_requests里，由ngx_http_run_posted_requests()调用出发子请求执行*/
            return ngx_http_post_request(pr->request, NULL);
        }

        /* pr->request为空，表示当前节点是数据，不是子请求 */

        if (pr->out == NULL) 
		{
            ngx_log_error(NGX_LOG_ALERT, c->log, 0,
                          "http postpone filter NULL output",
                          &r->uri, &r->args);

        } 
		else
		{
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http postpone filter output \"%V?%V\"",
                           &r->uri, &r->args);
            //调用下一个HTTP过滤模块转发out链表中保存的待转发的包体
            if (ngx_http_next_body_filter(r->main, pr->out) == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }

        r->postponed = pr->next;//遍历完postponed链表

    } while (r->postponed);

    return NGX_OK;
}


static ngx_int_t ngx_http_postpone_filter_add(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_http_postponed_request_t  *pr, **ppr;

    if (r->postponed) {

    	//pr指向链表的末尾
        for (pr = r->postponed; pr->next; pr = pr->next) { /* void */ }

        /*判断postponed链表末尾的ngx_http_postponed_request_t结构体存放的是否就是数据，如果是则把数据直接添加进去*/
        if (pr->request == NULL) {
            goto found;
        }

        //如果不是，在链表末尾新建一个对应的ngx_http_postponed_request_t结构体来存放该数据
        ppr = &pr->next;

    } else {
        ppr = &r->postponed;
    }

    pr = ngx_palloc(r->pool, sizeof(ngx_http_postponed_request_t));
    if (pr == NULL) {
        return NGX_ERROR;
    }

    *ppr = pr;

    pr->request = NULL;
    pr->out = NULL;
    pr->next = NULL;

found:

    if (ngx_chain_add_copy(r->pool, &pr->out, in) == NGX_OK) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_http_postpone_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_postpone_filter;

    return NGX_OK;
}
