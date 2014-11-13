#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_static_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_static_init(ngx_conf_t *cf);

ngx_http_module_t  ngx_http_static_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_static_init,                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};

/* 从某种程度上来说，此模块可以算的上是“最正宗的”，“最古老”的content handler。因为本模块的作用就是读取磁盘上的静态文件，并把文件内容作为产生的输出 */
ngx_module_t  ngx_http_static_module = {
    NGX_MODULE_V1,
    &ngx_http_static_module_ctx,           /* module context */
    NULL,                                  /* module directives,不需要解析配置项 */
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

//该模块的处理函数
static ngx_int_t ngx_http_static_handler(ngx_http_request_t *r)
{
    u_char                    *last, *location;
    size_t                     root, len;
    ngx_str_t                  path;
    ngx_int_t                  rc;
    ngx_uint_t                 level;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;
    //首先查看客户端的请求类型
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST)))
    {
        return NGX_HTTP_NOT_ALLOWED;
    }
    /*其次是检查请求的url的结尾字符是不是斜杠‘/’，如果是说明请求的不是一个文件，给后续的handler去处理，比如后续的ngx_http_autoindex_handler
   （如果是请求的是一个目录下面，可以列出这个目录的文件），或者是ngx_http_index_handler（如果请求的路径下面有个默认的index文件，直接返回
   index文件的内容 */
    if (r->uri.data[r->uri.len - 1] == '/')
    {
        return NGX_DECLINED;//如果返回NGX_DECLINED，那么将按照顺序进入下一个处理方法，这个处理方法既可能属于当前阶段，也可能属于下一个阶段
    }
    log = r->connection->log;
    /* 然后接下来调用了一个ngx_http_map_uri_to_path函数，该函数的作用是把请求的http协议的路径转化成一个文件系统的路径 */
    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    path.len = last - path.data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http filename: \"%s\"", path.data);
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    ngx_memzero(&of, sizeof(ngx_open_file_info_t));
    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;
    /* 如果请求的文件是个symbol link，根据配置，是否允许符号链接，不允许返回错误 */
    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)!= NGX_OK)
    {
        switch (of.err)
        {
        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;
        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;
        default:
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }
        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found)
        {
            ngx_log_error(level, log, of.err, "%s \"%s\" failed", of.failed, path.data);
        }
        return rc;
    }
    r->root_tested = !r->error_page;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);
    /* 如果请求的是的名称是一个目录的名字，也返回错误 */
    if (of.is_dir)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");
        ngx_http_clear_location(r);
        r->headers_out.location = ngx_palloc(r->pool, sizeof(ngx_table_elt_t));
        if (r->headers_out.location == NULL)
        {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        len = r->uri.len + 1;
        if (!clcf->alias && clcf->root_lengths == NULL && r->args.len == 0)
        {
            location = path.data + clcf->root.len;
            *last = '/';
        }
        else
        {
            if (r->args.len)
            {
                len += r->args.len + 1;
            }
            location = ngx_pnalloc(r->pool, len);
            if (location == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            last = ngx_copy(location, r->uri.data, r->uri.len);
            *last = '/';
            if (r->args.len) {
                *++last = '?';
                ngx_memcpy(++last, r->args.data, r->args.len);
            }
        }
        /* we do not need to set the r->headers_out.location->hash and r->headers_out.location->key fields */
        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = location;
        return NGX_HTTP_MOVED_PERMANENTLY;
    }
#if !(NGX_WIN32) /* the not regular files are probably Unix specific */
    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0, "\"%s\" is not a regular file", path.data);
        return NGX_HTTP_NOT_FOUND;
    }

#endif
    if (r->method & NGX_HTTP_POST) {
        return NGX_HTTP_NOT_ALLOWED;
    }
    rc = ngx_http_discard_request_body(r);//丢弃包体
    if (rc != NGX_OK)
    {
        return rc;
    }
    log->action = "sending response to client";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;
    if (ngx_http_set_etag(r) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (ngx_http_set_content_type(r) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (r != r->main && of.size == 0)
    {
        return ngx_http_send_header(r);
    }
    r->allow_ranges = 1;
    /* we need to allocate all before the header would be sent */
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
    {
        return rc;
    }
    b->file_pos = 0;
    b->file_last = of.size;
    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;
    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;
    out.buf = b;
    out.next = NULL;
    /* 把产生的内容传递给后续的filter去处理*/
    return ngx_http_output_filter(r, &out);
}

static ngx_int_t ngx_http_static_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    //将当前模块的回调功能函数ngx_http_static_handler挂载到NGX_HTTP_CONTENT_PHASE阶段
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL)
    {
        return NGX_ERROR;
    }
    *h = ngx_http_static_handler;
    return NGX_OK;
}
