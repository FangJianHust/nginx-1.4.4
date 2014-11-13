﻿
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;
/* ngx_buf_t是Nginx处理大数据的关键数据结构，它既应用于内存数据，也应用于磁盘数据 */
struct ngx_buf_s
{
	/* pos通常用来告诉使用者本次应该从pos这个位置开始处理内存中的数据，这样设置是因为
	同一个ngx_buf_t可能被多次反复处理。当然，pos的含义是由使用它的模块定义的 */
    u_char          *pos;
	/* 通常表示有效的内容到此为止，注意，pos和last之间的内存是希望nginx处理的内容 */
    u_char          *last;
	/* 处理文件时，file_pos与file_last的含义与处理内存时的pos和last的相同，le_pos表示将要处理的文件位置，
	file_last表示截止的文件位置 */
    off_t            file_pos;
    off_t            file_last;
    u_char          *start; /* start of buffer：如果ngx_buf_t用于内存，那么start指向这段内存的起始地址 */
    u_char          *end;   /* end of buffer：与start对应，指向缓冲区的末尾 */
	/*表示当前缓冲区的类型，例如由哪个模块使用就指向这个模块ngx_module_t变量的地址*/
    ngx_buf_tag_t    tag;
    ngx_file_t      *file;//引用的文件
    ngx_buf_t       *shadow;
	//临时内存标志，为1表示数据在内存中且这段内存可以修改
	unsigned         temporary:1;
    /* the buf's content is in a memory cache or in a read only memory and must not be changed */

	//为1时表示数据在内存中且这段内存不可以修改
    unsigned         memory:1;
    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1;//为1时表示这段内存是用mman()系统调用映射过来的，不可以被修改
    unsigned         recycled:1;//为1时表示可回收
    unsigned         in_file:1;//为1时表示这段缓冲区处理的是文件而不是内存
	//为1时表示需要执行flush
    unsigned         flush:1;
	/* 对于操作这块缓冲区时是否使用同步方式，需要谨慎考虑，这可能会阻塞Nginx进程，Nginx中所有的操作几乎都是异步的，这是它支持高并发的关键。有些框架代码在sync为1时可能会有阻塞的方式进行I/O操作，它的意义视使用它的Nginx模块而定 */
    unsigned         sync:1;
	/* 表示是否是最后一块缓冲区，因为ngx_buf_t可以由ngx_chain_t链表串联起来，因此，当last_buf为1时，表示当前是最后一块待处理的缓冲区 */
    unsigned         last_buf:1;
	//表示是否时ngx_chain_t中最后一块缓冲区
    unsigned         last_in_chain:1;
    unsigned         last_shadow:1;
	//表示当前缓冲区是否属于临时文件
    unsigned         temp_file:1;
    /* STUB */ int   num;
};


struct ngx_chain_s {
    ngx_buf_t    *buf;
    ngx_chain_t  *next;
};


typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

#if (NGX_HAVE_FILE_AIO)
typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);
#endif

struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;
    ngx_chain_t                 *in;
    ngx_chain_t                 *free;
    ngx_chain_t                 *busy;

    unsigned                     sendfile:1;
    unsigned                     directio:1;
#if (NGX_HAVE_ALIGNED_DIRECTIO)
    unsigned                     unaligned:1;
#endif
    unsigned                     need_in_memory:1;
    unsigned                     need_in_temp:1;
#if (NGX_HAVE_FILE_AIO)
    unsigned                     aio:1;

    ngx_output_chain_aio_pt      aio_handler;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;
    ngx_int_t                    allocated;
    ngx_bufs_t                   bufs;
    ngx_buf_tag_t                tag;

    ngx_output_chain_filter_pt   output_filter;
    void                        *filter_ctx;
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
#define ngx_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_pool_t *p, ngx_chain_t **free,
    ngx_chain_t **busy, ngx_chain_t **out, ngx_buf_tag_t tag);


#endif /* _NGX_BUF_H_INCLUDED_ */
