
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_PIPE_H_INCLUDED_
#define _NGX_EVENT_PIPE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct ngx_event_pipe_s  ngx_event_pipe_t;

typedef ngx_int_t (*ngx_event_pipe_input_filter_pt)(ngx_event_pipe_t *p,ngx_buf_t *buf);//处理接收自上游的包体的回调方法原型
typedef ngx_int_t (*ngx_event_pipe_output_filter_pt)(void *data,ngx_chain_t *chain);//向下游发送响应的回调方法的原型


struct ngx_event_pipe_s 
{
    ngx_connection_t  *upstream;//与上游服务期间的连接
    ngx_connection_t  *downstream;//与下游客户端之间的连接

	/* 直接接收自上游服务器的缓冲区链表，注意，这个链表中的顺序是逆序的，也就是说，链表前端的ngx_buf_t缓冲区指向的是后
	接收到的响应。因此，该链表仅在接收响应时使用*/
    ngx_chain_t       *free_raw_bufs;

	/* 表示接收到的上游缓冲区。通常，in在input_filter方法中设置，可参考ngx_pipe_copy_input_filter方法，它会
	将接收到的缓冲区设置到in链表中*/
    ngx_chain_t       *in;

    ngx_chain_t      **last_in;//指向刚刚接收到的一个缓冲区

	/* 保存着将要发送给客户端的缓冲区链表，在写入临时文件成功时，会把in链表中写入文件的缓冲区添加到out中 */
    ngx_chain_t       *out;
	
    ngx_chain_t       *free;//等待释放的缓冲区

	/* 表示上次调用ngx_http_output_filter方法发送响应时没有发送完的缓冲区链表。这个链表中的缓冲区已经保存到请求
	的out链表中，busy仅用于记录还有多大的响应正等待发送*/
    ngx_chain_t       *busy;

    /* 处理接收到的来自上游服务器的响应数据时所需要执行的回调函数，一般使用upstream机制默认提供的
     * ngx_event_pipe_copy_input_filter方法作为input_filter.对于fastcgi模块，使用的是
     * ngx_http_fastcgi_input_filter()对后台服务器的响应数据进行的过滤回调
    */
    ngx_event_pipe_input_filter_pt    input_filter;
    void                             *input_ctx;//用于input_filter方法的成员，一般将它设置为ngx_http_request_t结构体的地址

	/* 表示向下游发送响应的方法，默认使用ngx_http_output_filter方法 */
    ngx_event_pipe_output_filter_pt   output_filter;
    void                             *output_ctx;//指向ngx_http_request_t结构体

    unsigned           read:1;//为1时表示当前已经读取到上游的响应
    unsigned           cacheable:1;//为1表示启用文件缓存
    unsigned           single_buf:1;//为1表示接收上游响应时一次只能接收一个ngx_buf_t缓冲区

	/* 为1表示一旦不再接收上游响应包体，将尽可能立刻释放缓冲区。所谓尽可能是指，一旦这个缓冲区没有被引用，如
	没有用于写临时文件或者用于向下游客户端释放，就把缓冲区指向的内存释放给pool内存池*/
    unsigned           free_bufs:1;

	/* 提供给HTTP模块在input_filter方法中使用的标志位，表示nginx与上游间的交互已经结束，如果HTTP模块在解析包体时，
	认为从业务上需要结束与上游间的连接，可以把该标志位置为1 */
    unsigned           upstream_done:1;

	/* nginx与上游服务器之间的连接出现错误时，该标志位为1，一般当接收上游响应超时或者调用recv出错时，把该标志位置为1 */
    unsigned           upstream_error:1;

	/* 表示与上游的连接状态，为1时表示与上游的连接已经关闭 */
    unsigned           upstream_eof:1;
	
	/* 表示暂时阻塞住读取上游响应的流程，期待通过向下游发送响应来清理出空闲的缓冲区，再用空出的缓冲区接收响应。也就是说，该标志位为1时
	会在ngx_event_pipe方法的循环中先调用ngx_pipe_write_to_downstream方法发送响应，然后再调用ngx_event_pipe_read_upstream方法读取上游响应*/
    unsigned           upstream_blocked:1;
    unsigned           downstream_done:1;
    unsigned           downstream_error:1;//为1时表示nginx与下游客户端间的连接出现错误

	/* 为1时表示会复用临时文件中曾经使用过的空间，不建议将其置为1，它是由ngx_http_upstream_conf_t中的同名成员赋值的 */
    unsigned           cyclic_temp_file:1;

    ngx_int_t          allocated;//表示已经分配的缓冲区数目。收到bufs.num成员的限制

	/* 记录了接收上游响应的内存缓冲区大小，其中bufs.size表示每个缓冲区的大小，而bufs.num表示最多可以有的缓冲区个数 */
    ngx_bufs_t         bufs;
    ngx_buf_tag_t      tag;//用于设置、比较缓冲区链表中ngx_buf_t结构体的tag标志位

	/* 设置busy缓冲区中待发送的响应长度触发值，当达到busy_size长度时，必须等待busy缓冲区发送了足够的内容时，
	才能继续发送out和in缓冲区中的内容*/
    ssize_t            busy_size;

    off_t              read_length;//已经接收到的上游包体的长度
    off_t              length;

    off_t              max_temp_file_size;//表示临时文件的最大长度
    ssize_t            temp_file_write_size;//一次写入文件时的最大长度

    ngx_msec_t         read_timeout;//读取上游响应的超时时间
    ngx_msec_t         send_timeout;//向下游发送响应的超时时间
    ssize_t            send_lowat;//向下游发送响应时，TCP连接中设置的send_lowat水位

    ngx_pool_t        *pool;//用于分配内存缓冲区的连接池对象
    ngx_log_t         *log;

    ngx_chain_t       *preread_bufs;//表示在接收上游服务器响应头部阶段，已经读取到的响应包体
    size_t             preread_size;//preread_bufs的长度
    ngx_buf_t         *buf_to_file;

    ngx_temp_file_t   *temp_file;//存放上游响应的临时文件，最大长度由max_temp_file_size成员限制

    /* STUB */ int     num;//已经使用的ngx_buf_t缓冲区数目
};


ngx_int_t ngx_event_pipe(ngx_event_pipe_t *p, ngx_int_t do_write);
ngx_int_t ngx_event_pipe_copy_input_filter(ngx_event_pipe_t *p, ngx_buf_t *buf);
ngx_int_t ngx_event_pipe_add_free_buf(ngx_event_pipe_t *p, ngx_buf_t *b);


#endif /* _NGX_EVENT_PIPE_H_INCLUDED_ */
