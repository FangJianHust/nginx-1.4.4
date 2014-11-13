
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000100
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000200
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00000400
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00000800
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404)

#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100


typedef struct {
    ngx_msec_t                       bl_time;
    ngx_uint_t                       bl_state;

    ngx_uint_t                       status;
    time_t                           response_sec;
    ngx_uint_t                       response_msec;
    off_t                            response_length;

    ngx_str_t                       *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;
                                             /* ngx_http_upstream_srv_conf_t */
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);


typedef struct {
    ngx_http_upstream_init_pt        init_upstream;
    ngx_http_upstream_init_peer_pt   init;
    void                            *data;
} ngx_http_upstream_peer_t;


typedef struct {
    ngx_addr_t                      *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;

    unsigned                         down:1;
    unsigned                         backup:1;
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020


struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_http_upstream_server_t */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    in_port_t                        default_port;
    ngx_uint_t                       no_port;  /* unsigned no_port:1 */
};


typedef struct {
    ngx_addr_t                      *addr;
    ngx_http_complex_value_t        *value;
} ngx_http_upstream_local_t;


typedef struct 
{
	/* 在ngx_http_upstream_t结构体中没有实现resolved成员时，该成员才有效，表示上游服务器的配置 */
    ngx_http_upstream_srv_conf_t    *upstream;

    ngx_msec_t                       connect_timeout;//连接上游服务器超时时间，毫秒
    ngx_msec_t                       send_timeout;//发送TCP包到上游服务器的超时时间，毫秒
    ngx_msec_t                       read_timeout;//接收TCP包到上游服务器的超时时间，毫秒
    ngx_msec_t                       timeout;

    size_t                           send_lowat;//TCP的SO_SNOLOWAT选项，表示发送缓冲区的下限

	/* 定义了接收头部缓冲区分配的内存大小(ngx_http_upstream_t中的buffer缓冲区)，当不转发响应给下游或者在
	buffering标志位为0的情况下转发响应时，它同样表示接收包体的缓冲区大小*/
    size_t                           buffer_size;

	/* 仅当buffering为1且向下游转发响应时生效，设置到ngx_event_pipe_t结构体的busu_size成员 */
    size_t                           busy_buffers_size;

	/* 在buffering为1时，如果上游速度快于下游速度，将有可能把来自上游的响应存储到临时文件中，而该成员指定了
	临时文件的最大长度，实际上，它将显示ngx_event_pipe_t结构体中temp_file*/
    size_t                           max_temp_file_size;

	/* 表示将缓冲区中的响应写入临时文件时一次写入字符流的最大长度 */
    size_t                           temp_file_write_size;

    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    ngx_bufs_t                       bufs;//以缓存响应的方法转发上游服务器的包体时所使用的内存大小

	/* 针对ngx_http_upstream_t结构体中保存解析完的包头的headers_in成员，ignore_headers可以按照二进制位
	使得upstream在转发包头时跳过对某些头部的处理，最多可以跳过32个需要跳过不予处理的头部，目前仅提供8个
	位用于忽略8个HTTP头部的处理 */
    ngx_uint_t                       ignore_headers;
    
	/* 以二进制来表示一些错误码，如果处理上游响应时发现这些错误码，那么在没有将响应转发给下游客户端时，
	将会选择下一个上游服务器来重新发送*/
	ngx_uint_t                       next_upstream;

	/* 在buffering标志位为1的情况下转发响应时，将有可能把响应存放到临时文件中，在gnx_http_upstream_t
	中的store为1时，store_access表示所创建的目录、文件的权限*/
    ngx_uint_t                       store_access;

	/* 决定转发响应方式的标志位，为1时表示打开缓存，这时认为上游的网速快于下游的网速，会尽量在内存或者
	磁盘中缓存来自上游的响应；如果buffering为0，仅会开辟一块固定大小的内存块作为缓存来转发响应*/
    ngx_flag_t                       buffering;
    ngx_flag_t                       pass_request_headers;
    ngx_flag_t                       pass_request_body;

	/* 为1时表示与上游服务器交互时将不检查Nginx与下游客户端间的连接是否断开，也就是说，即使下游客户端
	主动关闭了连接，也不会中断与上游服务器间的交互 */
    ngx_flag_t                       ignore_client_abort;

	/* 当解析上游响应的包头时，如果解析后设置到headers_in结构体中的status_n错误码大于400，则会试图把它与
	error_page中指定的错误码向匹配，如果匹配上，则发送error_page中指定的响应，否则继续返回上游服务器的错误码 */
    ngx_flag_t                       intercept_errors;
    
	/* buffering为1时才有意义，如果cyclic_temp_file为1.则会试图复用临时文件中已经使用过的空间 */
	ngx_flag_t                       cyclic_temp_file;

    ngx_path_t                      *temp_path;//buffering为1的情况下转发响应时，存放临时文件的路径

	/* 不转发的头部，实际上是通过ngx_http_upstream_hide_headers_hash方法，根据hide_headers和
	pass_headers动态数组构造出的需要隐藏的HTTP头部散列表*/
    ngx_hash_t                       hide_headers_hash;

	/* 当转发上游响应头部给下游客户端时，如果不希望某些头部转发给下游，就设置到hide_headers动态数组中 */
    ngx_array_t                     *hide_headers;

	/* 当转发上游响应头部时给下游客户端时，upstream机制默认不转发如"Date"、"Server"之类的头部，如果确实
	希望直接转发他们到下游，就设置到pass_headers动态数组中*/
    ngx_array_t                     *pass_headers;

    ngx_http_upstream_local_t       *local;//连接上游服务器使用的本机地址

#if (NGX_HTTP_CACHE)
    ngx_shm_zone_t                  *cache;

    ngx_uint_t                       cache_min_uses;
    ngx_uint_t                       cache_use_stale;
    ngx_uint_t                       cache_methods;

    ngx_flag_t                       cache_lock;
    ngx_msec_t                       cache_lock_timeout;

    ngx_array_t                     *cache_valid;
    ngx_array_t                     *cache_bypass;
    ngx_array_t                     *no_cache;
#endif

    ngx_array_t                     *store_lengths;
    ngx_array_t                     *store_values;

    signed                           store:2;//与ngx_http_upstream_t中的store相同

	/* 上面的intercept_erroes标志位定义了400以上的错误码将会与error_page比较后再进行处理，实际上这个规则
	是可以有一个例外的，如果intercept_404为1，当上游返回404时就会直接转发这个错误码给下游，而不去和
	erroe_page比较*/
    unsigned                         intercept_404:1;

	/* 当该标志位为1时，将会根据ngx_http_upstream_t中headers_in结构体里的X-Accel-Buffering头部来改变buffering
	标志位，当其值为yes时，buffering为1,。因此，change_bbuffering为1时将有可能根据上游服务器返回的响应头部
	，动态的决定是以上游网速优先还是以下游网速优先*/
    unsigned                         change_buffering:1;

#if (NGX_HTTP_SSL)
    ngx_ssl_t                       *ssl;
    ngx_flag_t                       ssl_session_reuse;
#endif

    ngx_str_t                        module;
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;

    ngx_uint_t                       status_n;
    ngx_str_t                        status_line;

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;
    ngx_table_elt_t                 *transfer_encoding;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    off_t                            content_length_n;

    ngx_array_t                      cache_control;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
} ngx_http_upstream_headers_in_t;


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;//地址个数
    in_addr_t                       *addrs;

    struct sockaddr                 *sockaddr;//上游服务器地址
    socklen_t                        socklen;

    ngx_resolver_ctx_t              *ctx;
} ngx_http_upstream_resolved_t;


typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
    ngx_http_upstream_t *u);


struct ngx_http_upstream_s 
{
    ngx_http_upstream_handler_pt     read_event_handler;//处理读事件的回调方法，每一个阶段都有不同的read_event_handler
    ngx_http_upstream_handler_pt     write_event_handler;//同上

    ngx_peer_connection_t            peer;//表示主动向上游服务器发起的连接

	/* 当向下游客户端转发响应时(ngx_http_request_t结构体中的subrequest_in_memory标志位为0)，如果打开了缓存
	且认为上游网速更快(conf配置中的buffering标志为1)，这时会使用pipe成员来转发响应。在使用这种方式转发响应
	时，必须由HTTP模块在使用upstream机制前构造pipe结构体，否则会出现严重的codedump错误 */
    ngx_event_pipe_t                *pipe;

    ngx_chain_t                     *request_bufs;//决定发送什么样的请求给上游服务器，在实现create_request方法时需要设置它

    ngx_output_chain_ctx_t           output;//定义了向下游发送响应的方式
    ngx_chain_writer_ctx_t           writer;

    ngx_http_upstream_conf_t        *conf;//upstream访问时所有限制性参数

	/* HTTP模块在实现process_header方法时，如果希望upstream直接转发响应，就需要把解析出的响应头部都适配为
	HTTP的响应头部，同时需要把包头中的信息设置到headers_in结构体中，然后把headers_in中设置的头部添加到要
	发送到下游客户端的响应头部headers_out中 */
    ngx_http_upstream_headers_in_t   headers_in;

    ngx_http_upstream_resolved_t    *resolved;//指定上游服务器的地址

    ngx_buf_t                        from_client;
	/* buffer成员存储接收自上游服务器发来的响应内容，由于它会被复用，所以具有下列多种意义：
	a)在使用process_header方法解析上游响应的包头时，buffer中将会保存完整的响应包头;
	b)当下面的buffering成员为1，而且此时upstream是向下游转发上游的包体时，buffer没有意义;
	c)当buffering标志位为0时，buffer缓冲区会被调用于反复地接收上游的包体，进而向下游转发;
	d)当upstream并不用于转发上游包体时，buffer会被用于反复接收上游的包体，HTTP模块实现的input_filter方法
	 需要关注它 */
    ngx_buf_t                        buffer;
    off_t                            length;//表示来自上游服务器的响应包体的长度

	/* out_bufs在两种场景下有不同的意义：1：当不需要转发包体时，且使用默认的input_filter方法(也就是
	ngx_http_upstream_non_buffered_filter方法)处理包体时，out_bufs将会指向响应包体，事实上，out_bufs链表中
	会产生多个ngx_buf_t缓冲区，每个缓冲区都指向buffer缓冲中的一部分，而这里的一部分就是每次调用recv方法接
	收到的一段TCP流。2：当需要转发响应包体到下游时(buffering标志位为0，即以下游网速优先)，这个链表指向上一
	次向下游转发响应到现在这段时间内接收自上游的缓存响应 */
    ngx_chain_t                     *out_bufs;
    
	/* 当需要发响应包体到下游时，它表示上一次向下游转发响应时没有发送完的内容 */
	ngx_chain_t                     *busy_bufs;
	
	/* 这个链表将用于回收out_bufs中已经发送给下游的ngx_buf_t结构体，
	这同样应用在buffering标志位为0即以下游网速优先的场景 */
    ngx_chain_t                     *free_bufs;

    ngx_int_t                      (*input_filter_init)(void *data);//处理包体前的初始化方法
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);//处理包体的方法
    void                            *input_filter_ctx;//用于传递HTTP模块自定义的数据结构，上面两个回调方法的data参数

#if (NGX_HTTP_CACHE)
    ngx_int_t                      (*create_key)(ngx_http_request_t *r);
#endif
    ngx_int_t                      (*create_request)(ngx_http_request_t *r);//构造发往上游服务器的请求内容

	/* 与上游服务器通信失败后，如果按照重试规则还需要再次向上游服务器发起连接，则会调用reinit_request方法 */
    ngx_int_t                      (*reinit_request)(ngx_http_request_t *r);
	
	/* 解析上游服务器的响应包头，收到上游服务器的响应后就会回调process_header方法.
	如果process_header返回NGX_AGAIN,那么是在告诉upstream还没有收到完整的响应包头，此时，对于本次upstream
	请求来说，再次接收到上游服务器发来的TCP流时，还会调用process_header方法处理，直到process_header函数
	返回非NGX_AGAIN值这一阶段才会停止 */
    ngx_int_t                      (*process_header)(ngx_http_request_t *r);
    void                           (*abort_request)(ngx_http_request_t *r);

    void                           (*finalize_request)(ngx_http_request_t *r,
                                         ngx_int_t rc);//销毁upstream请求时调用
	/* 在上游返回的响应出现Location或者Refresh头部表示重定向时，会通过ngx_http_upstream_process_headers方法
	调用到可由HTTP模块实现的rewrite_redirect方法*/
    ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h, size_t prefix);
    ngx_int_t                      (*rewrite_cookie)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h);

    ngx_msec_t                       timeout;

    ngx_http_upstream_state_t       *state;//用于表示上游响应的错误码、包体长度等信息

    ngx_str_t                        method;
    ngx_str_t                        schema;
    ngx_str_t                        uri;

    ngx_http_cleanup_pt             *cleanup;

    unsigned                         store:1;
    unsigned                         cacheable:1;//是否启用文件缓存
    unsigned                         accel:1;
    unsigned                         ssl:1;//是否基于SSL协议访问上游服务器
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

	/* 在向客户端转发上游服务器的包体时才有用.当buffering为1时，表示使用多个缓冲区以及磁盘文件来转发上游
	的响应包体.当Nginx与上游间的网速远大于Nginx与下游客户端间的网速时，让Nginx开辟更多的内存甚至使用磁盘
	文件来缓存上游的响应包体，这是有意义的，它可以减轻上游服务器的并发压力。当buffering为0时，表示只使用
	上面的这一个buffer缓冲区来向下游转发响应包体 */
    unsigned                         buffering:1;
    unsigned                         keepalive:1;
    unsigned                         upgrade:1;
	
	/* 表示是否已经向上游服务器发送了请求，为1时表示upstream机制已经向上游服务器发送了全部或者部分请求，
	事实上，这个标志位更多的是为了使用ngx_output_chain方法发送请求，因为该方法发送请求时会自动把未发送完的
	request_bufs链表记录下来，为了防止反复发送重复请求，必须由request_sent标志位记录是否调用过
	ngx_output_chain方法 */
    unsigned                         request_sent:1;
    
	/* 将上游服务器的响应划分为包头和包尾，如果把响应直接转发给客户端，header_sent标志位表示包头是否发送，
	为1表示已经把包头转发给客户端了；如果不转发响应到客户端，则没有意义*/
	unsigned                         header_sent:1;
};


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_http_upstream_next_t;


typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
    ngx_uint_t  skip_empty;
} ngx_http_upstream_param_t;


ngx_int_t ngx_http_upstream_header_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
void ngx_http_upstream_init(ngx_http_request_t *r);
ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_http_upstream_module;
extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
