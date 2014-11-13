
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
#define _NGX_HTTP_REQUEST_H_INCLUDED_


#define NGX_HTTP_MAX_URI_CHANGES           10
#define NGX_HTTP_MAX_SUBREQUESTS           200

/* must be 2^n */
#define NGX_HTTP_LC_HEADER_LEN             32


#define NGX_HTTP_DISCARD_BUFFER_SIZE       4096
#define NGX_HTTP_LINGERING_BUFFER_SIZE     4096


#define NGX_HTTP_VERSION_9                 9
#define NGX_HTTP_VERSION_10                1000
#define NGX_HTTP_VERSION_11                1001

#define NGX_HTTP_UNKNOWN                   0x0001
#define NGX_HTTP_GET                       0x0002
#define NGX_HTTP_HEAD                      0x0004
#define NGX_HTTP_POST                      0x0008
#define NGX_HTTP_PUT                       0x0010
#define NGX_HTTP_DELETE                    0x0020
#define NGX_HTTP_MKCOL                     0x0040
#define NGX_HTTP_COPY                      0x0080
#define NGX_HTTP_MOVE                      0x0100
#define NGX_HTTP_OPTIONS                   0x0200
#define NGX_HTTP_PROPFIND                  0x0400
#define NGX_HTTP_PROPPATCH                 0x0800
#define NGX_HTTP_LOCK                      0x1000
#define NGX_HTTP_UNLOCK                    0x2000
#define NGX_HTTP_PATCH                     0x4000
#define NGX_HTTP_TRACE                     0x8000

#define NGX_HTTP_CONNECTION_CLOSE          1
#define NGX_HTTP_CONNECTION_KEEP_ALIVE     2


#define NGX_NONE                           1


#define NGX_HTTP_PARSE_HEADER_DONE         1

#define NGX_HTTP_CLIENT_ERROR              10
#define NGX_HTTP_PARSE_INVALID_METHOD      10
#define NGX_HTTP_PARSE_INVALID_REQUEST     11
#define NGX_HTTP_PARSE_INVALID_09_METHOD   12

#define NGX_HTTP_PARSE_INVALID_HEADER      13


/* unused                                  1 */
#define NGX_HTTP_SUBREQUEST_IN_MEMORY      2
#define NGX_HTTP_SUBREQUEST_WAITED         4
#define NGX_HTTP_LOG_UNSAFE                8


#define NGX_HTTP_CONTINUE                  100
#define NGX_HTTP_SWITCHING_PROTOCOLS       101
#define NGX_HTTP_PROCESSING                102

#define NGX_HTTP_OK                        200
#define NGX_HTTP_CREATED                   201
#define NGX_HTTP_ACCEPTED                  202

//没有内容
#define NGX_HTTP_NO_CONTENT                204
#define NGX_HTTP_PARTIAL_CONTENT           206

#define NGX_HTTP_SPECIAL_RESPONSE          300
#define NGX_HTTP_MOVED_PERMANENTLY         301
#define NGX_HTTP_MOVED_TEMPORARILY         302
#define NGX_HTTP_SEE_OTHER                 303
#define NGX_HTTP_NOT_MODIFIED              304
#define NGX_HTTP_TEMPORARY_REDIRECT        307

#define NGX_HTTP_BAD_REQUEST               400
#define NGX_HTTP_UNAUTHORIZED              401
#define NGX_HTTP_FORBIDDEN                 403
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_NOT_ALLOWED               405
#define NGX_HTTP_REQUEST_TIME_OUT          408
#define NGX_HTTP_CONFLICT                  409
#define NGX_HTTP_LENGTH_REQUIRED           411
#define NGX_HTTP_PRECONDITION_FAILED       412
#define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NGX_HTTP_REQUEST_URI_TOO_LARGE     414
#define NGX_HTTP_UNSUPPORTED_MEDIA_TYPE    415
#define NGX_HTTP_RANGE_NOT_SATISFIABLE     416


/* Our own HTTP codes */

/* The special code to close connection without any response */
#define NGX_HTTP_CLOSE                     444

#define NGX_HTTP_NGINX_CODES               494

#define NGX_HTTP_REQUEST_HEADER_TOO_LARGE  494

#define NGX_HTTPS_CERT_ERROR               495
#define NGX_HTTPS_NO_CERT                  496

/*
 * We use the special code for the plain HTTP requests that are sent to
 * HTTPS port to distinguish it from 4XX in an error page redirection
 */
#define NGX_HTTP_TO_HTTPS                  497

/* 498 is the canceled code for the requests with invalid host name */

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define NGX_HTTP_CLIENT_CLOSED_REQUEST     499


#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_NOT_IMPLEMENTED           501
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_SERVICE_UNAVAILABLE       503
#define NGX_HTTP_GATEWAY_TIME_OUT          504
#define NGX_HTTP_INSUFFICIENT_STORAGE      507


#define NGX_HTTP_LOWLEVEL_BUFFERED         0xf0

//告诉HTTP框架out缓冲区还有响应待发送
#define NGX_HTTP_WRITE_BUFFERED            0x10

#define NGX_HTTP_GZIP_BUFFERED             0x20
#define NGX_HTTP_SSI_BUFFERED              0x01
#define NGX_HTTP_SUB_BUFFERED              0x02
#define NGX_HTTP_COPY_BUFFERED             0x04


typedef enum {
    NGX_HTTP_INITING_REQUEST_STATE = 0,
    NGX_HTTP_READING_REQUEST_STATE,
    NGX_HTTP_PROCESS_REQUEST_STATE,

    NGX_HTTP_CONNECT_UPSTREAM_STATE,
    NGX_HTTP_WRITING_UPSTREAM_STATE,
    NGX_HTTP_READING_UPSTREAM_STATE,

    NGX_HTTP_WRITING_REQUEST_STATE,
    NGX_HTTP_LINGERING_CLOSE_STATE,
    NGX_HTTP_KEEPALIVE_STATE
} ngx_http_state_e;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
    ngx_http_header_handler_pt        handler;
} ngx_http_header_t;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
} ngx_http_header_out_t;

/* 所有解析过的HTTP首部都在headers链表中,这里headers链表的每一个元素都是ngx_table_elt_t */
typedef struct {
    ngx_list_t                        headers;
    /* 以下每个ngx_table_elt_t成员都是RFC1616规范中定义的HTT首部，他们实际都指向headers链表中的相应  成员。注意，当它们为NULL时，表示没有解析到相应的
    HTTP头部 */
    ngx_table_elt_t                  *host;
    ngx_table_elt_t                  *connection;
    ngx_table_elt_t                  *if_modified_since;
    ngx_table_elt_t                  *if_unmodified_since;
    ngx_table_elt_t                  *if_match;
    ngx_table_elt_t                  *if_none_match;
    ngx_table_elt_t                  *user_agent;
    ngx_table_elt_t                  *referer;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_type;

    ngx_table_elt_t                  *range;
    ngx_table_elt_t                  *if_range;

    ngx_table_elt_t                  *transfer_encoding;
    ngx_table_elt_t                  *expect;
    ngx_table_elt_t                  *upgrade;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                  *accept_encoding;
    ngx_table_elt_t                  *via;
#endif

    ngx_table_elt_t                  *authorization;

    ngx_table_elt_t                  *keep_alive;

#if (NGX_HTTP_X_FORWARDED_FOR)
    ngx_array_t                       x_forwarded_for;
#endif

#if (NGX_HTTP_REALIP)
    ngx_table_elt_t                  *x_real_ip;
#endif

#if (NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept;
    ngx_table_elt_t                  *accept_language;
#endif

#if (NGX_HTTP_DAV)
    ngx_table_elt_t                  *depth;
    ngx_table_elt_t                  *destination;
    ngx_table_elt_t                  *overwrite;
    ngx_table_elt_t                  *date;
#endif

    ngx_str_t                         user;
    ngx_str_t                         passwd;

    ngx_array_t                       cookies;

	//HTTP的虚拟主机URL地址
    ngx_str_t                         server;

	/* content-length首部的长度。当丢弃包体时，请求的request_body成员为NULL，此时用ngx_http_request_t
	结构体headers_in成员里的content_length_n表示已经丢弃的包体的大小，每丢弃一部分包体，就
	会减去相应的大小
	*/
    off_t                             content_length_n;
    time_t                            keep_alive_n;

	//HTTP连接类型，它的取值范围是0、NGX_HTTP_CONNECTION_CLOSE或者NGX_HTTP_CONNECTION_KEEP_ALIVE
    unsigned                          connection_type:2;

	/* 以下7个标志位是HTTP框架根据浏览器传来的"useragent"头部，它们可用来判断浏览器的类型，
	值为1表示是相应的浏览器发来的请求 */

	//包体进行了编码
    unsigned                          chunked:1;

	unsigned                          msie:1;
    unsigned                          msie6:1;
    unsigned                          opera:1;
    unsigned                          gecko:1;
    unsigned                          chrome:1;
    unsigned                          safari:1;
    unsigned                          konqueror:1;
} ngx_http_headers_in_t;


typedef struct {

	//响应首部
    ngx_list_t                        headers;

	//响应中的状态，如200表示成功，可以用上面定义的宏表示，如NGX_HTTP_OK
    ngx_uint_t                        status;

	//响应行的状态，如"HTTP/1.1 201 CREATED"
    ngx_str_t                         status_line;

	/* 以下成员(包括ngx_table_elt_t)都是RFC1616中定义的HTTP头部，设置和，ngx_http_header_filter_module过滤
	模块可以把它们加到待发送的网络包中 */
    ngx_table_elt_t                  *server;
    ngx_table_elt_t                  *date;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_encoding;
    ngx_table_elt_t                  *location;
    ngx_table_elt_t                  *refresh;
    ngx_table_elt_t                  *last_modified;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *accept_ranges;
    ngx_table_elt_t                  *www_authenticate;
    ngx_table_elt_t                  *expires;
    ngx_table_elt_t                  *etag;

    ngx_str_t                        *override_charset;
	
	/* 可以调用ngx_http_set_content_type(r)方法帮助我们设置Content-Type头部，这个方法会根据URI中的
	文件扩展名并对应着Mime.type来设置Content-Type值 */
    size_t                            content_type_len;
    ngx_str_t                         content_type;
    ngx_str_t                         charset;
    u_char                           *content_type_lowcase;
    ngx_uint_t                        content_type_hash;

    ngx_array_t                       cache_control;

    off_t                             content_length_n;
    time_t                            date_time;

    //上次修改的时间，用于对if_modified_since首部进行判断
    time_t                            last_modified_time;
} ngx_http_headers_out_t;


typedef void (*ngx_http_client_body_handler_pt)(ngx_http_request_t *r);

//保存HTTP包体的结构体
typedef struct 
{
	//存放HTTP包体的临时文件
    ngx_temp_file_t                  *temp_file;
	/*接收HTTP包体的缓存区链表。当包体需要全部放在内存中时，如果一块ngx_buf_t缓冲区无法存放
	完，这时需要使用ngx_chain_t链表来存放*/
    ngx_chain_t                      *bufs;
	//根据接收HTTP包体的缓存
    ngx_buf_t                        *buf;
	//接收content-length头部和已接受到的包体长度，计算出还需要接收的包体长度
    off_t                             rest;
	
    ngx_chain_t                      *free;
    ngx_chain_t                      *busy;
    ngx_http_chunked_t               *chunked;
	//HTTP包体接收完毕后执行的回调方法
    ngx_http_client_body_handler_pt   post_handler;
} ngx_http_request_body_t;


typedef struct ngx_http_addr_conf_s  ngx_http_addr_conf_t;

typedef struct {
    ngx_http_addr_conf_t             *addr_conf;
    ngx_http_conf_ctx_t              *conf_ctx;

#if (NGX_HTTP_SSL && defined SSL_CTRL_SET_TLSEXT_HOSTNAME)
    ngx_str_t                        *ssl_servername;
#if (NGX_PCRE)
    ngx_http_regex_t                 *ssl_servername_regex;
#endif
#endif

    ngx_buf_t                       **busy;
    ngx_int_t                         nbusy;

    ngx_buf_t                       **free;
    ngx_int_t                         nfree;

#if (NGX_HTTP_SSL)
    ngx_uint_t                        ssl;    /* unsigned  ssl:1; */
#endif
} ngx_http_connection_t;


typedef void (*ngx_http_cleanup_pt)(void *data);

typedef struct ngx_http_cleanup_s  ngx_http_cleanup_t;

struct ngx_http_cleanup_s 
{
    ngx_http_cleanup_pt               handler;//HTTP模块提供的清理资源的回调方法
    void                             *data;//希望给上面的回调方法传递参数
    ngx_http_cleanup_t               *next;//一个请求可能会有多个清理方法
};


typedef ngx_int_t (*ngx_http_post_subrequest_pt)(ngx_http_request_t *r,
    void *data, ngx_int_t rc);


//子请求的回调函数和参数
typedef struct 
{
    ngx_http_post_subrequest_pt       handler;
    void                             *data;
} ngx_http_post_subrequest_t;

/*以下两个结构体用于实现subrequest功能*/


typedef struct ngx_http_postponed_request_s  ngx_http_postponed_request_t;

/*每个请求都有一个postponed链表，一般情况下每个链表节点都保存了该请求的一个子请求，
即request成员*/
struct ngx_http_postponed_request_s 
{
	//保存子请求
    ngx_http_request_t               *request;
	/*一个请求的postponed链表里面处了保存子请求的节点，还有保存该请求自己产生的数据的节点，数据保存在out字段*/
    ngx_chain_t                      *out;
    ngx_http_postponed_request_t     *next;
};


typedef struct ngx_http_posted_request_s  ngx_http_posted_request_t;

struct ngx_http_posted_request_s 
{
	//指向当前待处理的子请求的ngx_http_request_t结构体
    ngx_http_request_t               *request;
	//指向下一个子请求
    ngx_http_posted_request_t        *next;
};


typedef ngx_int_t (*ngx_http_handler_pt)(ngx_http_request_t *r);
typedef void (*ngx_http_event_handler_pt)(ngx_http_request_t *r);

//对应一个http连接
struct ngx_http_request_s
{
    uint32_t                          signature;         /* "HTTP" */
	//这个请求对应的客户端连接
    ngx_connection_t                 *connection;
    void                            **ctx;//指向存放所有HTTP模块的上下文结构体的指针数组
	//指向请求对应的存放main级别配置结构体的指针数组
    void                            **main_conf;
	//指向请求对应的存放srv级别配置结构体的指针数组
    void                            **srv_conf;
	//指向请求对应的存放loc级别配置结构体的指针数组
    void                            **loc_conf;

	/* 下面的读写事件与ngx_connection_t中的读写事件不同，ngx_connection_t中的读写事件是读写通过套接字发送的数据，而此处的HTTP请求中的
	读写事件是在处理HTTP请求时对内存的访问，即是否需要读写内存。在接收完HTTP头部，第一次在业务上处理HTTP请求时，HTTP框架提供的处理方法是
	ngx_http_process_request,但如果该方法无法一次性处理完该请求的全部业务，在归还控制权到epoll事件模块后，该请求再次被回调时，将通过
	ngx_http_request_handler方法来处理，而这个方法中对于可读事件的处理就是调用read_event_handler处理请求，也就是说，HTTP模块希望在
	底层处理请求的读事件时，重新实现read_event_handler方法*/
    ngx_http_event_handler_pt         read_event_handler;
    /* 下面的读写事件与ngx_connection_t中的读写事件不同，ngx_connection_t中的读写事件是读写通过套接字发送的数据，而此处的HTTP请求中的
    读写事件是在处理HTTP请求时对内存的访问，即是否需要读写内存。*/
    ngx_http_event_handler_pt         write_event_handler;

#if (NGX_HTTP_CACHE)
    ngx_http_cache_t                 *cache;
#endif

    ngx_http_upstream_t              *upstream;
    ngx_array_t                      *upstream_states;
    /*表示这个请求的内存池，在ngx_http_free_request方法中销毁，它与ngx_connection_t中的内存池意义不同，当请求释放时，T
    CP连接可能并没有关闭，这时请求的内存池会销毁，但ngx_connection_t的内存池不会*/
    ngx_pool_t                       *pool;
    ngx_buf_t                        *header_in;//指向Nginx收到的未经解析的HTTP头部，即接收HTTP头部的缓冲区
	/*ngx_http_process_request_headers方法在接收、解析完HTTP请求的首部后，会把解析完的每一个HTTP首部加
	入到headers_in的headers链表中，同时会构造headers_in中的其它成员*/
    ngx_http_headers_in_t             headers_in;

	/*HTTP模块会把想要发送的HTTP响应信息放到headers_out中，期望HTTP框架将headers_out中的成员序列化为HTTP响应包发送给用户*/
    ngx_http_headers_out_t            headers_out;

	//接收HTTP请求中包体的数据结构，详见11.8
    ngx_http_request_body_t          *request_body;

	//延迟关闭的时间
    time_t                            lingering_time;

	/* 当前请求初始化时间，1970-1-1:0:0:0到当前的秒数,如果是子请求，该时间是子请求建立的
	时间，如果是用户发来的请求，则是建立起TCP连接后，第一次接收到可读事件的时间 */
    time_t                            start_sec;

	//与start_sec配合使用，毫秒数
    ngx_msec_t                        start_msec;

	/* 以下9个成员都是邋邋邋邋ngx_http_process_request_line方法在接收、解析HTTP请求行时解析出的
	信息，其意义在第3章描述过 */

	//它是Nginx忽略大小写等情形时解析完用户请求后得到的方法类型，如NGX_HTTP_GET，NGX_HTTP_PUT等
    ngx_uint_t                        method;
    ngx_uint_t                        http_version;

	//HTTP请求行
    ngx_str_t                         request_line;

	//指向用户请求中的URI,如"http://www.contoso.com/",必须以'/'结尾
    ngx_str_t                         uri;
	
    ngx_str_t                         args;//指向用户请求中的URL参数

	//指向用户请求的文件扩展，如：在访问"GET /a.txt HTTP/1.1"时,extern的值是{len=3,data="txt"}
    ngx_str_t                         exten;
	
    ngx_str_t                         unparsed_uri;//表示没有进行URL解码的原始请求。例如：当uri为"/a b"时，unparsed_uri是"/a%20b"(空格字符做完编码后是%20)

	//HTTP方法名
    ngx_str_t                         method_name;

	//指向HTTP版本号,如"HTTP/1.1"
    ngx_str_t                         http_protocol;

	/*表示需要发送给客户端的HTTP响应，out中保存着由headers_out中序列化后的表示HTTP头部的TCP流，
	在调用ngx_http_output_filter方法后，out中还会保存待发送的HTTP包体，它是实现异步发送HTTP响应的关
	键，参见11.9*/
    ngx_chain_t                      *out;

	//存放子请求，见11.10.6
    ngx_http_postponed_request_t     *postponed;

    /* 主要是记录一个回调函数以及其参数，回调函数在当前子请求结束时被调用 */
    ngx_http_post_subrequest_t       *post_subrequest;

	/* 以下三个成员是用来实现子请求的 */

	/*待处理的子请求组成的单链表，所有的子请求都是通过这个单链表连接起来的，执行
	post子请求时调用的ngx_http_run_posted_requests方法就是通过遍历该单链表来执行子请求的	*/
    ngx_http_posted_request_t        *posted_requests;
	
	/* 指向一系列有亲缘关系的请求中的唯一的那个原始请求，我们可以在任何一个子请求中通过
	main成员找到原始请求，而无论怎样执行子请求，都是围绕着main指向的原始请求进行的 */
	ngx_http_request_t               *main;
	
	//当前子请求的父请求
    ngx_http_request_t               *parent;

	/* 全局的ngx_http_phase_engine_t结构体中定义了一个ngx_http_phase_handler_t回调方法组成的数组，
	而phase_handler成员则与该数组配合使用，表示请求下次应当执行以phase_handler作为序号
	指定的数组中的回调方法，HTTP框架正是以这种方式把各个HTTP模块集成起来处理请求的*/
    ngx_int_t                         phase_handler;

	/*表示NGX_HTTP_CONTENT_PHASE阶段提供给HTTP模块处理请求的一种方式，content_handler指向
	HTTP模块实现的请求处理方法，11.6.4*/
    ngx_http_handler_pt               content_handler;

	/*在NGX_HTTP_ACCESS_PHASE阶段需要判断请求是否具有访问权限时，通过access_code来传递HTTP
	模块的handler回调方法的返回值，如果为0，则表示请求具有访问权限，反之则说明没有访问权限*/
    ngx_uint_t                        access_code;

    ngx_http_variable_value_t        *variables;

#if (NGX_PCRE)
    ngx_uint_t                        ncaptures;
    int                              *captures;
    u_char                           *captures_data;
#endif

	//每秒钟可以发送的字节数
    size_t                            limit_rate;

    /* used to learn the Apache compatible response length without a header */
    size_t                            header_size;

	//HTTP请求的全部长度，包括包体
    off_t                             request_length;

    ngx_uint_t                        err_status;

    ngx_http_connection_t            *http_connection;
#if (NGX_HTTP_SPDY)
    ngx_http_spdy_stream_t           *spdy_stream;
#endif

    ngx_http_log_handler_pt           log_handler;

	/*在这个请求中如果打开了某些资源，并需要在请求结束时释放，那么都需要在把定义的释放资源
	方法添加到cleanup成员中，11.10.2*/
    ngx_http_cleanup_t               *cleanup;

    unsigned                          subrequests:8;

	/*表示当前请求的引用计数，例如，在使用subrequest功能时，依附在这个请求上的子请求数目会
	返回到count上，每增加一个子请求，count数就要加1.其中任何一个子请求派生出新的子请求时，对
	应的原始请求的count都要加1.又如，当我们接收HTTP包体时，由于这也是一个异步调用，所以count
	也要加1，这样在请求结束时，就不会再count引用计数未清零时销毁请求，参见11.10.3的ngx_http_close_request
	方法*/
    unsigned                          count:8;

	//阻塞标志位
	unsigned                          blocked:8;

	//为1时表示当前请求正在使用异步文件IO
    unsigned                          aio:1;

    unsigned                          http_state:4;

    /* URI with "/." and on Win32 with "//" */
    unsigned                          complex_uri:1;

    /* URI with "%" */
    unsigned                          quoted_uri:1;

    /* URI with "+" */
    unsigned                          plus_in_uri:1;

    /* URI with " " */
    unsigned                          space_in_uri:1;

    unsigned                          invalid_header:1;

    unsigned                          add_uri_to_alias:1;
    unsigned                          valid_location:1;
    unsigned                          valid_unparsed_uri:1;

	//为1时表示URL发生过rewrite重写
    unsigned                          uri_changed:1;

	/*表示使用URL重写的次数，因为目前最多可以更改10次，所有初始化为11，而每次重写URL就把
	uri_changes减1，一旦uri_changes等 于0，则向用户返回失败*/
    unsigned                          uri_changes:4;

    unsigned                          request_body_in_single_buf:1;

	//http的body存放在临时文件中
    unsigned                          request_body_in_file_only:1;

	//该临时文件不会被删除，保留下来
	unsigned                          request_body_in_persistent_file:1;
    unsigned                          request_body_in_clean_file:1;
    unsigned                          request_body_file_group_access:1;
    unsigned                          request_body_file_log_level:3;

    unsigned                          subrequest_in_memory:1;
    unsigned                          waited:1;

#if (NGX_HTTP_CACHE)
    unsigned                          cached:1;
#endif

#if (NGX_HTTP_GZIP)
    unsigned                          gzip_tested:1;
    unsigned                          gzip_ok:1;
    unsigned                          gzip_vary:1;
#endif

    unsigned                          proxy:1;
    unsigned                          bypass_cache:1;
    unsigned                          no_cache:1;

    /*
     * instead of using the request context data in
     * ngx_http_limit_conn_module and ngx_http_limit_req_module
     * we use the single bits in the request structure
     */
    unsigned                          limit_conn_set:1;
    unsigned                          limit_req_set:1;

#if 0
    unsigned                          cacheable:1;
#endif

    unsigned                          pipeline:1;

	//分块编码
    unsigned                          chunked:1;

	//只需要发送响应行和首部，对应于请求的HEAD方法
    unsigned                          header_only:1;

	//为1时表示当前请求时keepalive请求
    unsigned                          keepalive:1;

	/*延迟关闭标志位，为1时表示需要延迟关闭，例如在接收完HTTP头部时，如果发现包体存在，该标志位会设为1，而放弃接收包体时则会设为0，11.8*/
    unsigned                          lingering_close:1;
	//正在丢弃包体
    unsigned                          discard_body:1;
	//为1时表示请求的当前状态是在做内部跳转，即重定向，图11-5
    unsigned                          internal:1;
	
    unsigned                          error_page:1;
    unsigned                          ignore_content_encoding:1;
    unsigned                          filter_finalize:1;
    unsigned                          post_action:1;
    unsigned                          request_complete:1;
    unsigned                          request_output:1;

	/*为1时表示发送给客户端的HTTP响应头部已经发送，在11.9。1节中调用ngx_http_send_header
	方法后，若已经成功地启动响应头部发送流程，则该标志位为1，用来防止反复地发送头部*/
    unsigned                          header_sent:1;
    unsigned                          expect_tested:1;
    unsigned                          root_tested:1;
    unsigned                          done:1;
    unsigned                          logged:1;

	//表示缓冲区是否有待发送内容的标志位
    unsigned                          buffered:4;

    unsigned                          main_filter_need_in_memory:1;
    unsigned                          filter_need_in_memory:1;
    unsigned                          filter_need_temporary:1;

    //是否允许范围请求
    unsigned                          allow_ranges:1;

#if (NGX_STAT_STUB)
    unsigned                          stat_reading:1;
    unsigned                          stat_writing:1;
#endif

    /* used to parse HTTP headers */

	//状态机解析HTTP时使用state来表示当前的解析状态
    ngx_uint_t                        state;

    ngx_uint_t                        header_hash;
    ngx_uint_t                        lowcase_index;
    u_char                            lowcase_header[NGX_HTTP_LC_HEADER_LEN];

	//首部名的开始和结尾处，如HOST
    u_char                           *header_name_start;
    u_char                           *header_name_end;

	//首部值得开始和结尾处，如www.myserver.com
    u_char                           *header_start;
    u_char                           *header_end;

    /*
     * a memory that can be reused after parsing a request line
     * via ngx_http_ephemeral_t
     */

	//请求行中URI的开始处
    u_char                           *uri_start;
	
    u_char                           *uri_end;
    u_char                           *uri_ext;
    u_char                           *args_start;

	//请求行的开始
    u_char                           *request_start;
	
    u_char                           *request_end;
    u_char                           *method_end;
    u_char                           *schema_start;
    u_char                           *schema_end;
    u_char                           *host_start;
    u_char                           *host_end;
    u_char                           *port_start;
    u_char                           *port_end;

    unsigned                          http_minor:16;
    unsigned                          http_major:16;
};


typedef struct {
    ngx_http_posted_request_t         terminal_posted_request;
#if (NGX_HAVE_AIO_SENDFILE)
    u_char                            aio_preload;
#endif
} ngx_http_ephemeral_t;


extern ngx_http_header_t       ngx_http_headers_in[];
extern ngx_http_header_out_t   ngx_http_headers_out[];


#define ngx_http_set_connection_log(c, l)                                     \
                                                                              \
    c->log->file = l->file;                                                   \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                    \
        c->log->log_level = l->log_level;                                     \
    }


#endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */
