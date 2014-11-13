
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;
//代表Nginx服务器监听的一个端口
struct ngx_listening_s {
    ngx_socket_t        fd;//套接字句柄

    struct sockaddr    *sockaddr;//监听的sockaddr地址
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;//addr_text的最大长度
    ngx_str_t           addr_text;//以字符串的形式存储IP地址

    int                 type;//套接字地址，SOCK_STREAM表示TCP

    int                 backlog;//TCP实时监听时的backlog队列,它表示允许正在通过三次握手建立TCP连接但还没有任何进程开始处理的连接的最大个数
    int                 rcvbuf;//内核中对于这个套接字的接收缓冲区大小
    int                 sndbuf;//内核中对于这个套接字的发送缓冲区大小
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    ngx_connection_handler_pt   handler;//当新的TCP连接成功建立后的处理方法

	/*实际上框架并不使用servers指针，它更多是作为一个保留指针，目前主要用于HTTP或者mail等
	模块，用于保存当前监听端口对应着的所有主机名*/
    void               *servers;

    ngx_log_t           log;//log和logp都是可用的日至对象指针
    ngx_log_t          *logp;

    size_t              pool_size;//如果为新的TCP连接创建内存池，则内存池的初始大小为pool_size
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;

	/*TCP_DEFER_ACCEPT选项将在TCP连接成功且接收到用户的请求数据后，才向对监听套接字感兴趣的
	进程发送事件通知，而连接建立成功后，如果post_accept_timeout秒后仍然没有收到用户的数据请
	求，则内核直接丢弃连接*/
    ngx_msec_t          post_accept_timeout;

    ngx_listening_t    *previous;//前一个ngx_listening_t结构，多个ngx_listening_t结构之间由previous组成单链表
    ngx_connection_t   *connection;//当前监听句柄对应着的ngx_connection_t结构体

    unsigned            open:1;//为1表示在当前监听句柄有效，且执行ngx_init_cycle时不关闭监听端口，为0表示正常关闭
    unsigned            remain:1;//为1表示使用已有的ngx_cycle_t来初始化新的ngx_cycle_t时，不关闭原先打开的监听端口，这对运行中升级程序很有用，为0表示正常关闭曾经打开的监听端口
    unsigned            ignore:1;//表示是否绑定，目前没有使用

    unsigned            bound:1;       /* 已经绑定 */
    unsigned            inherited:1;//表示当前监听句柄是否来自前一个进程(如升级Nginx程序),如果为1，则表示来自前一个进程
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;
    unsigned            nonblocking:1;//套接字是否阻塞
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;//为1时表示nginx会将网络地址转化为字符串形式的地址

#if (NGX_HAVE_INET6 && defined IPV6_V6ONLY)
    unsigned            ipv6only:1;
#endif
    unsigned            keepalive:2;

#if (NGX_HAVE_DEFERRED_ACCEPT)
    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#ifdef SO_ACCEPTFILTER
    char               *accept_filter;
#endif
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

};


typedef enum {
     NGX_ERROR_ALERT = 0,
     NGX_ERROR_ERR,
     NGX_ERROR_INFO,
     NGX_ERROR_IGNORE_ECONNRESET,
     NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;

//TCP的nodelay特性,ngx_connection_t的tcp_nodelay标志位的取值范围
typedef enum 
{
     NGX_TCP_NODELAY_UNSET = 0,
     NGX_TCP_NODELAY_SET,
     NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;

//表示如何使用TCP的nopush特性，ngx_connection_t标志位tcp_nopush的取值范围
typedef enum 
{
     NGX_TCP_NOPUSH_UNSET = 0,
     NGX_TCP_NOPUSH_SET,
     NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01

/*该连接表示是客户端主动发起的、Nginx服务器被动接受的TCP连接，简称被动连接?琻gx_peer_connection_t表示主动连接*/
struct ngx_connection_s
 {
	/*连接未使用时，data成员用于充当连接池中空闲连接链表中的next指针，当连接被使用时，data的意义由使用它的nginx模块而定，如在HTTP框架中，data
	指向ngx_http_request_t请求;当执行到有子请求的filter模块时，data指向的请求表示当前排在最前面的子请求，也就是当前可以发往客户端的子请求*/
    void               *data;
    ngx_event_t        *read;//读事件
    ngx_event_t        *write;//写事件
    ngx_socket_t        fd;//套接字句柄
	//直接接收网络字符流的方法
    ngx_recv_pt         recv;
    ngx_send_pt         send;//直接发送网络字符流的方法
    ngx_recv_chain_pt   recv_chain;//以ngx_chain_pt链表为参数来接收网络字符流的方法
    ngx_send_chain_pt   send_chain;//以ngx_chain_pt链表为参数来发送网络字符流的方法
    ngx_listening_t    *listening;//该连接对应的ngx_listening_t监听对象，此连接由listening监听端口的事件建立
	//已发送的HTTP响应字节数
    off_t               sent;
    ngx_log_t          *log;
	/* 内存池，一般在accept一个新连接时，会创建一个内存池，而在这个连接结束时会销毁内存池 */
    ngx_pool_t         *pool;
    struct sockaddr    *sockaddr;//连接客户端的sockaddr结构体
    socklen_t           socklen;
    ngx_str_t           addr_text;//连接客户端字符串形式的IP地址
	//安全加密
#if (NGX_SSL)
    ngx_ssl_connection_t  *ssl;
#endif
	//本机端口对应的sockaddr结构体，也就是listening监听对象中的sockaddr成员
    struct sockaddr    *local_sockaddr;
	/*用于接收、缓存客户端发来的字符流，每个事件消费模块可以自由决定从连接池中分配多大的空间给buffer这个接收缓存字段*/
    ngx_buf_t          *buffer;
	/*该字段用来将当前连接以双向链表元素的形式添加到ngx_cycle_t核心结构体的reusable_connections_queue双向链表中，表示可以重用的连接*/
    ngx_queue_t         queue;
    ngx_atomic_uint_t   number;//连接使用的次数，每次建立一条主动或被动连接时，number都会加1
    ngx_uint_t          requests;//处理请求的次数	
    unsigned            buffered:8;//缓存中的业务类型，最多可以同时表示8个不同的业务
    unsigned            log_error:3;     /* ngx_connection_log_error_e */
    unsigned            unexpected_eof:1;//为1时表示独立连接，如从客户端发起的连接；为0时表示依靠其他行为而建立起来的非独立连接，如使用upstream机制向后端服务器建立起来的连接
    unsigned            timedout:1;
    unsigned            error:1;
    unsigned            destroyed:1;//为1时表示连接已经销毁，这里的连接指的是TCP连接，而不是ngx_connection_t结构体，ngx_connection_t结构体仍然存在，但其对应的套接字、内存池等已经不可用
    unsigned            idle:1;//为1表示连接处于空闲状态，如keepalive请求中两次请求之间的状态
    unsigned            reusable:1;//为1时表示可重用，与上面的queue字段是对应使用的
    unsigned            close:1;
    unsigned            sendfile:1;//为1时表示正在将文件中的数据发往连接的另一端
    /*如果为1，表示只有在连接套接字对应的发送缓冲区必须满足最低设置的大小阀值时，事件驱动模块才会分发该事件，与ngx_handle_write_event方法中的
    lowat参数是对应的 */
    unsigned            sndlowat:1;
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */
#if (NGX_HAVE_IOCP)
    unsigned            accept_context_updated:1;
#endif

#if (NGX_HAVE_AIO_SENDFILE)
    unsigned            aio_sendfile:1;//为1时表示使用异步I/O方式将磁盘上的文件发送给网络连接的另一端
    ngx_buf_t          *busy_sendfile;//使用异步I/O方式发送的文件，busy_sendfile缓冲区中保存待发送文件的信息
#endif
#if (NGX_THREADS)
    ngx_atomic_t        lock;
#endif
};

ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, void *sockaddr,socklen_t socklen);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,ngx_uint_t port);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);
ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);
void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);
#endif /* _NGX_CONNECTION_H_INCLUDED_ */
