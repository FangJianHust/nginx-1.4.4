
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_EVENT_CONNECT_H_INCLUDED_
#define _NGX_EVENT_CONNECT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define NGX_PEER_KEEPALIVE           1
#define NGX_PEER_NEXT                2
#define NGX_PEER_FAILED              4


typedef struct ngx_peer_connection_s  ngx_peer_connection_t;

//当使用长连接与上游服务器通信时，可通过该方法从连接池中获取一个新连接
typedef ngx_int_t (*ngx_event_get_peer_pt)(ngx_peer_connection_t *pc,void *data);

//当使用长连接与上游服务器通信时，通过该方法将使用完毕的连接释放给连接池
typedef void (*ngx_event_free_peer_pt)(ngx_peer_connection_t *pc, void *data,ngx_uint_t state);
#if (NGX_SSL)

typedef ngx_int_t (*ngx_event_set_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
typedef void (*ngx_event_save_peer_session_pt)(ngx_peer_connection_t *pc,
    void *data);
#endif

//使用该结构体表示主动连接，只是对ngx_connection_t结构体做了简单的包装
struct ngx_peer_connection_s
{
    ngx_connection_t                *connection;//一个主动连接实际上也需要ngx_connection_t结构体中的大部分成员，并且处于重用的考虑而定义了connection成员
    struct sockaddr                 *sockaddr;//远端socket地址
    socklen_t                        socklen;
    ngx_str_t                       *name;//远端服务器的名称
    ngx_uint_t                       tries;//当前连接出现异常后可以重试的次数
    ngx_event_get_peer_pt            get;//当使用长连接与上游服务器通信时，可通过该方法由连接池中获取一个新连接
    ngx_event_free_peer_pt           free;//当使用长连接与上游服务器通信时，可通过该方法将使用完毕的连接释放给连接池
    void                            *data;//上述get和free方法的参数

#if (NGX_SSL)
    ngx_event_set_peer_session_pt    set_session;
    ngx_event_save_peer_session_pt   save_session;
#endif

#if (NGX_THREADS)
    ngx_atomic_t                    *lock;
#endif

    ngx_addr_t                      *local;//本机的地址信息

    int                              rcvbuf;//套接字接收缓冲区的大小

    ngx_log_t                       *log;

    unsigned                         cached:1;//为1时表示上面的connection连接已经缓存

                                     /* ngx_connection_log_error_e */
    unsigned                         log_error:2;
};


ngx_int_t ngx_event_connect_peer(ngx_peer_connection_t *pc);
ngx_int_t ngx_event_get_peer(ngx_peer_connection_t *pc, void *data);


#endif /* _NGX_EVENT_CONNECT_H_INCLUDED_ */
