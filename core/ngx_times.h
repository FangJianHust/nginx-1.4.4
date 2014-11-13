
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_TIMES_H_INCLUDED_
#define _NGX_TIMES_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/* 缓存的全局时间变量；nginx中的每个进程都会单独地管理当前时间，对于worker进程而言，除了
Nginx启动时更新一次时间外，任何更新时间的操作都只能由ngx_epoll_process_events方法执行，
它会调用ngx_time_update方法更新缓存时间
*/
typedef struct 
{
    time_t      sec;//1970.1.1:0:00到当前时间的秒数
    ngx_uint_t  msec;//当前时间相对于sec的毫秒偏移量
    ngx_int_t   gmtoff;//时区
} ngx_time_t;


void ngx_time_init(void);
void ngx_time_update(void);
void ngx_time_sigsafe_update(void);
u_char *ngx_http_time(u_char *buf, time_t t);
u_char *ngx_http_cookie_time(u_char *buf, time_t t);
void ngx_gmtime(time_t t, ngx_tm_t *tp);

time_t ngx_next_time(time_t when);
#define ngx_next_time_n      "mktime()"


extern volatile ngx_time_t  *ngx_cached_time;

//获取到格林威治时间1970年1月1日凌晨0点0分0秒当前时间的秒数
#define ngx_time()           ngx_cached_time->sec

//获取缓存的ngx_time_t类型时间
#define ngx_timeofday()      (ngx_time_t *) ngx_cached_time

//各种格式的时间
extern volatile ngx_str_t    ngx_cached_err_log_time;
extern volatile ngx_str_t    ngx_cached_http_time;
extern volatile ngx_str_t    ngx_cached_http_log_time;
extern volatile ngx_str_t    ngx_cached_http_log_iso8601;

/*
 * milliseconds elapsed since epoch and truncated to ngx_msec_t,
 * used in event timers
 */
extern volatile ngx_msec_t  ngx_current_msec;


#endif /* _NGX_TIMES_H_INCLUDED_ */
