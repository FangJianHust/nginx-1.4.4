
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


/*
 * FreeBSD file AIO features and quirks:
 *
 *    if an asked data are already in VM cache, then aio_error() returns 0,
 *    and the data are already copied in buffer;
 *
 *    aio_read() preread in VM cache as minimum 16K (probably BKVASIZE);
 *    the first AIO preload may be up to 128K;
 *
 *    aio_read/aio_error() may return EINPROGRESS for just written data;
 *
 *    kqueue EVFILT_AIO filter is level triggered only: an event repeats
 *    until aio_return() will be called;
 *
 *    aio_cancel() cannot cancel file AIO: it returns AIO_NOTCANCELED always.
 */


extern int  ngx_kqueue;


static ssize_t ngx_file_aio_result(ngx_file_t *file, ngx_event_aio_t *aio,
    ngx_event_t *ev);
static void ngx_file_aio_event_handler(ngx_event_t *ev);

/* 打开文件异步I/O后，这个方法将会负责磁盘文件的读取.该方法会向异步I/O上下文中添加
事件，该epoll_wait在通过ngx_eventfd描述符检测到异步I/O事件后，会再调用
ngx_epoll_eventfd_handler方法将io_event事件取出来，放入ngx_posted_events队列中延后
执行，ngx_posted_events队列中的事件执行时，则会调用ngx_file_aio_event_handler方法*/
ssize_t ngx_file_aio_read(ngx_file_t *file, u_char *buf, size_t size, off_t offset,
    ngx_pool_t *pool)
{
    int               n;
    ngx_event_t      *ev;
    ngx_event_aio_t  *aio;

    if (!ngx_file_aio) 
	{
        return ngx_read_file(file, buf, size, offset);
    }

    aio = file->aio;

    if (aio == NULL) 
	{
        aio = ngx_pcalloc(pool, sizeof(ngx_event_aio_t));
        if (aio == NULL) {
            return NGX_ERROR;
        }

        aio->file = file;
        aio->fd = file->fd;
        aio->event.data = aio;
        aio->event.ready = 1;
        aio->event.log = file->log;
#if (NGX_HAVE_AIO_SENDFILE)
        aio->last_offset = -1;
#endif
        file->aio = aio;
    }

    ev = &aio->event;

    if (!ev->ready) {
        ngx_log_error(NGX_LOG_ALERT, file->log, 0,
                      "second aio post for \"%V\"", &file->name);
        return NGX_AGAIN;
    }

    ngx_log_debug4(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio complete:%d @%O:%z %V",
                   ev->complete, offset, size, &file->name);

	//异步I/O操作已经完成
    if (ev->complete) 
	{
        ev->complete = 0;
        ngx_set_errno(aio->err);

        if (aio->err == 0) {
            return aio->nbytes;
        }

        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "aio read \"%s\" failed", file->name.data);

        return NGX_ERROR;
    }

    ngx_memzero(&aio->aiocb, sizeof(struct aiocb));

	/* 设置iocb结构体，这里的aiocb成员就是iocb类型，注意，aio_data已经设置为这个
	ngx_event_t事件的指针，这样，从io_getevents方法获取的io_event对象中的data也
	是这个指针 */
    aio->aiocb.aio_fildes = file->fd;
    aio->aiocb.aio_offset = offset;
    aio->aiocb.aio_buf = buf;
    aio->aiocb.aio_nbytes = size;
#if (NGX_HAVE_KQUEUE)
    aio->aiocb.aio_sigevent.sigev_notify_kqueue = ngx_kqueue;
    aio->aiocb.aio_sigevent.sigev_notify = SIGEV_KEVENT;
    aio->aiocb.aio_sigevent.sigev_value.sigval_ptr = ev;
#endif

	/* 设置事件的回调方法，它的调用关系类似这样:epoll_wait中调用
	ngx_epoll_eventfd_handler方法将当前事件放到ngx_posted_events
	队列中，在延后执行的队列中调用ngx_file_aio_event_handler方法*/
    ev->handler = ngx_file_aio_event_handler;

	//把 I/O 请求加入aiocb指向的缓存区队列里
    n = aio_read(&aio->aiocb);

    if (n == -1) {
        n = ngx_errno;

        if (n == NGX_EAGAIN) {
            return ngx_read_file(file, buf, size, offset);
        }

        ngx_log_error(NGX_LOG_CRIT, file->log, n,
                      "aio_read(\"%V\") failed", &file->name);

        if (n == NGX_ENOSYS) {
            ngx_file_aio = 0;
            return ngx_read_file(file, buf, size, offset);
        }

        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio_read: fd:%d %d", file->fd, n);

    ev->active = 1;
    ev->ready = 0;
    ev->complete = 0;

    return ngx_file_aio_result(aio->file, aio, ev);
}


static ssize_t
ngx_file_aio_result(ngx_file_t *file, ngx_event_aio_t *aio, ngx_event_t *ev)
{
    int        n;
    ngx_err_t  err;

	//返回iocb指向的异步I/O操作请求的错误状态
    n = aio_error(&aio->aiocb);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio_error: fd:%d %d", file->fd, n);
	//调用失败，aio_error()返回-1，并设置errno为对应的数值
    if (n == -1) 
	{
        err = ngx_errno;
        aio->err = err;

        ngx_log_error(NGX_LOG_ALERT, file->log, err,
                      "aio_error(\"%V\") failed", &file->name);
        return NGX_ERROR;
    }

	//若异步I/O操作成功完成，aio_error()返回0；若尚未完成，返回EINPROGRESS
    if (n == NGX_EINPROGRESS) 
	{
        if (ev->ready) {
            ev->ready = 0;
            ngx_log_error(NGX_LOG_ALERT, file->log, n,
                          "aio_read(\"%V\") still in progress",
                          &file->name);
        }

        return NGX_AGAIN;
    }
	
	//异步I/O操作成功，即返回0
	/* 异步I/O和标准块I/O之间的另外一个区别是我们不能立即访问这个函数的返回状态，因为我们并
	没有阻塞在read调用上。在标准的read调用中，返回状态是在该函数返回时提供的。但是在异步I/O
	中，我们要使用aio_return函数。只有在aio_error调用确定请求已经完成（可能成功，也可能发生
	了错误）之后，才会调用这个函数。aio_return的返回值就等价于同步情况中read或write系统调用
	的返回值（所传输的字节数，如果发生错误，返回值就为-1） */
    n = aio_return(&aio->aiocb);

    if (n == -1) {
        err = ngx_errno;
        aio->err = err;
        ev->ready = 1;

        ngx_log_error(NGX_LOG_CRIT, file->log, err,
                      "aio_return(\"%V\") failed", &file->name);
        return NGX_ERROR;
    }

    aio->err = 0;
    aio->nbytes = n;
    ev->ready = 1;
    ev->active = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, file->log, 0,
                   "aio_return: fd:%d %d", file->fd, n);

    return n;
}

/* 这里调用了ngx_event_aio_t结构体的handler回调方法，这个回调方法是由真正的业务模块
实现的，也就是说，任一个业务模块想使用文件异步I/O，就可以实现handler方法，这样，在
文件异步操作完成后，该方法就会被回调*/
static void ngx_file_aio_event_handler(ngx_event_t *ev)
{
    ngx_event_aio_t  *aio;

    aio = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);

    if (ngx_file_aio_result(aio->file, aio, ev) != NGX_AGAIN) {
        aio->handler(ev);
    }
}
