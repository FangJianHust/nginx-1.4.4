
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


extern int            ngx_eventfd;
extern aio_context_t  ngx_aio_ctx;


static void ngx_file_aio_event_handler(ngx_event_t *ev);

/* ctx是文件异步I/O的上下文描述符，n是一次提交的事件个数，paiocb是需要提交的事件数组的
首个元素地址。
提交文件异步I/O操作，向异步I/O中添加事件，返回值表示成功提交的事件个数
*/
static int io_submit(aio_context_t ctx, long n, struct iocb **paiocb)
{
    return syscall(SYS_io_submit, ctx, n, paiocb);
}

/* 该方法会向异步I/O上下文中添加事件，该epoll_wait在通过ngx_eventfd描述符检测到异步I/O事件后，
会再调用ngx_epoll_eventfd_handler方法将io_event事件取出来放入ngx_posted_events队列中延后
执行，ngx_posted_events队列中的事件执行时，会调用ngx_file_aio_event_handler方法，最后调用
ngx_event_aio_t结构体的handler方法，这个方法是由真正的业务模块实现的，也就是说，任一个业务模
块想使用文件异步I/O，就可以实现该handler方法，这样在文件异步操作完成后，该方法就会被调用*/
ssize_t ngx_file_aio_read(ngx_file_t *file, u_char *buf, size_t size, off_t offset,
    ngx_pool_t *pool)
{
    ngx_err_t         err;
    struct iocb      *piocb[1];
    ngx_event_t      *ev;
    ngx_event_aio_t  *aio;

    if (!ngx_file_aio) {
        return ngx_read_file(file, buf, size, offset);
    }

    aio = file->aio;

    if (aio == NULL) {
        aio = ngx_pcalloc(pool, sizeof(ngx_event_aio_t));
        if (aio == NULL) {
            return NGX_ERROR;
        }

        aio->file = file;
        aio->fd = file->fd;
        aio->event.data = aio;
        aio->event.ready = 1;
        aio->event.log = file->log;
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

    if (ev->complete) {
        ev->active = 0;
        ev->complete = 0;

        if (aio->res >= 0) {
            ngx_set_errno(0);
            return aio->res;
        }

        ngx_set_errno(-aio->res);

        ngx_log_error(NGX_LOG_CRIT, file->log, ngx_errno,
                      "aio read \"%s\" failed", file->name.data);

        return NGX_ERROR;
    }

    ngx_memzero(&aio->aiocb, sizeof(struct iocb));

    aio->aiocb.aio_data = (uint64_t) (uintptr_t) ev;
    aio->aiocb.aio_lio_opcode = IOCB_CMD_PREAD;
    aio->aiocb.aio_fildes = file->fd;
    aio->aiocb.aio_buf = (uint64_t) (uintptr_t) buf;
    aio->aiocb.aio_nbytes = size;
    aio->aiocb.aio_offset = offset;
    aio->aiocb.aio_flags = IOCB_FLAG_RESFD;
    aio->aiocb.aio_resfd = ngx_eventfd;

	/* 设置事件的回调方法为ngx_file_aio_event_handler，它的调用关系类似这样：epoll_wait中调用ngx_epoll_eventfd_handler
	方法将当前事件放到ngx_posted_events队列中，在延后执行的队列中再调用ngx_file_aio_event_handler方法*/
    ev->handler = ngx_file_aio_event_handler;

    piocb[0] = &aio->aiocb;

    if (io_submit(ngx_aio_ctx, 1, piocb) == 1) 
	{//向ngx_aio_ctx异步I/O上下文中添加一个事件
        ev->active = 1;
        ev->ready = 0;
        ev->complete = 0;

        return NGX_AGAIN;
    }

    err = ngx_errno;

    if (err == NGX_EAGAIN) {
        return ngx_read_file(file, buf, size, offset);
    }

    ngx_log_error(NGX_LOG_CRIT, file->log, err,
                  "io_submit(\"%V\") failed", &file->name);

    if (err == NGX_ENOSYS) {
        ngx_file_aio = 0;
        return ngx_read_file(file, buf, size, offset);
    }

    return NGX_ERROR;
}


static void ngx_file_aio_event_handler(ngx_event_t *ev)
{
    ngx_event_aio_t  *aio;

    aio = ev->data;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, ev->log, 0,
                   "aio event handler fd:%d %V", aio->fd, &aio->file->name);
	/*这里调用了ngx_event_aio_t结构体的handler回调方法，这个方法是由真正的业务模块实现的，
	也就是说，任一个业务模块想使用文件异步I/O，就可以实现该handler方法，这样在文件异步操
	作完成后，该方法就会被调用*/
    aio->handler(ev);
}
