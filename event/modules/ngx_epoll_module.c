#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>

#if (NGX_TEST_BUILD_EPOLL)

/* epoll declarations */

//表示对应的连接上有数据可以读出(如果是TCP连接的远端主动关闭连接也相当于可读事件，因为需要处理发送来的FIN包)
#define EPOLLIN        0x001

//表示对应的连接上可以写入数据发送(如果是主动向上游服务器发起的非阻塞的TCP连接，连接建立成功的事件也相当于可写事件)
#define EPOLLPRI       0x002
#define EPOLLOUT       0x004
#define EPOLLRDNORM    0x040
#define EPOLLRDBAND    0x080
#define EPOLLWRNORM    0x100
#define EPOLLWRBAND    0x200
#define EPOLLMSG       0x400
#define EPOLLERR       0x008
#define EPOLLHUP       0x010
//表示将触发方式设置为边缘触发(ET),系统默认的是水平触发(LT)
#define EPOLLET        0x80000000
#define EPOLLONESHOT   0x40000000

#define EPOLL_CTL_ADD  1
#define EPOLL_CTL_DEL  2
#define EPOLL_CTL_MOD  3

typedef union epoll_data 
{
	//ngx_epoll_module模块只使用了ptr成员作为指向ngx_connection_t连接的指针
    void         *ptr;
    int           fd;
    uint32_t      u32;
    uint64_t      u64;
} epoll_data_t;

struct epoll_event {
    uint32_t      events;
    epoll_data_t  data;
};

//创建一个epoll文件描述符
int epoll_create(int size);

int epoll_create(int size)
{
    return -1;
}

//添加/修改/删除需要侦听的文件描述符及其事件
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return -1;
}
//接收发生在被侦听的描述符上的，用户感兴趣的IO事件,类似于selecct
int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout);

int epoll_wait(int epfd, struct epoll_event *events, int nevents, int timeout)
{
    return -1;
}

#if (NGX_HAVE_FILE_AIO)

#define SYS_io_setup      245
#define SYS_io_destroy    246
#define SYS_io_getevents  247
#define SYS_eventfd       323

typedef u_int  aio_context_t;

typedef enum io_iocb_cmd
{
	//异步读操作
	IO_CMD_PREAD = 0;

	//异步写操作
	IO_CMD_PWRITE = 1;

	//强制同步
	IO_CMD_FSYNC = 2;

	IO_CMD_FDSYNC = 3;
	IO_CMD_POLL = 5;
	IO_CMD_NOOP = 6;
}io_iocb_cmd_t;
struct iocb
{
	/* 存储着业务需要的指针，例如在nginx中，这个字段通常存储着对应的ngx_event_t
	事件的指针，它实际上与io_getevents方法中返回的io_event结构体的data成员是完全
	一致的*/
	u_int64_t aio_data;
	u_int32_t PADDED(aio_key,aio_reserved1);

	//操作码，其取值范围是io_iocb_cmd_t中的枚举命令
	u_int16_t aio_lio_opcode;

	//请求的优先级
	int16_t aio_reqprio;

	//文件描述符
	u_int32_t aio_fildes;

	//读写操作对应的用户态缓冲区
	u_int64_t aio_buf;

	//读写缓冲区的字节长度
	u_int64_t aio_nbytes;

	//读写操作对应于文件操作中的偏移量
	int64_t aio_offset;

	//保留字段
	u_int64_t aio_reserved2;

	/* 表示可以设置为IOCB_FLAG_RESFD,它会告诉内核当有异步I/O请求处理完成时使用
	eventfd进行通知，可与epoll配合使用，其在Nginx中的使用见9.9.2*/
	u_int32_t aio_flags;

	//表示当使用IOCB_FLAG_RESFD标志位时，用于进行事件通知的句柄
	u_int32_t aio_resfd;
};
struct io_event 
{	
	//与提交事件时对应的iocb结构体中的aio_data是一致的
    uint64_t  data;  /* the data field from the iocb */
	//指向提交事件时对应的iocb结构体
    uint64_t  obj;   /* what iocb this event came from */
	//异步I/O请求的结构，res>=0时表示成功，小于0时表示失败
    int64_t   res;   /* result code for this event */
	//保留字段
    int64_t   res2;  /* secondary result */
};


#endif
#endif

//存储ngx_epoll_module配置项的结构体
typedef struct 
{
    ngx_uint_t  events;//调用epoll_wait方法时传入的第3个参数，而第2个参数events数组的大小也是由它决定的
    ngx_uint_t  aio_requests;
} ngx_epoll_conf_t;

static ngx_int_t ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer);
static void ngx_epoll_done(ngx_cycle_t *cycle);
static ngx_int_t ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event,ngx_uint_t flags);
static ngx_int_t ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event,ngx_uint_t flags);
static ngx_int_t ngx_epoll_add_connection(ngx_connection_t *c);
static ngx_int_t ngx_epoll_del_connection(ngx_connection_t *c,ngx_uint_t flags);
static ngx_int_t ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,ngx_uint_t flags);

#if (NGX_HAVE_FILE_AIO)
static void ngx_epoll_eventfd_handler(ngx_event_t *ev);
#endif

static void *ngx_epoll_create_conf(ngx_cycle_t *cycle);
static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf);

static int                  ep = -1;//epoll对象的描述符

//该数组就是用于在epoll_wait调用中接收事件的参数
static struct epoll_event  *event_list;
static ngx_uint_t           nevents;

#if (NGX_HAVE_FILE_AIO)

//用于通知异步I/O事件的描述符，它与iocb结构体中的aio_resfd成员是一致的
int                         ngx_eventfd = -1;

//异步I/O的上下文，全局唯一，必须经过io_setup初始化才能使用
aio_context_t               ngx_aio_ctx = 0;

//异步I/O事件完成后进行通知的描述符，也就是ngx_eventfd所对应的ngx_enent_t事件
static ngx_event_t          ngx_eventfd_event;

//异步I/O事件完成后进行通知的描述符ngx_eventfd所对应的ngx_connection_t连接
static ngx_connection_t     ngx_eventfd_conn;

#endif

static ngx_str_t      epoll_name = ngx_string("epoll");

//ngx_epoll_module模块感兴趣的配置项
static ngx_command_t  ngx_epoll_commands[] = {

	//在调用epoll_wait时，将由第2和第3个参数告诉Linux内核一次最多可返回多少个事件，这个配置项表示调用epoll_wait时最多可以返回的事件数
    { ngx_string("epoll_events"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, events),
      NULL },
	
	  //在开启异步I/O且使用io_setup系统调用初始化异步I/O上下文环境时，初始分配的异步I/O事件个数
    { ngx_string("worker_aio_requests"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      0,
      offsetof(ngx_epoll_conf_t, aio_requests),
      NULL },
      ngx_null_command
};

//每个事件模块都必须实现的事件模块接口
ngx_event_module_t  ngx_epoll_module_ctx = {
    &epoll_name,
    ngx_epoll_create_conf,               /* create configuration */
    ngx_epoll_init_conf,                 /* init configuration */
    {
        ngx_epoll_add_event,             /* add an event */
        ngx_epoll_del_event,             /* delete an event */
        ngx_epoll_add_event,             /* enable an event */
        ngx_epoll_del_event,             /* disable an event */
        ngx_epoll_add_connection,        /* add an connection */
        ngx_epoll_del_connection,        /* delete an connection */
        NULL,                            /* process the changes */
        ngx_epoll_process_events,        /* process the events */
        ngx_epoll_init,                  /* init the events,在Nginx的启动过程中被调用 */
        ngx_epoll_done,                  /* done the events */
    }
};

//epoll_module模块的定义
ngx_module_t  ngx_epoll_module = {
    NGX_MODULE_V1,
    &ngx_epoll_module_ctx,               /* module context */
    ngx_epoll_commands,                  /* module directives */
    NGX_EVENT_MODULE,                    /* module type */
    NULL,                                /* init master */
    NULL,                                /* init module */
    NULL,                                /* init process */
    NULL,                                /* init thread */
    NULL,                                /* exit thread */
    NULL,                                /* exit process */
    NULL,                                /* exit master */
    NGX_MODULE_V1_PADDING
};

#if (NGX_HAVE_FILE_AIO)

/*
 * We call io_setup(), io_destroy() io_submit(), and io_getevents() directly
 * as syscalls instead of libaio usage, because the library header file
 * supports eventfd() since 0.3.107 version only.
 *
 * Also we do not use eventfd() in glibc, because glibc supports it
 * since 2.8 version and glibc maps two syscalls eventfd() and eventfd2()
 * into single eventfd() function with different number of parameters.
 */

/* 初始化文件异步I/O的上下文，执行成功后ctx就是分配的上下文描述符，这个异步I/O上下文将至少可以处理nr_reqs个事件,返回0表示成功*/
static int io_setup(u_int nr_reqs, aio_context_t *ctx)
{
    return syscall(SYS_io_setup, nr_reqs, ctx);
}

//销毁文件异步I/O的上下文，返回0表示成功
static int io_destroy(aio_context_t ctx)
{
    return syscall(SYS_io_destroy, ctx);
}

/*从已经完成的文件异步I/O操作队列中读取操作，相当于epoll中的epoll_wait方法
ctx是文件异步I/O的上下文描述符;min_nr表示至少要获取的事件个数;而nr表示至多获取的事件
个数，它与events数组的个数一般是相同的；events是已经完成的异步I/O操作；timeout是超时时间
，也就是在获取min_nr个事件前的等待时间*/
static int io_getevents(aio_context_t ctx, long min_nr, long nr, struct io_event *events,struct timespec *tmo)
{
    return syscall(SYS_io_getevents, ctx, min_nr, nr, events, tmo);
}

/* 该方法会把异步I/O与epoll结合起来，当某一个异步I/O事件完成后，ngx_eventfd句柄就处于可
用状态，这样epoll_wait在返回ngx_eventfd_event事件后就会调用它的回调方法
ngx_epoll_eventfd_handler处理已经完成的异步I/O事件*/
static void ngx_epoll_aio_init(ngx_cycle_t *cycle, ngx_epoll_conf_t *epcf)
{
    int                 n;
    struct epoll_event  ee;

	//获取一个描述符句柄，用于通知异步I/O事件
    ngx_eventfd = syscall(SYS_eventfd, 0);

    if (ngx_eventfd == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "eventfd() failed");
        ngx_file_aio = 0;
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "eventfd: %d", ngx_eventfd);

    n = 1;

	//设置ngx_eventfd为非阻塞，n=0表示清除，非0表示设置
    if (ioctl(ngx_eventfd, FIONBIO, &n) == -1) 
	{
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "ioctl(eventfd, FIONBIO) failed");
        goto failed;
    }

	//初始化异步I/O的上下文
    if (io_setup(epcf->aio_requests, &ngx_aio_ctx) == -1) 
	{
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "io_setup() failed");
        goto failed;
    }

	//设置用于异步I/O完成通知的ngx_eventfd_event事件，它与ngx_eventfd_conn连接是对应的
    ngx_eventfd_event.data = &ngx_eventfd_conn;

	//在异步I/O事件完成后，使用该方法处理
    ngx_eventfd_event.handler = ngx_epoll_eventfd_handler;
    ngx_eventfd_event.log = cycle->log;
    ngx_eventfd_event.active = 1;

	//初始化ngx_eventfd_conn连接
    ngx_eventfd_conn.fd = ngx_eventfd;

	//ngx_eventfd_conn连接的读事件就是上面的ngx_eventfd_event
    ngx_eventfd_conn.read = &ngx_eventfd_event;
    ngx_eventfd_conn.log = cycle->log;

    ee.events = EPOLLIN|EPOLLET;
    ee.data.ptr = &ngx_eventfd_conn;

	//向epoll中添加到异步I/O的通知描述符ngx_eventfd
    if (epoll_ctl(ep, EPOLL_CTL_ADD, ngx_eventfd, &ee) != -1) 
	{
        return;
    }

    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                  "epoll_ctl(EPOLL_CTL_ADD, eventfd) failed");

    if (io_destroy(ngx_aio_ctx) == -1) 
	{
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "io_destroy() failed");
    }

failed:

    if (close(ngx_eventfd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "eventfd close() failed");
    }

    ngx_eventfd = -1;
    ngx_aio_ctx = 0;
    ngx_file_aio = 0;
}

#endif

//Nginx启动过程中调用，主要做了两件事：调用epoll_create方法创建epoll对象;创建event_list数组，用于进行epoll_wait调用时传递内核态的事件
static ngx_int_t ngx_epoll_init(ngx_cycle_t *cycle, ngx_msec_t timer)
{
    ngx_epoll_conf_t  *epcf;
	//获取create_conf中生成的ngx_epoll_conf_t结构体，它已经被赋予解析完配置项文件后的值
    epcf = ngx_event_get_conf(cycle->conf_ctx, ngx_epoll_module);
	//epoll对象的描述符，为-1表示还没有创建epoll对象
    if (ep == -1) 
	{
		//创建epoll对象，其中参数不是用于指明epoll能够处理的最大事件个数，该参数没有用处
        ep = epoll_create(cycle->connection_n / 2);
        if (ep == -1) 
		{
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,"epoll_create() failed");
            return NGX_ERROR;
        }
//如果开启了文件异步I/O
#if (NGX_HAVE_FILE_AIO)
        ngx_epoll_aio_init(cycle, epcf);
#endif
    }
    if (nevents < epcf->events)
	{
        if (event_list) 
		{
            ngx_free(event_list);
        }
		//初始化event_list数组，数组的个数是配置项epoll_events的参数
        event_list = ngx_alloc(sizeof(struct epoll_event) * epcf->events,cycle->log);
        if (event_list == NULL)
        {
            return NGX_ERROR;
        }
    }
    nevents = epcf->events;//nevents也是配置项epoll_events的参数
    ngx_io = ngx_os_io;//指明读写IO的方法
    ngx_event_actions = ngx_epoll_module_ctx.actions;//设置ngx_event_actions接口
#if (NGX_HAVE_CLEAR_EVENT)
    ngx_event_flags = NGX_USE_CLEAR_EVENT //默认采用ET模式来使用epoll的，NGX_USR_CLEAR_EVENT宏实际上就是在告诉Nginx使用ET模式
#else
    ngx_event_flags = NGX_USE_LEVEL_EVENT
#endif
                      |NGX_USE_GREEDY_EVENT
                      |NGX_USE_EPOLL_EVENT;
    return NGX_OK;
}

//nginx退出服务时调用，关闭epoll描述符ep，同时释放event_list数组
static void ngx_epoll_done(ngx_cycle_t *cycle)
{
	//关闭epoll描述符,epoll中监听的事件都会被取消
    if (close(ep) == -1) 
	{
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"epoll close() failed");
    }
    ep = -1;
#if (NGX_HAVE_FILE_AIO)
    if (ngx_eventfd != -1)
    {
        if (io_destroy(ngx_aio_ctx) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"io_destroy() failed");
        }
        if (close(ngx_eventfd) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"eventfd close() failed");
        }
        ngx_eventfd = -1;
    }
    ngx_aio_ctx = 0;
#endif
	//释放event_list数组
    ngx_free(event_list);
    event_list = NULL;
    nevents = 0;
}

//通过调用epoll_ctl向epoll中添加事件
static ngx_int_t ngx_epoll_add_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             events, prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;
	//每个事件的data成员都存放着其对应的ngx_connection_t连接
    c = ev->data;
	//下面会根据event参数确定当前事件是读事件还是写事件，这会决定events是加上EPOLLIN标志还是EPOLLOUT标志
    events = (uint32_t) event;
    if (event == NGX_READ_EVENT) 
	{
        e = c->write;
        prev = EPOLLOUT;
#if (NGX_READ_EVENT != EPOLLIN)
        events = EPOLLIN;
#endif
    }
	else 
	{
        e = c->read;
        prev = EPOLLIN;
#if (NGX_WRITE_EVENT != EPOLLOUT)
        events = EPOLLOUT;
#endif
    }
	//根据active确定是否为活跃事件，以决定到底是修改还是添加事件，如果当前事件是活跃的，则说明已经添加过了，现在是修改该事件
    if (e->active) 
	{
        op = EPOLL_CTL_MOD;
        events |= prev;
    } 
	else 
	{
        op = EPOLL_CTL_ADD;
    }
    ee.events = events | (uint32_t) flags;//加入flags参数到events标志位中
    ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);//ptr成员存储的是ngx_connection_t连接
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,"epoll add event: fd:%d op:%d ev:%08XD",c->fd, op, ee.events);
	//调用epoll_ctl方法向epoll中添加事件或者在epoll中修改事件
    if (epoll_ctl(ep, op, c->fd, &ee) == -1) 
	{
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,"epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }
    ev->active = 1;//表示当前事件时活跃的
#if 0
    ev->oneshot = (flags & NGX_ONESHOT_EVENT) ? 1 : 0;
#endif
    return NGX_OK;
}

//通过epoll_ctl删除epoll中的事件
static ngx_int_t ngx_epoll_del_event(ngx_event_t *ev, ngx_int_t event, ngx_uint_t flags)
{
    int                  op;
    uint32_t             prev;
    ngx_event_t         *e;
    ngx_connection_t    *c;
    struct epoll_event   ee;
    /* when the file descriptor is closed, the epoll automatically deletes it from its queue, so we do not need to
     * delete explicitly the event before the closing the file descriptor。如果epoll描述符被关闭，则该epoll
     * 上的事件会自动被删除 */
    if (flags & NGX_CLOSE_EVENT)
    {
        ev->active = 0;
        return NGX_OK;
    }
    c = ev->data;
    if (event == NGX_READ_EVENT)
    {
        e = c->write;
        prev = EPOLLOUT;
    }
    else
    {
        e = c->read;
        prev = EPOLLIN;
    }
    if (e->active)
    {
        op = EPOLL_CTL_MOD;
        ee.events = prev | (uint32_t) flags;
        ee.data.ptr = (void *) ((uintptr_t) c | ev->instance);
    }
    else
    {
        op = EPOLL_CTL_DEL;
        ee.events = 0;//调用EPOLL_CTL_DEL时，事件设置为0
        ee.data.ptr = NULL;
    }
    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ev->log, 0,"epoll del event: fd:%d op:%d ev:%08XD",c->fd, op, ee.events);
    if (epoll_ctl(ep, op, c->fd, &ee) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,"epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }
    ev->active = 0;
    return NGX_OK;
}

//添加该连接的读写事件到epoll中
static ngx_int_t ngx_epoll_add_connection(ngx_connection_t *c)
{
    struct epoll_event  ee;
    ee.events = EPOLLIN|EPOLLOUT|EPOLLET;//添加该连接的读写事件到epoll中，epoll默认使用ET模式，为了提高效率
    ee.data.ptr = (void *) ((uintptr_t) c | c->read->instance);
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,"epoll add connection: fd:%d ev:%08XD", c->fd, ee.events);
    if (epoll_ctl(ep, EPOLL_CTL_ADD, c->fd, &ee) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno, "epoll_ctl(EPOLL_CTL_ADD, %d) failed", c->fd);
        return NGX_ERROR;
    }
    c->read->active = 1;
    c->write->active = 1;
    return NGX_OK;
}

static ngx_int_t ngx_epoll_del_connection(ngx_connection_t *c, ngx_uint_t flags)
{
    int                 op;
    struct epoll_event  ee;
    /* when the file descriptor is closed the epoll automatically deletes it from its queue so we do not need to
     * delete explicitly the event before the closing the file descriptor */
    if (flags & NGX_CLOSE_EVENT)
    {
        c->read->active = 0;
        c->write->active = 0;
        return NGX_OK;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,"epoll del connection: fd:%d", c->fd);
    op = EPOLL_CTL_DEL;
    ee.events = 0;
    ee.data.ptr = NULL;
    if (epoll_ctl(ep, op, c->fd, &ee) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno, "epoll_ctl(%d, %d) failed", op, c->fd);
        return NGX_ERROR;
    }
    c->read->active = 0;
    c->write->active = 0;
    return NGX_OK;
}

//实现了收集、分发事件的process_events接口的方法
static ngx_int_t ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer, ngx_uint_t flags)
{
    int                events;
    uint32_t           revents;
    ngx_int_t          instance, i;
    ngx_uint_t         level;
    ngx_err_t          err;
    ngx_event_t       *rev, *wev, **queue;
    ngx_connection_t  *c;
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,"epoll timer: %M", timer);
	/*调用epoll_wait获取事件,如果没有事件准备好，当timer==NGX_TIMER_INFINITE时立即返回，为正数时，最长等待timer后返回,注意，
	 * 此处的epoll_wait不是在循环中调用的*/
    events = epoll_wait(ep, event_list, (int) nevents, timer);
    err = (events == -1) ? ngx_errno : 0;
    if (flags & NGX_UPDATE_TIME || ngx_event_timer_alarm) 
	{
        ngx_time_update();//更新时间
    }
    if (err) 
	{
        if (err == NGX_EINTR) 
		{
            if (ngx_event_timer_alarm) 
			{
                ngx_event_timer_alarm = 0;
                return NGX_OK;
            }
            level = NGX_LOG_INFO;
        }
		else 
		{
            level = NGX_LOG_ALERT;
        }
        ngx_log_error(level, cycle->log, err, "epoll_wait() failed");
        return NGX_ERROR;
    }
	//没有事件发生
    if (events == 0) 
	{
        if (timer != NGX_TIMER_INFINITE) 
		{
            return NGX_OK;
        }
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,"epoll_wait() returned no events without timeout");
        return NGX_ERROR;
    }
	//互斥的处理事件
    ngx_mutex_lock(ngx_posted_events_mutex);
	//遍历本次epoll_wait返回的所有事件
    for (i = 0; i < events; i++) 
	{
		//对照着ngx_epoll_add_event方法，可以看到ptr就是ngx_connection_t连接的地址，但是最后1位有特殊含义，需要把它屏蔽掉
        c = event_list[i].data.ptr;
        instance = (uintptr_t) c & 1;//将地址的最后一位取出来，用 instance变量标识
		//无论是32位还是64位机器，其地址最后1位肯定是0，可以用该语句把ngx_connection_t的地址还原到真正的地址值
        c = (ngx_connection_t *) ((uintptr_t) c & (uintptr_t) ~1);
        rev = c->read;//取出读事件
        if (c->fd == -1 || rev->instance != instance)//判断这个读事件是否为过期事件
		{
            /* the stale event from a file descriptor that was just closed in this iteration */
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,"epoll: stale event %p", c);
            continue;
        }
        revents = event_list[i].events;//取出事件类型
        ngx_log_debug3(NGX_LOG_DEBUG_EVENT, cycle->log, 0,"epoll: fd:%d ev:%04XD d:%p",c->fd, revents, event_list[i].data.ptr);
        if (revents & (EPOLLERR|EPOLLHUP)) 
		{
            ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,"epoll_wait() error on fd:%d ev:%04XD", c->fd, revents);
        }
#if 0
        if (revents & ~(EPOLLIN|EPOLLOUT|EPOLLERR|EPOLLHUP))
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,"strange epoll_wait() events fd:%d ev:%04XD",c->fd, revents);
        }
#endif
        if ((revents & (EPOLLERR|EPOLLHUP)) && (revents & (EPOLLIN|EPOLLOUT)) == 0)
        {
            /* if the error events were returned without EPOLLIN or EPOLLOUT, then add these flags to handle the
             * events at least in one active handler */
            revents |= EPOLLIN|EPOLLOUT;
        }
		//如果是读事件且该事件是活跃的
        if ((revents & EPOLLIN) && rev->active) 
		{
            if ((flags & NGX_POST_THREAD_EVENTS) && !rev->accept) 
			{
                rev->posted_ready = 1;
            }
			else 
			{
                rev->ready = 1;
            }
			//表示该事件要延后处理
            if (flags & NGX_POST_EVENTS)
			{
				/*如果要在post队列中延后处理该事件，首先要判断它是新连接事件还是普通事件，以决定把它加入到ngx_posted_accept_events
				 * 队列或者ngx_posted_events队列中*/
                queue = (ngx_event_t **) (rev->accept ? &ngx_posted_accept_events : &ngx_posted_events);
                ngx_locked_post_event(rev, queue);//将这个事件添加到相应的延后执行队列中
            } 
			else 
			{
                rev->handler(rev);//立即调用读事件的回调方法来处理这个事件
            }
        }
        wev = c->write;//取出写事件
        if ((revents & EPOLLOUT) && wev->active) 
		{
            if (c->fd == -1 || wev->instance != instance) //判断这个写事件是否为过期事件
			{
                /* the stale event from a file descriptor that was just closed in this iteration */
                ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,"epoll: stale event %p", c);
                continue;
            }
            if (flags & NGX_POST_THREAD_EVENTS)
            {
                wev->posted_ready = 1;
            }
            else
            {
                wev->ready = 1;
            }
            if (flags & NGX_POST_EVENTS)
			{
                ngx_locked_post_event(wev, &ngx_posted_events);//将这个事件添加到post队列中延后处理
            } 
			else
			{
                wev->handler(wev);//立即调用这个写事件的方法来处理这个事件
            }
        }
    }
    ngx_mutex_unlock(ngx_posted_events_mutex);
    return NGX_OK;
}


#if (NGX_HAVE_FILE_AIO)

//处理已完成的异步I/O事件的回调方法,一个异步I/O句柄关联着很多事件
static void ngx_epoll_eventfd_handler(ngx_event_t *ev)
{
    int               n, events;
    long              i;
    uint64_t          ready;
    ngx_err_t         err;
    ngx_event_t      *e;
    ngx_event_aio_t  *aio;
    struct io_event   event[64];//一次最多处理64个事件
    struct timespec   ts;

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd handler");

	//获取已完成的事件数目，并设置到ready中，注意，这个ready是可以大于64的
    n = read(ngx_eventfd, &ready, 8);
    err = ngx_errno;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0, "eventfd: %d", n);

    if (n != 8) 
	{
        if (n == -1) 
		{
            if (err == NGX_EAGAIN) {
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ev->log, err, "read(eventfd) failed");
            return;
        }

        ngx_log_error(NGX_LOG_ALERT, ev->log, 0,
                      "read(eventfd) returned only %d bytes", n);
        return;
    }

    ts.tv_sec = 0;
    ts.tv_nsec = 0;

	//ready表示还未处理的事件个数
    while (ready) 
	{
		//获取已完成的异步I/O事件
        events = io_getevents(ngx_aio_ctx, 1, 64, event, &ts);
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                       "io_getevents: %l", events);

        if (events > 0) 
		{
            ready -= events;
			
			//处理event数组里的事件
            for (i = 0; i < events; i++) 
			{
                ngx_log_debug4(NGX_LOG_DEBUG_EVENT, ev->log, 0,
                               "io_event: %uXL %uXL %L %L",
                                event[i].data, event[i].obj,
                                event[i].res, event[i].res2);

				//data成员指向这个异步I/O事件对应着的实际事件
                e = (ngx_event_t *) (uintptr_t) event[i].data;
				
                e->complete = 1;
                e->active = 0;
                e->ready = 1;

                aio = e->data;
                aio->res = event[i].res;

				//将该事件放到ngx_posted_events队列中延后执行
                ngx_post_event(e, &ngx_posted_events);
            }

            continue;
        }

        if (events == 0) {
            return;
        }

        /* events == -1 */
        ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                      "io_getevents() failed");
        return;
    }
}

#endif

//创建存储配置项参数的结构体
static void * ngx_epoll_create_conf(ngx_cycle_t *cycle)
{
    ngx_epoll_conf_t  *epcf;
    epcf = ngx_palloc(cycle->pool, sizeof(ngx_epoll_conf_t));
    if (epcf == NULL) {
        return NULL;
    }
    epcf->events = NGX_CONF_UNSET;
    epcf->aio_requests = NGX_CONF_UNSET;
    return epcf;
}
//解析完配置项后调用该方法方法
static char *ngx_epoll_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_epoll_conf_t *epcf = conf;
    ngx_conf_init_uint_value(epcf->events, 512);
    ngx_conf_init_uint_value(epcf->aio_requests, 32);
    return NGX_CONF_OK;
}
