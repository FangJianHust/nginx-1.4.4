
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define DEFAULT_CONNECTIONS  512


extern ngx_module_t ngx_kqueue_module;
extern ngx_module_t ngx_eventport_module;
extern ngx_module_t ngx_devpoll_module;
extern ngx_module_t ngx_epoll_module;
extern ngx_module_t ngx_rtsig_module;
extern ngx_module_t ngx_select_module;


static char *ngx_event_init_conf(ngx_cycle_t *cycle, void *conf);
static ngx_int_t ngx_event_module_init(ngx_cycle_t *cycle);
static ngx_int_t ngx_event_process_init(ngx_cycle_t *cycle);
static char *ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static void *ngx_event_core_create_conf(ngx_cycle_t *cycle);
static char *ngx_event_core_init_conf(ngx_cycle_t *cycle, void *conf);

//不为0表示nginx.conf中设置了timer_resolution配置项，即设置了时间间隔为ngx_timer_resolution
static ngx_uint_t     ngx_timer_resolution;

sig_atomic_t          ngx_event_timer_alarm;//为1表示需要更新时间

static ngx_uint_t     ngx_event_max_module;

ngx_uint_t            ngx_event_flags;
ngx_event_actions_t   ngx_event_actions;


static ngx_atomic_t   connection_counter = 1;
ngx_atomic_t         *ngx_connection_counter = &connection_counter;


ngx_atomic_t         *ngx_accept_mutex_ptr;
ngx_shmtx_t           ngx_accept_mutex;

//开启负载均衡锁
ngx_uint_t            ngx_use_accept_mutex;

ngx_uint_t            ngx_accept_events;

/*ngx_accept_mutex_held为1表示当前进程已经获取到锁了，是当前进程的一个全局变量，这个标志
主要用于进程内各模块了解是否获取到了ngx_accepte_mutex锁*/
ngx_uint_t            ngx_accept_mutex_held;

ngx_msec_t            ngx_accept_mutex_delay;

/*负载均衡的阀值，当它为负数时，不会进行触发负载均衡操作；而当它为正数时，就会触发
负载均衡，即当ngx_accept_disabled是正数时，当前进程将不再处理新连接事件，取而代之
的是ngx_accept_disabled值减1*/
ngx_int_t             ngx_accept_disabled;

ngx_file_t            ngx_accept_mutex_lock_file;


#if (NGX_STAT_STUB)
//已经接建立成功过的TCP连接数
ngx_atomic_t   ngx_stat_accepted0;
ngx_atomic_t  *ngx_stat_accepted = &ngx_stat_accepted0;

ngx_atomic_t   ngx_stat_handled0;
ngx_atomic_t  *ngx_stat_handled = &ngx_stat_handled0;
ngx_atomic_t   ngx_stat_requests0;
ngx_atomic_t  *ngx_stat_requests = &ngx_stat_requests0;

/* 已经从ngx_cycle_t核心结构体的free_connections 连接池中获取到ngx_connection_t对象的活跃连接数*/
ngx_atomic_t   ngx_stat_active0;
ngx_atomic_t  *ngx_stat_active = &ngx_stat_active0;
ngx_atomic_t   ngx_stat_reading0;
ngx_atomic_t  *ngx_stat_reading = &ngx_stat_reading0;
ngx_atomic_t   ngx_stat_writing0;
ngx_atomic_t  *ngx_stat_writing = &ngx_stat_writing0;
ngx_atomic_t   ngx_stat_waiting0;
ngx_atomic_t  *ngx_stat_waiting = &ngx_stat_waiting0;

#endif

//ngx_event_commands数组决定了ngx_events_module模块是如何定制其功能的，因为任何模块都是以配置项来定制其功能的
static ngx_command_t  ngx_events_commands[] = 
{
    { ngx_string("events"),//ngx_events_module模块只对event{……}模块感兴趣
      NGX_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_events_block,
      0,
      0,
      NULL },

      ngx_null_command
};
/*ngx_events_module模块并不会解析配置项的参数，只是在出现events配置项后会调用各事件模块去解析evnets{……}块内的配置项，
 * 自然不需要实现create_conf方法来创建存储配置项参数的结构体*/
static ngx_core_module_t  ngx_events_module_ctx = {
    ngx_string("events"),
    NULL,
    ngx_event_init_conf
};
//事件模块的定义
ngx_module_t  ngx_events_module = {
    NGX_MODULE_V1,
    &ngx_events_module_ctx,                /* module context */
    ngx_events_commands,                   /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_str_t  event_core_name = ngx_string("event_core");

//ngx_event_core_module模块感兴趣的配置项
static ngx_command_t  ngx_event_core_commands[] = {

    { ngx_string("worker_connections"),//连接池的大小，也就是每个worker进程支持的TCP最大连接数，它与下面的connections配置项的意义是重复的
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_connections,
      0,
      0,
      NULL },

    { ngx_string("connections"),
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_connections,
      0,
      0,
      NULL },

    { ngx_string("use"),//确定选择哪一个事件模块 作为事件驱动机制
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_use,
      0,
      0,
      NULL },

    { ngx_string("multi_accept"),//对于epolle事件驱动模式来说哦，意味着在接收到一个新连接事件时，调用accept以尽可能多的接收连接
      NGX_EVENT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_event_conf_t, multi_accept),
      NULL },

    { ngx_string("accept_mutex"),//确定是否使用accept_mutex负载均衡锁，默认为开启
      NGX_EVENT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_event_conf_t, accept_mutex),
      NULL },

    { ngx_string("accept_mutex_delay"),//启用accpet_mutex负载均衡锁后，延迟accept_mutex_delay毫秒后再试图处理新连接事件
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      0,
      offsetof(ngx_event_conf_t, accept_mutex_delay),
      NULL },

    { ngx_string("debug_connection"),//需要对来自指定IP的TCP连接打印debug级别的调试日志
      NGX_EVENT_CONF|NGX_CONF_TAKE1,
      ngx_event_debug_connection,
      0,
      0,
      NULL },

      ngx_null_command
};
//因为ngx_event_core_module没有实现ngx_event_actions_t方法，因为它不真正负责TCP网络事件的驱动
ngx_event_module_t  ngx_event_core_module_ctx = {
    &event_core_name,
    ngx_event_core_create_conf,            /* create configuration */
    ngx_event_core_init_conf,              /* init configuration */

    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

ngx_module_t  ngx_event_core_module = {
    NGX_MODULE_V1,
    &ngx_event_core_module_ctx,            /* module context */
    ngx_event_core_commands,               /* module directives */
    NGX_EVENT_MODULE,                      /* module type */
    NULL,                                  /* init master */
    ngx_event_module_init,		/* 在Nginx启动过程中还没有fork出worker子进程时，会首先调用该方法 */
    ngx_event_process_init,		/* 在fork出worker子进程后，每一个worker进程会在调用该方法后才会进入正式的工作循环 */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

/* 每个worker进程都在ngx_worker_proecss_cycle方法中循环处理事件，处理事件实际上就是调用该方法，
该方法的核心操作主要有三个：
调用所使用的事件驱动模块实现的process_events方法，处理网络事件
处理两个post事件队列中的事件，实际上就是分别调用ngx_event_proecss_posted和ngx_evnet_process_posted方法
处理定时器事件，实际上就是调用ngx_event_expire_timers方法 */
void ngx_process_events_and_timers(ngx_cycle_t *cycle)
{
    ngx_uint_t  flags;
    ngx_msec_t  timer, delta;
	/* 如果配置文件中使用了timer_resolution配置项，则说明用户希望服务器时间精度为ngx_timer_resolution毫秒，这时，将ngx_process_events的timer参数
	 * 设为-1，告诉ngx_process_events方法在检测事件时不要等待，直接搜集所有已经就绪的事件然后返回；同时将flags参数初始化为0，告诉ngx_process_events
	 * 没有任何附加动作*/
    if (ngx_timer_resolution) 
	{
        timer = NGX_TIMER_INFINITE;
        flags = 0;
    } 
    /* 如果没有使用timer_resolution,那么将调用ngx_event_find_timer()方法获取最近一个将要触发的事件距离现在有多少毫秒，然后把这个时间
    赋予timer参数，告诉ngx_process_events方法在检测事件时如果没有任何事件，最多等待timer毫秒就返回；将flags参数设置为NGX_UPDATA_TIME,
    告诉ngx_process_events方法更新缓存的时间*/
	else 
	{
        timer = ngx_event_find_timer();
        flags = NGX_UPDATE_TIME;
#if (NGX_THREADS)
        if (timer == NGX_TIMER_INFINITE || timer > 500) {
            timer = 500;
        }

#endif
    }
	//如果在配置文件中使用accept_mutex打开了accept_mutex锁
    if (ngx_use_accept_mutex) 
	{	
		//检测负载均衡阀值
        if (ngx_accept_disabled > 0) 
		{
            ngx_accept_disabled--;
        }
		else 
		{
			//如果为负数，表明还没有触发到负载均衡机制，此时要调用ngx_trylock_accept_mutex方法试图获取accept_mutex锁
            if (ngx_trylock_accept_mutex(cycle) == NGX_ERROR) 
			{
                return;
            }
			/*如果获取到accept_mutex锁，也就是说，ngx_accept_mutex_held标志位为1.那么将flags参数加上NGX_POST_EVENTS标志，告诉
			ngx_process_events方法搜集到的事件没有直接执行它的handler方法，而是分门别类的放到ngx_posted_accept_events队列和
			ngx_posted_events队列中*/
            if (ngx_accept_mutex_held) 
			{
                flags |= NGX_POST_EVENTS;

            } 
			else
			{
				/*如果没有获取到accept_mutex锁，既不能让当前worker进程频繁的试图抢锁，也不能让它经过太长时间再去抢锁，而是让它等待
				 ngx_accept_mutex_delay再去抢锁*/
                if (timer == NGX_TIMER_INFINITE || timer > ngx_accept_mutex_delay)
                {
                    timer = ngx_accept_mutex_delay;
                }
            }
        }
    }
	//调用ngx_process_events方法，并计算该方法执行时消耗的时间
    delta = ngx_current_msec;
    (void) ngx_process_events(cycle, timer, flags);//即调用ngx_epoll_process_events方法，进而调用epoll_wait
    delta = ngx_current_msec - delta;
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "timer delta: %M", delta);
    //如果ngx_posted_accept_events队列不空，那么调用ngx_event_process_posted方法执行该队列中需要建立新连接的事件
    if (ngx_posted_accept_events) 
	{
        ngx_event_process_posted(cycle, &ngx_posted_accept_events);
    }
	//处理两个队列之间释放accept_mutex锁
    if (ngx_accept_mutex_held) 
	{
		/* 如果该标志位1，表示当前进程获得了accept_mutex锁，而且前面也已经处理完了新连接事件，这时需要调用ngx_shmtx_unlock释放
    	accept_mutex锁 */
        ngx_shmtx_unlock(&ngx_accept_mutex);
    }
	//处理定时器事件
    if (delta) 
	{
		/*如果ngx_process_events执行时消耗的时间大于0(该方法更新了时间)，而且这时可能有新的定时器事件被触发，那么需要调用
		 * ngx_event_expire_timers方法处理所有满足条件的定时器事件*/
        ngx_event_expire_timers();
    }
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,"posted events %p", ngx_posted_events);
    if (ngx_posted_events) 
	{
		//如果ngx_posted_events队列不为空，则调用ngx_event_process_posted方法执行该队列中的普通读写事件
        if (ngx_threaded) 
		{
            ngx_wakeup_worker_thread(cycle);
        } 
		else 
		{
            ngx_event_process_posted(cycle, &ngx_posted_events);
        }
    }
}

/* 该方法将读事件添加到epoll等事件驱动模块中，这样该事件对应的TCP连接上一旦出现可读事件，就会回调该事件的handler方法 */
ngx_int_t ngx_handle_read_event(ngx_event_t *rev, ngx_uint_t flags)
{
    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) 
	{
        /* kqueue, epoll */

        if (!rev->active && !rev->ready) 
		{
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_CLEAR_EVENT) == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }
        return NGX_OK;
    }
	else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) 
	{
        /* select, poll, /dev/poll */

        if (!rev->active && !rev->ready) 
		{
            if (ngx_add_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT) == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
        if (rev->active && (rev->ready || (flags & NGX_CLOSE_EVENT))) 
		{
            if (ngx_del_event(rev, NGX_READ_EVENT, NGX_LEVEL_EVENT | flags) == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }
	else if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) 
	{
        /* event ports */

        if (!rev->active && !rev->ready) 
		{
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) 
			{
                return NGX_ERROR;
            }

            return NGX_OK;
        }
        if (rev->oneshot && !rev->ready) 
		{
            if (ngx_del_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) 
			{
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }
    /* aio, iocp, rtsig */

    return NGX_OK;
}

/* 该方法会将写事件添加到事件驱动模块中，wev是要操作的事件，lowat表示
只有当连接对应的套接字缓冲区有lowat大小的可用空间时，事件收集器如
select或者epoll_wait调用才能处理这个事件，lowat参数为0表示不考虑可写缓冲区的大小*/
ngx_int_t ngx_handle_write_event(ngx_event_t *wev, size_t lowat)
{
    ngx_connection_t  *c;

    if (lowat) 
	{
        c = wev->data;

        if (ngx_send_lowat(c, lowat) == NGX_ERROR) 
		{
            return NGX_ERROR;
        }
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) 
	{
        /* kqueue, epoll */

        if (!wev->active && !wev->ready) 
		{
            if (ngx_add_event(wev, NGX_WRITE_EVENT,NGX_CLEAR_EVENT | (lowat ? NGX_LOWAT_EVENT : 0))== NGX_ERROR)
            {
                return NGX_ERROR;
            }
        }
        return NGX_OK;
    }
	else if (ngx_event_flags & NGX_USE_LEVEL_EVENT) 
    {
        /* select, poll, /dev/poll */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (wev->active && wev->ready) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, NGX_LEVEL_EVENT)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

    }
	else if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) 
	{

        /* event ports */

        if (!wev->active && !wev->ready) {
            if (ngx_add_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (wev->oneshot && wev->ready) {
            if (ngx_del_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }

            return NGX_OK;
        }
    }

    /* aio, iocp, rtsig */

    return NGX_OK;
}


static char *
ngx_event_init_conf(ngx_cycle_t *cycle, void *conf)
{
    if (ngx_get_conf(cycle->conf_ctx, ngx_events_module) == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "no \"events\" section in configuration");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

//初始化一些变量
static ngx_int_t ngx_event_module_init(ngx_cycle_t *cycle)
{
    void              ***cf;
    u_char              *shared;
    size_t               size, cl;
    ngx_shm_t            shm;
    ngx_time_t          *tp;
    ngx_core_conf_t     *ccf;
    ngx_event_conf_t    *ecf;

    cf = ngx_get_conf(cycle->conf_ctx, ngx_events_module);
    ecf = (*cf)[ngx_event_core_module.ctx_index];

    if (!ngx_test_config && ngx_process <= NGX_PROCESS_MASTER) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "using the \"%s\" event method", ecf->name);
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    ngx_timer_resolution = ccf->timer_resolution;

#if !(NGX_WIN32)
    {
    ngx_int_t      limit;
    struct rlimit  rlmt;

    if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "getrlimit(RLIMIT_NOFILE) failed, ignored");

    } else {
        if (ecf->connections > (ngx_uint_t) rlmt.rlim_cur
            && (ccf->rlimit_nofile == NGX_CONF_UNSET
                || ecf->connections > (ngx_uint_t) ccf->rlimit_nofile))
        {
            limit = (ccf->rlimit_nofile == NGX_CONF_UNSET) ?
                         (ngx_int_t) rlmt.rlim_cur : ccf->rlimit_nofile;

            ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                          "%ui worker_connections exceed "
                          "open file resource limit: %i",
                          ecf->connections, limit);
        }
    }
    }
#endif /* !(NGX_WIN32) */


    if (ccf->master == 0) {
        return NGX_OK;
    }

    if (ngx_accept_mutex_ptr) {
        return NGX_OK;
    }


    /* 计算出需要使用的共享内存的大小，虽然个ngx_atomic_t变量最多需要8个字节，但是每个统计员需要使用128自己是因为:
	nginx充分考虑了CPU的二级缓存。在目前许多CPU架构下缓存行的大小都是128字节，而下面需要统计的变量都是访问非常
	频繁的成员，同时他们占用的内存又非常少，所以采用了每个成有都使用128字节存放的形式，这样速度更快*/

    cl = 128;

    size = cl            /* ngx_accept_mutex */
           + cl          /* ngx_connection_counter */
           + cl;         /* ngx_temp_number */
//定义了NGX_STAT_STUB宏后才会统计上述6个原子变量
#if (NGX_STAT_STUB)

    size += cl           /* ngx_stat_accepted */
           + cl          /* ngx_stat_handled */
           + cl          /* ngx_stat_requests */
           + cl          /* ngx_stat_active */
           + cl          /* ngx_stat_reading */
           + cl          /* ngx_stat_writing */
           + cl;         /* ngx_stat_waiting */

#endif

	/* 初始化共享内存的ngx_shm_t结构体	*/
    shm.size = size;
    shm.name.len = sizeof("nginx_shared_zone");
    shm.name.data = (u_char *) "nginx_shared_zone";
    shm.log = cycle->log;

	/*开辟一块共享内存*/
    if (ngx_shm_alloc(&shm) != NGX_OK) {
        return NGX_ERROR;
    }

    shared = shm.addr;

	/*原子变量类型的accept锁使用了128字节的共享内存*/
    ngx_accept_mutex_ptr = (ngx_atomic_t *) shared;

	/*ngx_accept_mutex就是负载均衡锁，spin为-1就是告诉nginx这把锁不可以使进程进入睡眠状态*/
    ngx_accept_mutex.spin = (ngx_uint_t) -1;

    if (ngx_shmtx_create(&ngx_accept_mutex, (ngx_shmtx_sh_t *) shared,
                         cycle->lock_file.data)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

	/*原子变量类型的ngx_connection_counter统计所有建立过的连接数*/
    ngx_connection_counter = (ngx_atomic_t *) (shared + 1 * cl);

    (void) ngx_atomic_cmp_set(ngx_connection_counter, 0, 1);

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "counter: %p, %d",
                   ngx_connection_counter, *ngx_connection_counter);

    ngx_temp_number = (ngx_atomic_t *) (shared + 2 * cl);

    tp = ngx_timeofday();

    ngx_random_number = (tp->msec << 16) + ngx_pid;

#if (NGX_STAT_STUB)

	/*依次初始化需要统计的原子变量，也就是使用共享内存作为原子变量*/
    ngx_stat_accepted = (ngx_atomic_t *) (shared + 3 * cl);
    ngx_stat_handled = (ngx_atomic_t *) (shared + 4 * cl);
    ngx_stat_requests = (ngx_atomic_t *) (shared + 5 * cl);
    ngx_stat_active = (ngx_atomic_t *) (shared + 6 * cl);
    ngx_stat_reading = (ngx_atomic_t *) (shared + 7 * cl);
    ngx_stat_writing = (ngx_atomic_t *) (shared + 8 * cl);
    ngx_stat_waiting = (ngx_atomic_t *) (shared + 9 * cl);

#endif

    return NGX_OK;
}


#if !(NGX_WIN32)

static void
ngx_timer_signal_handler(int signo)
{
    ngx_event_timer_alarm = 1;

#if 1
    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_cycle->log, 0, "timer signal");
#endif
}

#endif

//ngx_event_core_module模块在启动过程中的主要工作都是在该方法中进行的
static ngx_int_t ngx_event_process_init(ngx_cycle_t *cycle)
{
    ngx_uint_t           m, i;
    ngx_event_t         *rev, *wev;
    ngx_listening_t     *ls;
    ngx_connection_t    *c, *next, *old;
    ngx_core_conf_t     *ccf;
    ngx_event_conf_t    *ecf;
    ngx_event_module_t  *module;
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);
	//当打开accept_mutex负载均衡锁，同时使用了master模式并且worker进程数量大于1时，才正式确定了进程将使用accept_mutex负载均衡锁
    if (ccf->master && ccf->worker_processes > 1 && ecf->accept_mutex) 
	{
        ngx_use_accept_mutex = 1;
        ngx_accept_mutex_held = 0;
        ngx_accept_mutex_delay = ecf->accept_mutex_delay;
    } 
	else 
	{
        ngx_use_accept_mutex = 0;
    }
#if (NGX_WIN32)
    /* disable accept mutex on win32 as it may cause deadlock if grabbed by a process which can't accept connections */
    ngx_use_accept_mutex = 0;
#endif
#if (NGX_THREADS)
    ngx_posted_events_mutex = ngx_mutex_init(cycle->log, 0);
    if (ngx_posted_events_mutex == NULL) {
        return NGX_ERROR;
    }
#endif
	//初始化红黑树实现定时器
    if (ngx_event_timer_init(cycle->log) == NGX_ERROR) 
	{
        return NGX_ERROR;
    }
    for (m = 0; ngx_modules[m]; m++) 
	{
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) //选择事件模块
		{
            continue;
        }
        if (ngx_modules[m]->ctx_index != ecf->use) //当前ues配置项指定的事件模块
		{
            continue;
        }
        module = ngx_modules[m]->ctx;
		//调用该模块的ngx_event_module_t接口下的ngx_event_actions_t中的init方法进行这个事件模块的初始化工作，如调用epoll的ngx_epoll_init
        if (module->actions.init(cycle, ngx_timer_resolution) != NGX_OK) 
		{
            exit(2);
        }
        break;
    }
#if !(NGX_WIN32)
    if (ngx_timer_resolution && !(ngx_event_flags & NGX_USE_TIMER_EVENT))
	{
        struct sigaction  sa;
        struct itimerval  itv;
        ngx_memzero(&sa, sizeof(struct sigaction));
        sa.sa_handler = ngx_timer_signal_handler;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGALRM, &sa, NULL) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"sigaction(SIGALRM) failed");
            return NGX_ERROR;
        }
        itv.it_interval.tv_sec = ngx_timer_resolution / 1000;
        itv.it_interval.tv_usec = (ngx_timer_resolution % 1000) * 1000;
        itv.it_value.tv_sec = ngx_timer_resolution / 1000;
        itv.it_value.tv_usec = (ngx_timer_resolution % 1000 ) * 1000;
		/* 每隔一段时间发出一个SIGALRM信号，从而调用一次ngx_timer_signal_handler方法。在linux下如果对定时要求不太精确的话，
		 * 使用alarm()和signal()就行了，但是如果想要实现精度较高的定时功能的话，就要使用setitimer和signal函数 */
        if (setitimer(ITIMER_REAL, &itv, NULL) == -1) 
		{
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"setitimer() failed");
        }
    }
	//对于poll、rtsig这样的事件模块
    if (ngx_event_flags & NGX_USE_FD_EVENT) 
	{
        struct rlimit  rlmt;
        if (getrlimit(RLIMIT_NOFILE, &rlmt) == -1) //获得每个进程能打开的最多文件数
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"getrlimit(RLIMIT_NOFILE) failed");
            return NGX_ERROR;
        }
        cycle->files_n = (ngx_uint_t) rlmt.rlim_cur;
        cycle->files = ngx_calloc(sizeof(ngx_connection_t *) * cycle->files_n,cycle->log);
        if (cycle->files == NULL)
        {
            return NGX_ERROR;
        }
    }
#endif
	/*预分配ngx_connection_t数组作为连接池，同时将ngx_cycle_t结构体中的connections成员指向该数组，数组的个数为nginx.conf
	 * 配置文件中connections或worker_connections中配置的连接数*/
    cycle->connections = ngx_alloc(sizeof(ngx_connection_t) * cycle->connection_n, cycle->log);
    if (cycle->connections == NULL)
    {
        return NGX_ERROR;
    }
    c = cycle->connections;
	//预分配ngx_event_t事件数组作为读事件池
    cycle->read_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n,cycle->log);
    if (cycle->read_events == NULL)
    {
        return NGX_ERROR;
    }
    rev = cycle->read_events;
    for (i = 0; i < cycle->connection_n; i++) 
	{
        rev[i].closed = 1;
        rev[i].instance = 1;
#if (NGX_THREADS)
        rev[i].lock = &c[i].lock;
        rev[i].own_lock = &c[i].lock;
#endif
    }
	//预分配ngx_event_t事件数组作为写事件池
    cycle->write_events = ngx_alloc(sizeof(ngx_event_t) * cycle->connection_n,cycle->log);
    if (cycle->write_events == NULL)
    {
        return NGX_ERROR;
    }
    wev = cycle->write_events;
    for (i = 0; i < cycle->connection_n; i++)
	{
        wev[i].closed = 1;
#if (NGX_THREADS)
        wev[i].lock = &c[i].lock;
        wev[i].own_lock = &c[i].lock;
#endif
    }
    i = cycle->connection_n;
    next = NULL;
	/*按照序号，将上述3个数组相应的读写事件设置到每一个ngx_connection_t连接对象中，同时把这些连接以ngx_connection_t中的data成员
	 * 作为next指针串联成链表，为下一步设置空闲连接链表做好准备*/
    do {
        i--;
        c[i].data = next;
        c[i].read = &cycle->read_events[i];
        c[i].write = &cycle->write_events[i];
        c[i].fd = (ngx_socket_t) -1;
        next = &c[i];
#if (NGX_THREADS)
        c[i].lock = 0;
#endif
    } while (i);
	/*将ngx_cycle_t结构体中的空闲连接链表free_connections指向connections数组的最后一个元素，也就是上面所有ngx_connection_t
	 * 连接通过data成员组成的单链表的首部*/
    cycle->free_connections = next;
    cycle->free_connection_n = cycle->connection_n;
    /* 在刚刚建立好的连接池中，为所有的ngx_listening_t监听对象中的connection成员分配连接，同时对监听端口的读事件设置处理方法为
     * ngx_event_accept，也就是说，有新连接事件时将调用ngx_event_accept方法建立新连接*/
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) 
	{
        c = ngx_get_connection(ls[i].fd, cycle->log);
        if (c == NULL) 
		{
            return NGX_ERROR;
        }
        c->log = &ls[i].log;
        c->listening = &ls[i];
        ls[i].connection = c;
        rev = c->read;//读事件
        rev->log = c->log;
        rev->accept = 1;

#if (NGX_HAVE_DEFERRED_ACCEPT)
        rev->deferred_accept = ls[i].deferred_accept;
#endif
        if (!(ngx_event_flags & NGX_USE_IOCP_EVENT))
        {
            if (ls[i].previous) {
                /* delete the old accept events that were bound to the old cycle read events array */
                old = ls[i].previous->connection;

                if (ngx_del_event(old->read, NGX_READ_EVENT, NGX_CLOSE_EVENT) == NGX_ERROR)
                {
                    return NGX_ERROR;
                }
                old->fd = (ngx_socket_t) -1;
            }
        }
#if (NGX_WIN32)
        if (ngx_event_flags & NGX_USE_IOCP_EVENT) {
            ngx_iocp_conf_t  *iocpcf;

            rev->handler = ngx_event_acceptex;

            if (ngx_use_accept_mutex) {
                continue;
            }

            if (ngx_add_event(rev, 0, NGX_IOCP_ACCEPT) == NGX_ERROR) {
                return NGX_ERROR;
            }

            ls[i].log.handler = ngx_acceptex_log_error;

            iocpcf = ngx_event_get_conf(cycle->conf_ctx, ngx_iocp_module);
            if (ngx_event_post_acceptex(&ls[i], iocpcf->post_acceptex)
                == NGX_ERROR)
            {
                return NGX_ERROR;
            }
        } 
		else 
		{
            rev->handler = ngx_event_accept;

            if (ngx_use_accept_mutex) {
                continue;
            }

            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return NGX_ERROR;
            }
        }
#else
		//处理新事件的回调方法
        rev->handler = ngx_event_accept;
        if (ngx_use_accept_mutex)
        {
            continue;
        }
        if (ngx_event_flags & NGX_USE_RTSIG_EVENT)
        {
            if (ngx_add_conn(c) == NGX_ERROR) {
                return NGX_ERROR;
            }
        } 
		else 
		{
			//将监听对象连接的读事件添加到事件驱动模块中，这样，epoll等事件模块就开始检测监听服务，并开始向用户提供服务了
            if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) 
			{
                return NGX_ERROR;	
            }
        }
#endif
    }
    return NGX_OK;
}

//调用SO_SNDLOWAT选项设置TCP套接字的发送低潮度
ngx_int_t ngx_send_lowat(ngx_connection_t *c, size_t lowat)
{
    int  sndlowat;

#if (NGX_HAVE_LOWAT_EVENT)

    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT)
    {
        c->write->available = lowat;
        return NGX_OK;
    }

#endif

    if (lowat == 0 || c->sndlowat)
    {
        return NGX_OK;
    }
    sndlowat = (int) lowat;
    //SO_SNDLOWAT选项用于设置TCP套接字的发送低潮度，即TCP发送缓冲区中的数据必须达到规定的数据量sndlowat,内核才通知进程可写
    if (setsockopt(c->fd, SOL_SOCKET, SO_SNDLOWAT,(const void *) &sndlowat, sizeof(int))== -1)
    {
        ngx_connection_error(c, ngx_socket_errno,"setsockopt(SO_SNDLOWAT) failed");
        return NGX_ERROR;
    }
    c->sndlowat = 1;

    return NGX_OK;
}

//解析event{}配置项时调用该方法
static char * ngx_events_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                 *rv;
    void               ***ctx;
    ngx_uint_t            i;
    ngx_conf_t            pcf;
    ngx_event_module_t   *m;
    if (*(void **) conf) 
	{
        return "is duplicate";
    }
    ngx_event_max_module = 0;//所有事件模块的个数
    for (i = 0; ngx_modules[i]; i++) 
	{
        if (ngx_modules[i]->type != NGX_EVENT_MODULE) 
		{
            continue;
        }
		//初始化所有事件的ctx_index成员，ctx_index表示模块在同类模块(此处指事件模块)中的顺序
        ngx_modules[i]->ctx_index = ngx_event_max_module++;
    }
    ctx = ngx_pcalloc(cf->pool, sizeof(void *));
    if (ctx == NULL)
    {
        return NGX_CONF_ERROR;
    }
    *ctx = ngx_pcalloc(cf->pool, ngx_event_max_module * sizeof(void *));
    if (*ctx == NULL)
    {
        return NGX_CONF_ERROR;
    }
    *(void **) conf = ctx;
    for (i = 0; ngx_modules[i]; i++) 
	{
        if (ngx_modules[i]->type != NGX_EVENT_MODULE) 
		{
            continue;
        }
		//该模块的上下文结构体
        m = ngx_modules[i]->ctx;
        if (m->create_conf) 
		{
			//依次调用所有事件模块通用接口ngx_event_module_t中的create_conf方法
            (*ctx)[ngx_modules[i]->ctx_index] = m->create_conf(cf->cycle);
            if ((*ctx)[ngx_modules[i]->ctx_index] == NULL) 
			{
                return NGX_CONF_ERROR;
            }
        }
    }
    pcf = *cf;
    cf->ctx = ctx;
    cf->module_type = NGX_EVENT_MODULE;
    cf->cmd_type = NGX_EVENT_CONF;
	//解析模块配置项，这时每个事件模块定义的ngx_command_t决定了配置项解析方法，如果在nginx.conf中发现相应的配置项，就会回调各事件模块定义的方法
    rv = ngx_conf_parse(cf, NULL);
    *cf = pcf;
    if (rv != NGX_CONF_OK)return rv;
    for (i = 0; ngx_modules[i]; i++) 
	{
        if (ngx_modules[i]->type != NGX_EVENT_MODULE) 
		{
            continue;
        }
        m = ngx_modules[i]->ctx;
        if (m->init_conf) 
		{
			//解析完配置项后，依次调用所有事件模块通用接口ngx_event_module_t中的init_conf方法
            rv = m->init_conf(cf->cycle, (*ctx)[ngx_modules[i]->ctx_index]);
            if (rv != NGX_CONF_OK) 
			{
                return rv;
            }
        }
    }
    return NGX_CONF_OK;
}

static char *
ngx_event_connections(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

    ngx_str_t  *value;

    if (ecf->connections != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (ngx_strcmp(cmd->name.data, "connections") == 0) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "the \"connections\" directive is deprecated, "
                           "use the \"worker_connections\" directive instead");
    }

    value = cf->args->elts;
    ecf->connections = ngx_atoi(value[1].data, value[1].len);
    if (ecf->connections == (ngx_uint_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number \"%V\"", &value[1]);

        return NGX_CONF_ERROR;
    }

    cf->cycle->connection_n = ecf->connections;

    return NGX_CONF_OK;
}

/* use指令的处理函数，该指令用来选择哪一个I/O复用模块 */
static char * ngx_event_use(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_event_conf_t  *ecf = conf;
    ngx_int_t             m;
    ngx_str_t            *value;
    ngx_event_conf_t     *old_ecf;
    ngx_event_module_t   *module;
    if (ecf->use != NGX_CONF_UNSET_UINT)
    {
        return "is duplicate";
    }
    value = cf->args->elts;
    if (cf->cycle->old_cycle->conf_ctx) {
        old_ecf = ngx_event_get_conf(cf->cycle->old_cycle->conf_ctx,
                                     ngx_event_core_module);
    } else {
        old_ecf = NULL;
    }
    for (m = 0; ngx_modules[m]; m++) {
        if (ngx_modules[m]->type != NGX_EVENT_MODULE) {
            continue;
        }
        module = ngx_modules[m]->ctx;
        if (module->name->len == value[1].len)
        {
            if (ngx_strcmp(module->name->data, value[1].data) == 0)
            {
                ecf->use = ngx_modules[m]->ctx_index;//I/O复用模块的索引
                ecf->name = module->name->data;
                if (ngx_process == NGX_PROCESS_SINGLE
                    && old_ecf
                    && old_ecf->use != ecf->use)
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "when the server runs without a master process "
                               "the \"%V\" event type must be the same as "
                               "in previous configuration - \"%s\" "
                               "and it cannot be changed on the fly, "
                               "to change it you need to stop server "
                               "and start it again",
                               &value[1], old_ecf->name);

                    return NGX_CONF_ERROR;
                }

                return NGX_CONF_OK;
            }
        }
    }
    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid event type \"%V\"", &value[1]);
    return NGX_CONF_ERROR;
}


static char *
ngx_event_debug_connection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
#if (NGX_DEBUG)
    ngx_event_conf_t  *ecf = conf;

    ngx_int_t             rc;
    ngx_str_t            *value;
    ngx_url_t             u;
    ngx_cidr_t            c, *cidr;
    ngx_uint_t            i;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    value = cf->args->elts;

#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
        cidr = ngx_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        cidr->family = AF_UNIX;
        return NGX_CONF_OK;
    }

#endif

    rc = ngx_ptocidr(&value[1], &c);

    if (rc != NGX_ERROR) {
        if (rc == NGX_DONE) {
            ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                               "low address bits of %V are meaningless",
                               &value[1]);
        }

        cidr = ngx_array_push(&ecf->debug_connection);
        if (cidr == NULL) {
            return NGX_CONF_ERROR;
        }

        *cidr = c;

        return NGX_CONF_OK;
    }

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.host = value[1];

    if (ngx_inet_resolve_host(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in debug_connection \"%V\"",
                               u.err, &u.host);
        }

        return NGX_CONF_ERROR;
    }

    cidr = ngx_array_push_n(&ecf->debug_connection, u.naddrs);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_memzero(cidr, u.naddrs * sizeof(ngx_cidr_t));

    for (i = 0; i < u.naddrs; i++) {
        cidr[i].family = u.addrs[i].sockaddr->sa_family;

        switch (cidr[i].family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) u.addrs[i].sockaddr;
            cidr[i].u.in6.addr = sin6->sin6_addr;
            ngx_memset(cidr[i].u.in6.mask.s6_addr, 0xff, 16);
            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) u.addrs[i].sockaddr;
            cidr[i].u.in.addr = sin->sin_addr.s_addr;
            cidr[i].u.in.mask = 0xffffffff;
            break;
        }
    }

#else

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"debug_connection\" is ignored, you need to rebuild "
                       "nginx using --with-debug option to enable it");

#endif

    return NGX_CONF_OK;
}


static void *
ngx_event_core_create_conf(ngx_cycle_t *cycle)
{
    ngx_event_conf_t  *ecf;

    ecf = ngx_palloc(cycle->pool, sizeof(ngx_event_conf_t));
    if (ecf == NULL) {
        return NULL;
    }

    ecf->connections = NGX_CONF_UNSET_UINT;
    ecf->use = NGX_CONF_UNSET_UINT;
    ecf->multi_accept = NGX_CONF_UNSET;
    ecf->accept_mutex = NGX_CONF_UNSET;
    ecf->accept_mutex_delay = NGX_CONF_UNSET_MSEC;
    ecf->name = (void *) NGX_CONF_UNSET;

#if (NGX_DEBUG)

    if (ngx_array_init(&ecf->debug_connection, cycle->pool, 4,
                       sizeof(ngx_cidr_t)) == NGX_ERROR)
    {
        return NULL;
    }

#endif

    return ecf;
}


static char *
ngx_event_core_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_event_conf_t  *ecf = conf;

#if (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)
    int                  fd;
#endif
#if (NGX_HAVE_RTSIG)
    ngx_uint_t           rtsig;
    ngx_core_conf_t     *ccf;
#endif
    ngx_int_t            i;
    ngx_module_t        *module;
    ngx_event_module_t  *event_module;

    module = NULL;

#if (NGX_HAVE_EPOLL) && !(NGX_TEST_BUILD_EPOLL)

    fd = epoll_create(100);

    if (fd != -1) {
        (void) close(fd);
        module = &ngx_epoll_module;

    } else if (ngx_errno != NGX_ENOSYS) {
        module = &ngx_epoll_module;
    }

#endif

#if (NGX_HAVE_RTSIG)

    if (module == NULL) {
        module = &ngx_rtsig_module;
        rtsig = 1;

    } else {
        rtsig = 0;
    }

#endif

#if (NGX_HAVE_DEVPOLL)

    module = &ngx_devpoll_module;

#endif

#if (NGX_HAVE_KQUEUE)

    module = &ngx_kqueue_module;

#endif

#if (NGX_HAVE_SELECT)

    if (module == NULL) {
        module = &ngx_select_module;
    }

#endif

    if (module == NULL) {
        for (i = 0; ngx_modules[i]; i++) {

            if (ngx_modules[i]->type != NGX_EVENT_MODULE) {
                continue;
            }

            event_module = ngx_modules[i]->ctx;

            if (ngx_strcmp(event_module->name->data, event_core_name.data) == 0)
            {
                continue;
            }

            module = ngx_modules[i];
            break;
        }
    }

    if (module == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "no events module found");
        return NGX_CONF_ERROR;
    }

    ngx_conf_init_uint_value(ecf->connections, DEFAULT_CONNECTIONS);
    cycle->connection_n = ecf->connections;

    ngx_conf_init_uint_value(ecf->use, module->ctx_index);

    event_module = module->ctx;
    ngx_conf_init_ptr_value(ecf->name, event_module->name->data);

    ngx_conf_init_value(ecf->multi_accept, 0);
    ngx_conf_init_value(ecf->accept_mutex, 1);
    ngx_conf_init_msec_value(ecf->accept_mutex_delay, 500);


#if (NGX_HAVE_RTSIG)

    if (!rtsig) {
        return NGX_CONF_OK;
    }

    if (ecf->accept_mutex) {
        return NGX_CONF_OK;
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (ccf->worker_processes == 0) {
        return NGX_CONF_OK;
    }

    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "the \"rtsig\" method requires \"accept_mutex\" to be on");

    return NGX_CONF_ERROR;

#else

    return NGX_CONF_OK;

#endif
}
