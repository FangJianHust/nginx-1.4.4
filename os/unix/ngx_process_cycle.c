#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>

static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n,ngx_int_t type);
static void ngx_start_cache_manager_processes(ngx_cycle_t *cycle,ngx_uint_t respawn);
static void ngx_pass_open_channel(ngx_cycle_t *cycle, ngx_channel_t *ch);
static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo);
static ngx_uint_t ngx_reap_children(ngx_cycle_t *cycle);
static void ngx_master_process_exit(ngx_cycle_t *cycle);
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_worker_process_init(ngx_cycle_t *cycle, ngx_int_t worker);
static void ngx_worker_process_exit(ngx_cycle_t *cycle);
static void ngx_channel_handler(ngx_event_t *ev);
#if (NGX_THREADS)
static void ngx_wakeup_worker_threads(ngx_cycle_t *cycle);
static ngx_thread_value_t ngx_worker_thread_cycle(void *data);
#endif
static void ngx_cache_manager_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_cache_manager_process_handler(ngx_event_t *ev);
static void ngx_cache_loader_process_handler(ngx_event_t *ev);

ngx_uint_t    ngx_process;
ngx_pid_t     ngx_pid;
ngx_uint_t    ngx_threaded;

//为1表示有worker进程退出
sig_atomic_t  ngx_reap;

sig_atomic_t  ngx_sigio;
sig_atomic_t  ngx_sigalrm;

//为1时表示强制关闭进程
sig_atomic_t  ngx_terminate;

sig_atomic_t  ngx_quit;//优雅的关闭进程
sig_atomic_t  ngx_debug_quit;
ngx_uint_t    ngx_exiting;//开始准备关闭worker进程
sig_atomic_t  ngx_reconfigure;
sig_atomic_t  ngx_reopen;//重新打开所有文件

sig_atomic_t  ngx_change_binary;
ngx_pid_t     ngx_new_binary;
ngx_uint_t    ngx_inherited;
ngx_uint_t    ngx_daemonized;

sig_atomic_t  ngx_noaccept;
ngx_uint_t    ngx_noaccepting;
ngx_uint_t    ngx_restart;


#if (NGX_THREADS)
volatile ngx_thread_t  ngx_threads[NGX_MAX_THREADS];
ngx_int_t              ngx_threads_n;
#endif

static u_char  master_process[] = "master process";

static ngx_cache_manager_ctx_t  ngx_cache_manager_ctx = {
    ngx_cache_manager_process_handler, "cache manager process", 0
};

static ngx_cache_manager_ctx_t  ngx_cache_loader_ctx = {
    ngx_cache_loader_process_handler, "cache loader process", 60000
};

static ngx_cycle_t      ngx_exit_cycle;
static ngx_log_t        ngx_exit_log;
static ngx_open_file_t  ngx_exit_log_file;

//参考：http://www.cnblogs.com/h2-database/archive/2012/05/21/2583266.html
void ngx_master_process_cycle(ngx_cycle_t *cycle)
{
    char              *title;
    u_char            *p;
    size_t             size;
    ngx_int_t          i;
    ngx_uint_t         n, sigio;
    sigset_t           set;
    struct itimerval   itv;
    ngx_uint_t         live;
    ngx_msec_t         delay;
    ngx_listening_t   *ls;
    ngx_core_conf_t   *ccf;
	/* master设置一些需要屏蔽的的信号，这些信号主要是为了让子进程屏蔽的，因为子进程会继承父进程的信号屏蔽字，然后父进程调用sigsuspend
	 * 恢复自己的信号屏蔽字，从而达到监听信号的目的*/
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    /* 如果一个正在进行读写操作的TCP套接字处于信号驱动I/O 状态下，那么每当新数据到达本地的时候，将会产生一个SIGIO信号，每当本地套接字发出的数据被远程确认后，
     * 也会产生一个SIGIO信号，由于nginx使用的是epoll事件驱动，所以需要屏蔽该信号 */
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_NOACCEPT_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));
	//设置阻塞信号屏蔽字
    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"sigprocmask() failed");
    }
    sigemptyset(&set);
    size = sizeof(master_process);
    for (i = 0; i < ngx_argc; i++) {
        size += ngx_strlen(ngx_argv[i]) + 1;
    }
	//title用于存放是名字和环境变量
    title = ngx_pnalloc(cycle->pool, size);
    p = ngx_cpymem(title, master_process, sizeof(master_process) - 1);
    for (i = 0; i < ngx_argc; i++) {
        *p++ = ' ';
        p = ngx_cpystrn(p, (u_char *) ngx_argv[i], size);
    }
	//设置进程标题，如果你用ps –aux来查看就可以分清master与worker进程，这就是title的作用
    ngx_setproctitle(title);
	//获取核心模块的结构体
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
	//根据配置文件的worker_processes值创建多个worker子进程
    ngx_start_worker_processes(cycle, ccf->worker_processes,NGX_PROCESS_RESPAWN);
	/*启动cache manage子进程,有些模块需要文件cache，比如fastcgi模块，这些模块会把文件cache路径添加到cycle->paths中，
	 * 文件cache管理进程会定期调用这些模块的文件cache处理钩子处理一下文件cache*/
    ngx_start_cache_manager_processes(cycle, 0);
    ngx_new_binary = 0;
    delay = 0;
    sigio = 0;
    live = 1;
	/*master循环处理信号,master不是不停的在循环执行以下步骤，而是会通过sigsuspend调用使
	master进程休眠，等待master进程收到信号后激活master进程继续执行*/
    for ( ;; ) 
	{
		/*delay用来设置等待worker退出的时间，master接受了退出信号后，首先发送退出信号给worker，
		而worker退出需要一些时间，在下面有设置*/
        if (delay)
		{
            if (ngx_sigalrm)
			{
                sigio = 0;
                delay *= 2;
                ngx_sigalrm = 0;
            }
            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,"termination cycle: %d", delay);
            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = delay / 1000;
            itv.it_value.tv_usec = (delay % 1000 ) * 1000;
			//设置定时器，以系统真实时间来计算，送出SIGALRM信号
            if (setitimer(ITIMER_REAL, &itv, NULL) == -1)
			{
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"setitimer() failed");
            }
        }
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "sigsuspend");
		/*用于在接收到某个信号之前，临时用mask替换进程的信号掩码，并暂停进程执行，直到收到信号为止，该函数调用使得主进程大部分时间都
		 *处于挂起等待状态。也就是说，sigsuspend后，进程就挂在那里，等待着开放的信号的唤醒。系统在接收到信号后，调用处理函数，然后
		 *把现在的信号屏蔽集还原为原来的*/
        sigsuspend(&set);
        ngx_time_update();
        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "wake up, sigio %i", sigio);
		//收到了SIGCHLD信号，有worker退出(ngx_reap == 1)
        if (ngx_reap) 
		{
            ngx_reap = 0;
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "reap children");
			/*处理所有worker，如果有worker异常退出，则重启这个worker，如果所有的worker都退出了，则返回0*/
            live = ngx_reap_children(cycle);
        }
		/*如果worker都正常退出了并且收到了NGX_CMD_TERMINATE命令或者SIGTERM信号或SIGINT信号
		(ngx_terminate ==1)或NGX_CMD_QUIT命令或SIGQUIT信号(ngx_quit == 1),则master退出*/
        if (!live && (ngx_terminate || ngx_quit))
		{
            ngx_master_process_exit(cycle);
        }
		/*收到了NGX_CMD_TERMINATE命令或者SIGTERM信号或SIGINT信号(ngx_terminate ==1)通知所有worker退出，并且等待worker退出*/
        if (ngx_terminate)
		{
            if (delay == 0)
			{
                delay = 50;//设置延时
            }
            if (sigio)
            {
                sigio--;
                continue;
            }
            sigio = ccf->worker_processes + 2 /* cache processes */;
			//延时已到，给所有worker发送SIGKILL信号，强制杀死worker
            if (delay > 1000) 
			{
                ngx_signal_worker_processes(cycle, SIGKILL);
            }
			//给所有worker发送SIGTERM信号，通知worker退出
			else
			{
                ngx_signal_worker_processes(cycle,ngx_signal_value(NGX_TERMINATE_SIGNAL));
            }
            continue;
        }
		//NGX_CMD_QUIT命令或SIGQUIT信号(ngx_quit == 1)
        if (ngx_quit) 
		{	
			//给所有的worker发送SIGQUIT信号
            ngx_signal_worker_processes(cycle,ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
            ls = cycle->listening.elts;
			//关闭所有监听socket
            for (n = 0; n < cycle->listening.nelts; n++)
			{
                if (ngx_close_socket(ls[n].fd) == -1) 
				{
                    ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno, ngx_close_socket_n " %V failed", &ls[n].addr_text);
                }
            }
            cycle->listening.nelts = 0;
            continue;
        }
		/* 需要重新读取配置文件，Nginx不会再让原先的worker等子进程再重新读取配置文件，它的策略是重新初始化ngx_cycle_t结构体，
		 * 用它来读取新的配置文件，再拉起新的worker进程，销毁旧的worker进程*/
        if (ngx_reconfigure) 
		{
			//收到SIGHUP信号
            ngx_reconfigure = 0;
			//代码已被替换，重启worker，不需要重新初始化配置
            if (ngx_new_binary) 
			{
                ngx_start_worker_processes(cycle, ccf->worker_processes,NGX_PROCESS_RESPAWN);
                ngx_start_cache_manager_processes(cycle, 0);
                ngx_noaccepting = 0;
                continue;
            }
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");
			//重新初始化配置
            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }
			//重启worker
            ngx_cycle = cycle;
            ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,ngx_core_module);
			//再拉起一批worker进程，这些进程将使用新ngx_cycle_t结构体
            ngx_start_worker_processes(cycle, ccf->worker_processes,NGX_PROCESS_JUST_RESPAWN);
			//按照缓存模块的加载情况决定是否拉起cache manage或者cache loader进程
			ngx_start_cache_manager_processes(cycle, 1);
            /* allow new processes to start */
            ngx_msleep(100);
			//此时子进程肯定存在了
            live = 1;
			//向原先的非刚刚拉起的子进程发送QUIT信号，要求它们优雅的退出
            ngx_signal_worker_processes(cycle,gx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }
		//当ngx_noaccepting==1时，会把ngx_restart设为1，重启worker
        if (ngx_restart)
		{
            ngx_restart = 0;
            ngx_start_worker_processes(cycle, ccf->worker_processes, NGX_PROCESS_RESPAWN);
            ngx_start_cache_manager_processes(cycle, 0);
            live = 1;
        }
		//收到SIGUSR1信号，重新打开log文件
        if (ngx_reopen) 
		{
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
			//重新打开文件
            ngx_reopen_files(cycle, ccf->user);
            ngx_signal_worker_processes(cycle, ngx_signal_value(NGX_REOPEN_SIGNAL));
        }
		//收到SIGUSER2，表示需要平滑升级
        if (ngx_change_binary) 
		{
            ngx_change_binary = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "changing binary");
			//用新的子进程启动新版本的Nginx程序
            ngx_new_binary = ngx_exec_new_binary(cycle, ngx_argv);
        }
		//收到SIGWINCH信号不在接受请求，worker退出，master不退出
        if (ngx_noaccept) 
		{
            ngx_noaccept = 0;
            ngx_noaccepting = 1;
			//向所有子进程发送QUIT信号，要求它们优雅的关闭服务
            ngx_signal_worker_processes(cycle,ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }
    }
}


//如果nginx.conf中配置为单进程工作模式，这时会调用该方法进入单进程模式
void ngx_single_process_cycle(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    if (ngx_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->init_process) {
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR) {//调用所有模块的init_process方法，单进程工作模式的启动工作至此全部完成，将进入正常的工作模式
                /* fatal */
                exit(2);
            }
        }
    }

    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events_and_timers(cycle);

        if (ngx_terminate || ngx_quit) {

            for (i = 0; ngx_modules[i]; i++) {
                if (ngx_modules[i]->exit_process) {
                    ngx_modules[i]->exit_process(cycle);
                }
            }

            ngx_master_process_exit(cycle);
        }

        if (ngx_reconfigure) {
            ngx_reconfigure = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            ngx_cycle = cycle;
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, (ngx_uid_t) -1);
        }
    }
}

/* 启动n个worker子进程，并设置好每个子进程与master父进程之间使用sockerpair系统调用建立起来的socket句柄通信机制
type是启动方式，它的取值范围是:NGX_PROCESS_RESPAWN、NGX_PROCESS_NORESPAWN、
NGX_PROCESS_JUST_SPAWN、NGX_PROCESS_JUST_RESPAWN、NGX_PROCESS_DETACHED。type的
值将影响8.6节中ngx_process_t结构体的respawn、detached、just_spawn标志位。 */
static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n, ngx_int_t type)
{
    ngx_int_t      i;
    ngx_channel_t  ch;
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start worker processes");
	//传递给其他worker子进程的命令，打开通信管道
    ch.command = NGX_CMD_OPEN_CHANNEL;
	//创建n个worker子进程
    for (i = 0; i < n; i++) 
	{ 
		/*ngx_spawn_process创建worker子进程并初始化相关资源和属性然后执行子进程的执行函数ngx_worker_process_cycle*/
        ngx_spawn_process(cycle, ngx_worker_process_cycle,(void *) (intptr_t) i, "worker process", type);

        /* 取得当前子进程的UNIX描述符等信息，向其他worker子进程广播当前创建worker进程信息。。。*/
        ch.pid = ngx_processes[ngx_process_slot].pid;
        ch.slot = ngx_process_slot;
        ch.fd = ngx_processes[ngx_process_slot].channel[0];
        ngx_pass_open_channel(cycle, &ch); 
    }
}

/*根据是否使用文件缓存模块，也就是cycle中存储路径的动态数组是否有路径的manage标志打开，来决定是否启动cache manage子进程，
 *同样根据loader标志决定是否启动cache loader子进程*/
static void ngx_start_cache_manager_processes(ngx_cycle_t *cycle, ngx_uint_t respawn)
{
    ngx_uint_t       i, manager, loader;
    ngx_path_t     **path;
    ngx_channel_t    ch;

    manager = 0;
    loader = 0;

    path = ngx_cycle->paths.elts;
    for (i = 0; i < ngx_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            manager = 1;
        }

        if (path[i]->loader) {
            loader = 1;
        }
    }

    if (manager == 0) {
        return;
    }

    ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
                      &ngx_cache_manager_ctx, "cache manager process",
                      respawn ? NGX_PROCESS_JUST_RESPAWN : NGX_PROCESS_RESPAWN);

    ch.command = NGX_CMD_OPEN_CHANNEL;
    ch.pid = ngx_processes[ngx_process_slot].pid;
    ch.slot = ngx_process_slot;
    ch.fd = ngx_processes[ngx_process_slot].channel[0];

    ngx_pass_open_channel(cycle, &ch);

    if (loader == 0) {
        return;
    }

    ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
                      &ngx_cache_loader_ctx, "cache loader process",
                      respawn ? NGX_PROCESS_JUST_SPAWN : NGX_PROCESS_NORESPAWN);

    ch.command = NGX_CMD_OPEN_CHANNEL;
    ch.pid = ngx_processes[ngx_process_slot].pid;
    ch.slot = ngx_process_slot;
    ch.fd = ngx_processes[ngx_process_slot].channel[0];

    ngx_pass_open_channel(cycle, &ch);
}

//向所有已经打开的channel(通过socketpair生成的句柄进行通信)发送ch信息
static void ngx_pass_open_channel(ngx_cycle_t *cycle, ngx_channel_t *ch)
{
    ngx_int_t  i;
    for (i = 0; i < ngx_last_process; i++)
    {
		//跳过自己和异常的worker
        if (i == ngx_process_slot || ngx_processes[i].pid == -1 || ngx_processes[i].channel[0] == -1)
        {
            continue;
        }
        ngx_log_debug6(NGX_LOG_DEBUG_CORE, cycle->log, 0,"pass channel s:%d pid:%P fd:%d to s:%i pid:%P fd:%d", ch->slot, ch->pid, ch->fd,i, ngx_processes[i].pid, ngx_processes[i].channel[0]);
		//发送消息给其他的worker
        ngx_write_channel(ngx_processes[i].channel[0],ch, sizeof(ngx_channel_t), cycle->log);
    }
}

//向子进程发送信号
static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo)
{
    ngx_int_t      i;
    ngx_err_t      err;
    ngx_channel_t  ch;

#if (NGX_BROKEN_SCM_RIGHTS)

    ch.command = 0;

#else

    switch (signo) {

    case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
        ch.command = NGX_CMD_QUIT;
        break;

    case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        ch.command = NGX_CMD_TERMINATE;
        break;

    case ngx_signal_value(NGX_REOPEN_SIGNAL):
        ch.command = NGX_CMD_REOPEN;
        break;

    default:
        ch.command = 0;
    }

#endif

    ch.fd = -1;


    for (i = 0; i < ngx_last_process; i++) 
	{
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %d %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_spawn);

        if (ngx_processes[i].detached || ngx_processes[i].pid == -1) {
            continue;
        }

		//正在生成该子进程
        if (ngx_processes[i].just_spawn)
		{
            ngx_processes[i].just_spawn = 0;
            continue;
        }

        if (ngx_processes[i].exiting && signo == ngx_signal_value(NGX_SHUTDOWN_SIGNAL))
        {
            continue;
        }

		//向该子进程发送退出信息
        if (ch.command) 
		{
            if (ngx_write_channel(ngx_processes[i].channel[0],&ch, sizeof(ngx_channel_t), cycle->log) == NGX_OK)
            {
                if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
                    ngx_processes[i].exiting = 1;
                }

                continue;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (%P, %d)" , ngx_processes[i].pid, signo);
		//向该子进程发送信号
        if (kill(ngx_processes[i].pid, signo) == -1) 
		{
            err = ngx_errno;
            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "kill(%P, %d) failed", ngx_processes[i].pid, signo);

            if (err == NGX_ESRCH) {
                ngx_processes[i].exited = 1;
                ngx_processes[i].exiting = 0;
                ngx_reap = 1;
            }

            continue;
        }

        if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
            ngx_processes[i].exiting = 1;
        }
    }
}

/* 处理所有worker，如果有worker异常退出，则重启这个worker，如果所有的worker都退出了，则返回0*/
static ngx_uint_t ngx_reap_children(ngx_cycle_t *cycle)
{
    ngx_int_t         i, n;
    ngx_uint_t        live;
    ngx_channel_t     ch;
    ngx_core_conf_t  *ccf;

    ch.command = NGX_CMD_CLOSE_CHANNEL;//退出命令
    ch.fd = -1;

	//如果所有子进程都已经正常退出，live为0，如果有非正常退出或者还没有完全退出等则为1
    live = 0;
    for (i = 0; i < ngx_last_process; i++) 
	{

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %d %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_spawn);

        if (ngx_processes[i].pid == -1) {
            continue;
        }

		//该进程已经退出
        if (ngx_processes[i].exited) 
		{
            if (!ngx_processes[i].detached) 
			{
                ngx_close_channel(ngx_processes[i].channel, cycle->log);

                ngx_processes[i].channel[0] = -1;
                ngx_processes[i].channel[1] = -1;

				//发送方
                ch.pid = ngx_processes[i].pid;
                ch.slot = i;

				//向每一个未退出的进程发送退出消息
                for (n = 0; n < ngx_last_process; n++)
				{
                    if (ngx_processes[n].exited
                        || ngx_processes[n].pid == -1
                        || ngx_processes[n].channel[0] == -1)
                    {
                        continue;
                    }

                    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                                   "pass close channel s:%i pid:%P to:%P",
                                   ch.slot, ch.pid, ngx_processes[n].pid);

                    ngx_write_channel(ngx_processes[n].channel[0],&ch, sizeof(ngx_channel_t), cycle->log);
                }
            }

			//对于非正常关闭的进程，重新生成
            if (ngx_processes[i].respawn && !ngx_processes[i].exiting && !ngx_terminate && !ngx_quit)
            {
                if (ngx_spawn_process(cycle, ngx_processes[i].proc,ngx_processes[i].data,ngx_processes[i].name, i) == NGX_INVALID_PID)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,"could not respawn %s", ngx_processes[i].name);
                    continue;
                }

                ch.command = NGX_CMD_OPEN_CHANNEL;
                ch.pid = ngx_processes[ngx_process_slot].pid;
                ch.slot = ngx_process_slot;
                ch.fd = ngx_processes[ngx_process_slot].channel[0];

				//告诉其他进程自己已经启动
                ngx_pass_open_channel(cycle, &ch);

				//非正常退出
                live = 1;

                continue;
            }

            if (ngx_processes[i].pid == ngx_new_binary) 
			{
                ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,ngx_core_module);

                if (ngx_rename_file((char *) ccf->oldpid.data,(char *) ccf->pid.data) == NGX_FILE_ERROR)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                                  ngx_rename_file_n " %s back to %s failed "
                                  "after the new binary process \"%s\" exited",
                                  ccf->oldpid.data, ccf->pid.data, ngx_argv[0]);
                }

                ngx_new_binary = 0;
                if (ngx_noaccepting) {
                    ngx_restart = 1;
                    ngx_noaccepting = 0;
                }
            }

            if (i == ngx_last_process - 1) 
			{
                ngx_last_process--;

            }
			else 
			{
                ngx_processes[i].pid = -1;
            }

        }
		else if (ngx_processes[i].exiting || !ngx_processes[i].detached) 
		{
            live = 1;
        }
    }

    return live;
}

//退出master进程工作的循环
static void ngx_master_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    ngx_delete_pidfile(cycle);//删除存储进程号的pid

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exit");

    for (i = 0; ngx_modules[i]; i++) 
	{
        if (ngx_modules[i]->exit_master) 
		{
            ngx_modules[i]->exit_master(cycle);//调用所有模块的exit_master
        }
    }

    ngx_close_listening_sockets(cycle);//关闭进程打开的监听端口

    /*
     * Copy ngx_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard ngx_cycle->log allocated from
     * ngx_cycle->pool is already destroyed.
     */

    ngx_exit_log_file.fd = ngx_cycle->log->file->fd;

    ngx_exit_log = *ngx_cycle->log;
    ngx_exit_log.file = &ngx_exit_log_file;

    ngx_exit_cycle.log = &ngx_exit_log;
    ngx_exit_cycle.files = ngx_cycle->files;
    ngx_exit_cycle.files_n = ngx_cycle->files_n;
    ngx_cycle = &ngx_exit_cycle;

    ngx_destroy_pool(cycle->pool);//销毁内存池，退出master进程

    exit(0);
}

//参考：http://www.cnblogs.com/h2-database/archive/2012/05/22/2583264.html
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data)
{
    ngx_int_t worker = (intptr_t) data;
    ngx_uint_t         i;
    ngx_connection_t  *c;
    ngx_process = NGX_PROCESS_WORKER;//在master中，ngx_process被设置为NGX_PROCESS_MASTER
    ngx_worker_process_init(cycle, worker);//worker子进程的初始化
    ngx_setproctitle("worker process");
#if (NGX_THREADS)
    {
    ngx_int_t         n;
    ngx_err_t         err;
    ngx_core_conf_t  *ccf;
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    if (ngx_threads_n) {
        if (ngx_init_threads(ngx_threads_n, ccf->thread_stack_size, cycle) == NGX_ERROR)
        {
            exit(2);
        }
        err = ngx_thread_key_create(&ngx_core_tls_key);
        if (err != 0) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, err, ngx_thread_key_create_n " failed");
            exit(2);
        }
        for (n = 0; n < ngx_threads_n; n++) {

            ngx_threads[n].cv = ngx_cond_init(cycle->log);

            if (ngx_threads[n].cv == NULL) {
                /* fatal */
                exit(2);
            }
            if (ngx_create_thread((ngx_tid_t *) &ngx_threads[n].tid,
                                  ngx_worker_thread_cycle,
                                  (void *) &ngx_threads[n], cycle->log)
                != 0)
            {
                /* fatal */
                exit(2);
            }
        }
    }
    }
#endif
    for ( ;; ) 
	{
        if (ngx_exiting) //如果进程退出,关闭所有连接
		{
            c = cycle->connections;
            for (i = 0; i < cycle->connection_n; i++) 
			{
                /* THREAD: lock */
				/* 首先根据当前ngx_cycle_t中所有正在处理的连接，调用他们对应的关闭连接处理方法，就是将连接中的close标志置为1，再调用
				 * 读事件处理方法*/
                if (c[i].fd != -1 && c[i].idle) 
				{
                    c[i].close = 1;
                    c[i].read->handler(c[i].read);
                }
            }
			/* 该红黑树为空表示已经处理完所有事件，这时将调用所有模块的exit_process方法，最后销毁整个内存池，退出worker进程。如果不为空，
			 * 表示还有事件需要处理，将继续向下处理，调用ngx_process_events_and_timers方法处理事件*/
            if (ngx_event_timer_rbtree.root == ngx_event_timer_rbtree.sentinel)
            {
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
                ngx_worker_process_exit(cycle);
            }
        }
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");
		//处理事件和定时器
        ngx_process_events_and_timers(cycle);
        if (ngx_terminate) //收到NGX_CMD_TERMINATE命令
		{
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
			/*清理后进程退出，会调用所有模块的钩子exit_process.与上一步ngx_exiting为1的退出不同，这里不会调用所有活动连接的处理方法去
			 处理关闭连接事件，也不会检查是否已经处理完所有的事件，而是立刻调用所有模块的exit_process方法，销毁内存池，退出worker进程*/
            ngx_worker_process_exit(cycle);
        }
        if (ngx_quit) //收到NGX_CMD_QUIT命令
		{
            ngx_quit = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,"gracefully shutting down");
            ngx_setproctitle("worker process is shutting down");
            if (!ngx_exiting) 
			{ //如果进程没有"正在退出"
                ngx_close_listening_sockets(cycle);//关闭监听socket
                ngx_exiting = 1;//设置正在退出状态
            }
        }
        if (ngx_reopen) //收到NGX_CMD_REOPEN命令，重新打开log
		{
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, -1);
        }
    }
}

//参考:http://www.cnblogs.com/h2-database/archive/2012/05/22/2583264.html
static void ngx_worker_process_init(ngx_cycle_t *cycle, ngx_int_t worker)
{
    sigset_t          set;
    uint64_t          cpu_affinity;
    ngx_int_t         n;
    ngx_uint_t        i;
    struct rlimit     rlmt;
    ngx_core_conf_t  *ccf;
    ngx_listening_t  *ls;
	//全局性的设置，根据全局的配置信息设置执行环境、优先级、限制、setgid、setuid、信号初始化等
    if (ngx_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    if (worker >= 0 && ccf->priority != 0) {
        if (setpriority(PRIO_PROCESS, 0, ccf->priority) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "setpriority(%d) failed", ccf->priority);
        }
    }
    if (ccf->rlimit_nofile != NGX_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_nofile;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_nofile;

        if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"setrlimit(RLIMIT_NOFILE, %i) failed",ccf->rlimit_nofile);
        }
    }
    if (ccf->rlimit_core != NGX_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_core;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_core;

        if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "setrlimit(RLIMIT_CORE, %O) failed", ccf->rlimit_core);
        }
    }
#ifdef RLIMIT_SIGPENDING
    if (ccf->rlimit_sigpending != NGX_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_sigpending;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_sigpending;
        if (setrlimit(RLIMIT_SIGPENDING, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"setrlimit(RLIMIT_SIGPENDING, %i) failed", ccf->rlimit_sigpending);
        }
    }
#endif
    if (geteuid() == 0) {
        if (setgid(ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno, "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }
        if (initgroups(ccf->username, ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno, "initgroups(%s, %d) failed", ccf->username, ccf->group);
        }
        if (setuid(ccf->user) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,"setuid(%d) failed", ccf->user);
            /* fatal */
            exit(2);
        }
    }
    if (worker >= 0) {
        cpu_affinity = ngx_get_cpu_affinity(worker);
        if (cpu_affinity) {
            ngx_setaffinity(cpu_affinity, cycle->log);
        }
    }
#if (NGX_HAVE_PR_SET_DUMPABLE)

    /* allow coredump after setuid() in Linux 2.4.x */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "prctl(PR_SET_DUMPABLE) failed");
    }
#endif
    if (ccf->working_directory.len) {
        if (chdir((char *) ccf->working_directory.data) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"chdir(\"%s\") failed", ccf->working_directory.data);
            /* fatal */
            exit(2);
        }
    }
    sigemptyset(&set);
    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "sigprocmask() failed");
    }
    /* disable deleting previous events for the listening sockets because in the worker processes there are no
     * events at all at this point */
    ls = cycle->listening.elts;
    for (i = 0; i < cycle->listening.nelts; i++) {
        ls[i].previous = NULL;
    }
    for (i = 0; ngx_modules[i]; i++)
    {
        if (ngx_modules[i]->init_process)
		{//调用所有模块的钩子init_process
            if (ngx_modules[i]->init_process(cycle) == NGX_ERROR)
			{
                exit(2);
            }
        }
    }
    for (n = 0; n < ngx_last_process; n++)
	{//遍历所有的worker进程
        if (ngx_processes[n].pid == -1) {
            continue;
        }
        if (n == ngx_process_slot)
		{//如果是自己
            continue;
        }
        if (ngx_processes[n].channel[1] == -1) 
		{
            continue;
        }
        if (close(ngx_processes[n].channel[1]) == -1) 
		{//关闭所有其他worker进程channel[1]句柄(用于监听)
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"close() channel failed");
        }
    }
    /* 关闭自己的channel[0]句柄(用于发送信息),当前worker会使用其他worker的channel[0]句柄发送消息，使用当前worker的channel[1]句柄
     * 监听可读事件 */
    if (close(ngx_processes[ngx_process_slot].channel[0]) == -1)
	{
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "close() channel failed");
    }
#if 0
    ngx_last_process = 0;
#endif
	/*ngx_add_channel_event把句柄ngx_channel(当前worker的channel[1])上建立的连接的可读事件加入事件监控
	队列，事件处理函数为ngx_channel_hanlder(ngx_event_t *ev)。当有可读事件的时候，ngx_channel_handler负
	责处理消息具体代码可以查看src/os/unix/ngx_channel.c*/
    if (ngx_add_channel_event(cycle, ngx_channel, NGX_READ_EVENT,ngx_channel_handler)== NGX_ERROR)
    {
        exit(2);
    }
}

//执行缓存管理工作的循环方法，这与文件缓存模块密切相关
static void ngx_worker_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t         i;
    ngx_connection_t  *c;

#if (NGX_THREADS)
    ngx_terminate = 1;

    ngx_wakeup_worker_threads(cycle);
#endif

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->exit_process) {
            ngx_modules[i]->exit_process(cycle);
        }
    }

    if (ngx_exiting) {
        c = cycle->connections;
        for (i = 0; i < cycle->connection_n; i++) {
            if (c[i].fd != -1
                && c[i].read
                && !c[i].read->accept
                && !c[i].read->channel
                && !c[i].read->resolver)
            {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                              "open socket #%d left in connection %ui",
                              c[i].fd, i);
                ngx_debug_quit = 1;
            }
        }

        if (ngx_debug_quit) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "aborting");
            ngx_debug_point();
        }
    }

    /*
     * Copy ngx_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard ngx_cycle->log allocated from
     * ngx_cycle->pool is already destroyed.
     */

    ngx_exit_log_file.fd = ngx_cycle->log->file->fd;

    ngx_exit_log = *ngx_cycle->log;
    ngx_exit_log.file = &ngx_exit_log_file;

    ngx_exit_cycle.log = &ngx_exit_log;
    ngx_exit_cycle.files = ngx_cycle->files;
    ngx_exit_cycle.files_n = ngx_cycle->files_n;
    ngx_cycle = &ngx_exit_cycle;

    ngx_destroy_pool(cycle->pool);

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "exit");

    exit(0);
}

/* 把接收到的新子进程的相关信息存储在全局变量ngx_processes内*/
static void ngx_channel_handler(ngx_event_t *ev)
{
    ngx_int_t          n;
    ngx_channel_t      ch;
    ngx_connection_t  *c;
    if (ev->timedout)
    {
        ev->timedout = 0;
        return;
    }
    c = ev->data;
    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel handler");
    for ( ;; )
    {
        n = ngx_read_channel(c->fd, &ch, sizeof(ngx_channel_t), ev->log);
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel: %i", n);
        if (n == NGX_ERROR)
        {
            if (ngx_event_flags & NGX_USE_EPOLL_EVENT)
            {
                ngx_del_conn(c, 0);
            }
            ngx_close_connection(c);
            return;
        }
        if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT)
        {
            if (ngx_add_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR)
            {
                return;
            }
        }
        if (n == NGX_AGAIN)
        {
            return;
        }
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,"channel command: %d", ch.command);
        switch (ch.command)
        {
        case NGX_CMD_QUIT:
            ngx_quit = 1;
            break;
        case NGX_CMD_TERMINATE:
            ngx_terminate = 1;
            break;
        case NGX_CMD_REOPEN:
            ngx_reopen = 1;
            break;
		/* 把接收到的新子进程的相关信息存储在全局变量ngx_processes内*/
        case NGX_CMD_OPEN_CHANNEL:
            ngx_log_debug3(NGX_LOG_DEBUG_CORE, ev->log, 0, "get channel s:%i pid:%P fd:%d", ch.slot, ch.pid, ch.fd);
            ngx_processes[ch.slot].pid = ch.pid;
            ngx_processes[ch.slot].channel[0] = ch.fd;
            break;
        case NGX_CMD_CLOSE_CHANNEL:
            ngx_log_debug4(NGX_LOG_DEBUG_CORE, ev->log, 0,"close channel s:%i pid:%P our:%P fd:%d", ch.slot, ch.pid, ngx_processes[ch.slot].pid, ngx_processes[ch.slot].channel[0]);
            if (close(ngx_processes[ch.slot].channel[0]) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno, "close() channel failed");
            }
            ngx_processes[ch.slot].channel[0] = -1;
            break;
        }
    }
}
#if (NGX_THREADS)

static void
ngx_wakeup_worker_threads(ngx_cycle_t *cycle)
{
    ngx_int_t   i;
    ngx_uint_t  live;

    for ( ;; ) {

        live = 0;

        for (i = 0; i < ngx_threads_n; i++) {
            if (ngx_threads[i].state < NGX_THREAD_EXIT) {
                if (ngx_cond_signal(ngx_threads[i].cv) == NGX_ERROR) {
                    ngx_threads[i].state = NGX_THREAD_DONE;

                } else {
                    live = 1;
                }
            }

            if (ngx_threads[i].state == NGX_THREAD_EXIT) {
                ngx_thread_join(ngx_threads[i].tid, NULL);
                ngx_threads[i].state = NGX_THREAD_DONE;
            }
        }

        if (live == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                           "all worker threads are joined");

            /* STUB */
            ngx_done_events(cycle);
            ngx_mutex_destroy(ngx_event_timer_mutex);
            ngx_mutex_destroy(ngx_posted_events_mutex);

            return;
        }

        ngx_sched_yield();
    }
}


static ngx_thread_value_t
ngx_worker_thread_cycle(void *data)
{
    ngx_thread_t  *thr = data;

    sigset_t          set;
    ngx_err_t         err;
    ngx_core_tls_t   *tls;
    ngx_cycle_t      *cycle;

    cycle = (ngx_cycle_t *) ngx_cycle;

    sigemptyset(&set);
    sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));

    err = ngx_thread_sigmask(SIG_BLOCK, &set, NULL);
    if (err) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      ngx_thread_sigmask_n " failed");
        return (ngx_thread_value_t) 1;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "thread " NGX_TID_T_FMT " started", ngx_thread_self());

    ngx_setthrtitle("worker thread");

    tls = ngx_calloc(sizeof(ngx_core_tls_t), cycle->log);
    if (tls == NULL) {
        return (ngx_thread_value_t) 1;
    }

    err = ngx_thread_set_tls(ngx_core_tls_key, tls);
    if (err != 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                      ngx_thread_set_tls_n " failed");
        return (ngx_thread_value_t) 1;
    }

    ngx_mutex_lock(ngx_posted_events_mutex);

    for ( ;; ) {
        thr->state = NGX_THREAD_FREE;

        if (ngx_cond_wait(thr->cv, ngx_posted_events_mutex) == NGX_ERROR) {
            return (ngx_thread_value_t) 1;
        }

        if (ngx_terminate) {
            thr->state = NGX_THREAD_EXIT;

            ngx_mutex_unlock(ngx_posted_events_mutex);

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                           "thread " NGX_TID_T_FMT " is done",
                           ngx_thread_self());

            return (ngx_thread_value_t) 0;
        }

        thr->state = NGX_THREAD_BUSY;

        if (ngx_event_thread_process_posted(cycle) == NGX_ERROR) {
            return (ngx_thread_value_t) 1;
        }

        if (ngx_event_thread_process_posted(cycle) == NGX_ERROR) {
            return (ngx_thread_value_t) 1;
        }

        if (ngx_process_changes) {
            if (ngx_process_changes(cycle, 1) == NGX_ERROR) {
                return (ngx_thread_value_t) 1;
            }
        }
    }
}

#endif


static void
ngx_cache_manager_process_cycle(ngx_cycle_t *cycle, void *data)
{
    ngx_cache_manager_ctx_t *ctx = data;

    void         *ident[4];
    ngx_event_t   ev;

    /*
     * Set correct process type since closing listening Unix domain socket
     * in a master process also removes the Unix domain socket file.
     */
    ngx_process = NGX_PROCESS_HELPER;

    ngx_close_listening_sockets(cycle);

    /* Set a moderate number of connections for a helper process. */
    cycle->connection_n = 512;

    ngx_worker_process_init(cycle, -1);

    ngx_memzero(&ev, sizeof(ngx_event_t));
    ev.handler = ctx->handler;
    ev.data = ident;
    ev.log = cycle->log;
    ident[3] = (void *) -1;

    ngx_use_accept_mutex = 0;

    ngx_setproctitle(ctx->name);

    ngx_add_timer(&ev, ctx->delay);

    for ( ;; ) {

        if (ngx_terminate || ngx_quit) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
            exit(0);
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, -1);
        }

        ngx_process_events_and_timers(cycle);
    }
}


static void
ngx_cache_manager_process_handler(ngx_event_t *ev)
{
    time_t        next, n;
    ngx_uint_t    i;
    ngx_path_t  **path;

    next = 60 * 60;

    path = ngx_cycle->paths.elts;
    for (i = 0; i < ngx_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            n = path[i]->manager(path[i]->data);

            next = (n <= next) ? n : next;

            ngx_time_update();
        }
    }

    if (next == 0) {
        next = 1;
    }

    ngx_add_timer(ev, next * 1000);
}

static void
ngx_cache_loader_process_handler(ngx_event_t *ev)
{
    ngx_uint_t     i;
    ngx_path_t   **path;
    ngx_cycle_t   *cycle;

    cycle = (ngx_cycle_t *) ngx_cycle;

    path = cycle->paths.elts;
    for (i = 0; i < cycle->paths.nelts; i++) {

        if (ngx_terminate || ngx_quit) {
            break;
        }

        if (path[i]->loader) {
            path[i]->loader(path[i]->data);
            ngx_time_update();
        }
    }

    exit(0);
}
