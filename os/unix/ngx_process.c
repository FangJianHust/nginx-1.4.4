#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>

//描述一个信号的结构体，其定义的数组ngx_signal_t signals[]包括了全部的信号
typedef struct {

	//信号值，如SIGHUP、SIGINT等
    int     signo;
    char   *signame;//信号对应的字符串的名称
    char   *name;//这个信号对应着的nginx命令

	//信号处理程序，没有忽略的信号的处理程序都是ngx_signal_handler()
    void  (*handler)(int signo);
} ngx_signal_t;

static void ngx_execute_proc(ngx_cycle_t *cycle, void *data);
static void ngx_signal_handler(int signo);
static void ngx_process_get_status(void);
static void ngx_unlock_mutexes(ngx_pid_t pid);

int              ngx_argc;
char           **ngx_argv;
char           **ngx_os_argv;

//当前操作的进程在ngx_processes数组中的下标
ngx_int_t        ngx_process_slot;
ngx_socket_t     ngx_channel;
ngx_int_t        ngx_last_process;//ngx_processes中有意义的最大下标

/* 存储所有子进程的数组，父进程用来和子进程通信，子进程用来和其它子进程通信 */
ngx_process_t    ngx_processes[NGX_MAX_PROCESSES];
//定义进程将会处理的所有信号
ngx_signal_t  signals[] = {
    { ngx_signal_value(NGX_RECONFIGURE_SIGNAL),/*在不中止nginx服务的情况下更新配置*/
      "SIG" ngx_value(NGX_RECONFIGURE_SIGNAL),
      "reload",
      ngx_signal_handler },

    { ngx_signal_value(NGX_REOPEN_SIGNAL),
      "SIG" ngx_value(NGX_REOPEN_SIGNAL),
      "reopen",
      ngx_signal_handler },

    { ngx_signal_value(NGX_NOACCEPT_SIGNAL),
      "SIG" ngx_value(NGX_NOACCEPT_SIGNAL),
      "",
      ngx_signal_handler },

    { ngx_signal_value(NGX_TERMINATE_SIGNAL),
      "SIG" ngx_value(NGX_TERMINATE_SIGNAL),
      "stop",
      ngx_signal_handler },

    { ngx_signal_value(NGX_SHUTDOWN_SIGNAL),
      "SIG" ngx_value(NGX_SHUTDOWN_SIGNAL),
      "quit",
      ngx_signal_handler },

    { ngx_signal_value(NGX_CHANGEBIN_SIGNAL),
      "SIG" ngx_value(NGX_CHANGEBIN_SIGNAL),
      "",
      ngx_signal_handler },

    { SIGALRM, "SIGALRM", "", ngx_signal_handler },

    { SIGINT, "SIGINT", "", ngx_signal_handler },

    { SIGIO, "SIGIO", "", ngx_signal_handler },

    { SIGCHLD, "SIGCHLD", "", ngx_signal_handler },

    { SIGSYS, "SIGSYS, SIG_IGN", "", SIG_IGN },/*信号被忽略*/

    { SIGPIPE, "SIGPIPE, SIG_IGN", "", SIG_IGN },

    { 0, NULL, "", NULL }/*哨兵，结束的标志*/
};

/*proc:是子进程的执行函数ngx_worker_process_cycle,data是参数，name是子进程的名字*/
ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle, ngx_spawn_proc_pt proc, void *data,char *name, ngx_int_t respawn)
{
    u_long     on;
    ngx_pid_t  pid;
	//将要创建的子进程在进程表中的位置
    ngx_int_t  s;
	//替换进程ngx_processes[respawn],可安全重用该进程表项
    if (respawn >= 0) 
	{
        s = respawn;
    } 
	else 
	{
		//先找到一个被回收的进程表项
        for (s = 0; s < ngx_last_process; s++)
        {
            if (ngx_processes[s].pid == -1) {
                break;
            }
        }
		//进程表已经满
        if (s == NGX_MAX_PROCESSES) 
		{
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,"no more than %d processes can be spawned", NGX_MAX_PROCESSES);
            return NGX_INVALID_PID;
        }
    }
	//不是分离的子进程
    if (respawn != NGX_PROCESS_DETACHED) 
	{
        /* Solaris 9 still has no AF_LOCAL */

		//ngx_processes[s].channel数组是用于父子间通信的UNIX域套接字对
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, ngx_processes[s].channel) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "socketpair() failed while spawning \"%s\"", name);
            return NGX_INVALID_PID;
        }
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,"channel %d:%d", ngx_processes[s].channel[0], ngx_processes[s].channel[1]);
		//设置socket为非阻塞模式
        if (ngx_nonblocking(ngx_processes[s].channel[0]) == -1) 
		{ 
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, ngx_nonblocking_n " failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }
        if (ngx_nonblocking(ngx_processes[s].channel[1]) == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, ngx_nonblocking_n " failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }
		//开启channel[0]的消息驱动IO
        on = 1;
		/*FIOASYNC:设置/清除信号驱动异步I/O标志.根据iocl 的第三个参数指向一个0 值或非0 值分别清除或设置针对本套接口的信号驱动异步I/O
		 * 标志，它决定是否收取针对本套接口的异步I/O 信号（SIGIO ）。本请求和O_ASYNC 文件状态标志等效，而该标志可以通过fcntl 的F_SETFL命令清除或设置。*/
        if (ioctl(ngx_processes[s].channel[0], FIOASYNC, &on) == -1) 
		{
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"ioctl(FIOASYNC) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }
		//设置channel[0]的宿主，控制channel[0]的SIGIO信号只发给这个进程
        if (fcntl(ngx_processes[s].channel[0], F_SETOWN, ngx_pid) == -1)
		{
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "fcntl(F_SETOWN) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }
		//若进程执行了exec后，关闭socket
        if (fcntl(ngx_processes[s].channel[0], F_SETFD, FD_CLOEXEC) == -1)
		{
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"fcntl(FD_CLOEXEC) failed while spawning \"%s\"", name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }
		//同上
        if (fcntl(ngx_processes[s].channel[1], F_SETFD, FD_CLOEXEC) == -1) 
		{
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "fcntl(FD_CLOEXEC) failed while spawning \"%s\"",name);
            ngx_close_channel(ngx_processes[s].channel, cycle->log);
            return NGX_INVALID_PID;
        }
		//用于监听可读事件的socket
        ngx_channel = ngx_processes[s].channel[1];
    }
    else
    {
        ngx_processes[s].channel[0] = -1;
        ngx_processes[s].channel[1] = -1;
    }
	//设置当前子进程的进程表索引值
    ngx_process_slot = s;
	//创建子进程
    pid = fork();
    switch (pid)
    {
    case -1:
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno, "fork() failed while spawning \"%s\"", name);
        ngx_close_channel(ngx_processes[s].channel, cycle->log);
        return NGX_INVALID_PID;
    case 0:
		//设置当前子进程的父进程id
        ngx_pid = ngx_getpid();
		//子进程运行执行函数
        proc(cycle, data);
        break;
    default:
        break;
    }
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start %s %P", name, pid);
	//设置一些进程表项字段
    ngx_processes[s].pid = pid;
    ngx_processes[s].exited = 0;
	//如果是重复创建，即为替换进程，不用设置其他进程表字段，直接返回。
    if (respawn >= 0) 
	{
        return pid;
    }
	//设置其他进程表字段
    ngx_processes[s].proc = proc;
    ngx_processes[s].data = data;
    ngx_processes[s].name = name;
    ngx_processes[s].exiting = 0;
	//设置进程表项的一些状态字
    switch (respawn) 
	{
    case NGX_PROCESS_NORESPAWN:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 0;
        break;
    case NGX_PROCESS_JUST_SPAWN:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 1;
        ngx_processes[s].detached = 0;
        break;
    case NGX_PROCESS_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 0;
        break;
    case NGX_PROCESS_JUST_RESPAWN:
        ngx_processes[s].respawn = 1;
        ngx_processes[s].just_spawn = 1;
        ngx_processes[s].detached = 0;
        break;
    case NGX_PROCESS_DETACHED:
        ngx_processes[s].respawn = 0;
        ngx_processes[s].just_spawn = 0;
        ngx_processes[s].detached = 1;
        break;
    }
    if (s == ngx_last_process) {
        ngx_last_process++;
    }
    return pid;
}

ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx)
{
    return ngx_spawn_process(cycle, ngx_execute_proc, ctx, ctx->name, NGX_PROCESS_DETACHED);
}

static void ngx_execute_proc(ngx_cycle_t *cycle, void *data)
{
    ngx_exec_ctx_t  *ctx = data;
    if (execve(ctx->path, ctx->argv, ctx->envp) == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,"execve() failed while executing %s \"%s\"",ctx->name, ctx->path);
    }
    exit(1);
}

//初始化所有的信号
ngx_int_t ngx_init_signals(ngx_log_t *log)
{
    ngx_signal_t      *sig;
	//linux内核使用的信号
    struct sigaction   sa;
	/* 遍历signals数组，处理每一个ngx_signal_t类型的结构体 */
    for (sig = signals; sig->signo != 0; sig++)
    {
        ngx_memzero(&sa, sizeof(struct sigaction));
		//设置信号处理方法为handler方法，该方法在signals数组中指定
        sa.sa_handler = sig->handler;
		//将sa中的位全部置为0
        sigemptyset(&sa.sa_mask);
		/* 向linux注册信号的回调方法 */
        if (sigaction(sig->signo, &sa, NULL) == -1)
        {
            ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,"sigaction(%s) failed", sig->signame);
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}
//处理信号
void ngx_signal_handler(int signo)
{
    char            *action;
    ngx_int_t        ignore;
    ngx_err_t        err;
    ngx_signal_t    *sig;
    ignore = 0;
    err = ngx_errno;
    for (sig = signals; sig->signo != 0; sig++)
    {
        if (sig->signo == signo) {
            break;
        }
    }
    ngx_time_sigsafe_update();
    action = "";
    switch (ngx_process)
    {
    case NGX_PROCESS_MASTER:
    case NGX_PROCESS_SINGLE:
        switch (signo) {
        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            ngx_quit = 1;
            action = ", shutting down";
            break;
        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            ngx_terminate = 1;
            action = ", exiting";
            break;
        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            if (ngx_daemonized) {
                ngx_noaccept = 1;
                action = ", stop accepting connections";
            }
            break;
        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
            ngx_reconfigure = 1;
            action = ", reconfiguring";
            break;
        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            ngx_reopen = 1;
            action = ", reopening logs";
            break;
        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
            if (getppid() > 1 || ngx_new_binary > 0) {

                /*
                 * Ignore the signal in the new binary if its parent is
                 * not the init process, i.e. the old binary's process
                 * is still running.  Or ignore the signal in the old binary's
                 * process if the new binary's process is already running.
                 */

                action = ", ignoring";
                ignore = 1;
                break;
            }
            ngx_change_binary = 1;
            action = ", changing binary";
            break;
        case SIGALRM:
            ngx_sigalrm = 1;
            break;
        case SIGIO:
            ngx_sigio = 1;
            break;
        case SIGCHLD:
            ngx_reap = 1;
            break;
        }
        break;
    case NGX_PROCESS_WORKER:
    case NGX_PROCESS_HELPER:
        switch (signo) {
        case ngx_signal_value(NGX_NOACCEPT_SIGNAL):
            if (!ngx_daemonized) {
                break;
            }
            ngx_debug_quit = 1;
        case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
            ngx_quit = 1;
            action = ", shutting down";
            break;
        case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        case SIGINT:
            ngx_terminate = 1;
            action = ", exiting";
            break;
        case ngx_signal_value(NGX_REOPEN_SIGNAL):
            ngx_reopen = 1;
            action = ", reopening logs";
            break;
        case ngx_signal_value(NGX_RECONFIGURE_SIGNAL):
        case ngx_signal_value(NGX_CHANGEBIN_SIGNAL):
        case SIGIO:
            action = ", ignoring";
            break;
        }
        break;
    }
    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "signal %d (%s) received%s", signo, sig->signame, action);
    if (ignore)
    {
        ngx_log_error(NGX_LOG_CRIT, ngx_cycle->log, 0,
                      "the changing binary signal is ignored: "
                      "you should shutdown or terminate "
                      "before either old or new binary's process");
    }
    if (signo == SIGCHLD) {
        ngx_process_get_status();
    }

    ngx_set_errno(err);
}

static void ngx_process_get_status(void)
{
    int              status;
    char            *process;
    ngx_pid_t        pid;
    ngx_err_t        err;
    ngx_int_t        i;
    ngx_uint_t       one;

    one = 0;

    for ( ;; ) {
        pid = waitpid(-1, &status, WNOHANG);

        if (pid == 0) {
            return;
        }

        if (pid == -1) {
            err = ngx_errno;

            if (err == NGX_EINTR) {
                continue;
            }

            if (err == NGX_ECHILD && one) {
                return;
            }

            /*
             * Solaris always calls the signal handler for each exited process
             * despite waitpid() may be already called for this process.
             *
             * When several processes exit at the same time FreeBSD may
             * erroneously call the signal handler for exited process
             * despite waitpid() may be already called for this process.
             */

            if (err == NGX_ECHILD) {
                ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, err,
                              "waitpid() failed");
                return;
            }

            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, err,
                          "waitpid() failed");
            return;
        }


        one = 1;
        process = "unknown process";

        for (i = 0; i < ngx_last_process; i++) {
            if (ngx_processes[i].pid == pid) {
                ngx_processes[i].status = status;
                ngx_processes[i].exited = 1;
                process = ngx_processes[i].name;
                break;
            }
        }

        if (WTERMSIG(status)) {
#ifdef WCOREDUMP
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d%s",
                          process, pid, WTERMSIG(status),
                          WCOREDUMP(status) ? " (core dumped)" : "");
#else
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited on signal %d",
                          process, pid, WTERMSIG(status));
#endif

        } else {
            ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0,
                          "%s %P exited with code %d",
                          process, pid, WEXITSTATUS(status));
        }

        if (WEXITSTATUS(status) == 2 && ngx_processes[i].respawn) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "%s %P exited with fatal code %d "
                          "and cannot be respawned",
                          process, pid, WEXITSTATUS(status));
            ngx_processes[i].respawn = 0;
        }

        ngx_unlock_mutexes(pid);
    }
}


static void
ngx_unlock_mutexes(ngx_pid_t pid)
{
    ngx_uint_t        i;
    ngx_shm_zone_t   *shm_zone;
    ngx_list_part_t  *part;
    ngx_slab_pool_t  *sp;

    /*
     * unlock the accept mutex if the abnormally exited process
     * held it
     */

    if (ngx_accept_mutex_ptr) {
        (void) ngx_shmtx_force_unlock(&ngx_accept_mutex, pid);
    }

    /*
     * unlock shared memory mutexes if held by the abnormally exited
     * process
     */

    part = (ngx_list_part_t *) &ngx_cycle->shared_memory.part;
    shm_zone = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            shm_zone = part->elts;
            i = 0;
        }

        sp = (ngx_slab_pool_t *) shm_zone[i].shm.addr;

        if (ngx_shmtx_force_unlock(&sp->mutex, pid)) {
            ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log, 0,
                          "shared memory zone \"%V\" was locked by %P",
                          &shm_zone[i].shm.name, pid);
        }
    }
}


void
ngx_debug_point(void)
{
    ngx_core_conf_t  *ccf;

    ccf = (ngx_core_conf_t *) ngx_get_conf(ngx_cycle->conf_ctx,
                                           ngx_core_module);

    switch (ccf->debug_points) {

    case NGX_DEBUG_POINTS_STOP:
        raise(SIGSTOP);
        break;

    case NGX_DEBUG_POINTS_ABORT:
        ngx_abort();
    }
}


ngx_int_t
ngx_os_signal_process(ngx_cycle_t *cycle, char *name, ngx_int_t pid)
{
    ngx_signal_t  *sig;

    for (sig = signals; sig->signo != 0; sig++) {
        if (ngx_strcmp(name, sig->name) == 0) {
            if (kill(pid, sig->signo) != -1) {
                return 0;
            }

            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "kill(%P, %d) failed", pid, sig->signo);
        }
    }

    return 1;
}
