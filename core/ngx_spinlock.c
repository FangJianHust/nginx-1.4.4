
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/* 基于原子操作的自旋锁.
lock:原子变量表达的锁，当lock为0时表示锁时被释放的，不为0时表示锁已经被某个进程持有了；
value：表示希望当没有任何进程持有锁时，把lock值设置为value表示当前进程持有了锁；
spin：表示在多处理器系统内，当该方法没有拿到锁时，当前进程在内核的一次调度中，该方法等待其他啊处理器释放锁的时间*/
void ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin)
{

#if (NGX_HAVE_ATOMIC_OPS)

    ngx_uint_t  i, n;

	/* 无法获取锁时进程的代码将一直在这个循环中执行 */
    for ( ;; ) 
	{
		/* lock为0表示锁没有被其他进程持有，这时把lock设置为value表示当前进程持有了锁 */
        if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) 
		{
            return;
        }

		/*ngx_ncpu表示处理器个数*/
        if (ngx_ncpu > 1) 
		{
			/* 在多处理器下，更好的做法是当前进程不要立刻让出正在使用的CPU处理器，而是等待一段时间，看看其他处理器
			上的进程是否会释放锁，这会减少进程间切换的次数*/
            for (n = 1; n < spin; n <<= 1) 
			{
				/* 注意，随着等待的次数越来越多，实际去检查lock是否释放的频繁会越来越小，因为检查lock值更消耗CPU，
				而执行ngx_cpu_pause对于CPU的能耗来说是很省电的 */
                for (i = 0; i < n; i++) 
				{
					/* 该方法是在许多架构体系中专门为了自旋锁而提高的指令，他会告诉CPU现在处于自旋锁等待状态，通常
					一些CPU会将自己置于节能状态，降低功耗，注意，在执行该方法后，当前进程没有让出正使用的处理器*/
                    ngx_cpu_pause();
                }

				/* 检查锁是否被释放了，如果lock值为0且释放了锁后，就把它的值设置为value，当前进程持有锁成功并返回 */
                if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) 
				{
                    return;
                }
            }
        }

		/* 当前进程仍然处于可执行状态，但暂时让出处理器，使得处理器优先调度其他可执行状态的进程，这样，在进程被内核
		再次调度时，在for循环代码中可以期望其他进程释放锁*/
        ngx_sched_yield();
    }

#else

#if (NGX_THREADS)

#error ngx_spinlock() or ngx_atomic_cmp_set() are not defined !

#endif

#endif

}
