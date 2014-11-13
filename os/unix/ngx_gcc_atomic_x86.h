
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#if (NGX_SMP)
#define NGX_SMP_LOCK  "lock;"
#else
#define NGX_SMP_LOCK
#endif


/*
 * "cmpxchgl  r, [m]":
 *
 *     if (eax == [m]) {//如果eax寄存器中的值等于m
 *         zf = 1;//将zf标志为设为1
 *         [m] = r;//将m设置为r
 *     } else {//如果eax寄存器中的值不等于m
 *         zf = 0;//zf设置为0
 *         eax = [m];//eax设置为m
 *     }
 *
 *
 * The "r" means the general register.
 * The "=a" and "a" are the %eax register.
 * Although we can return result in any register, we use "a" because it is
 * used in cmpxchgl anyway.  The result is actually in %al but not in %eax,
 * however, as the code is inlined gcc can test %al as well as %eax,
 * and icc adds "movzbl %al, %eax" by itself.
 *
 * The "cc" means that flags were changed.
 */

static ngx_inline ngx_atomic_uint_t
ngx_atomic_cmp_set(ngx_atomic_t *lock, ngx_atomic_uint_t old,
    ngx_atomic_uint_t set)
{
    u_char  res;

	/*在C语言中嵌入汇编语言*/
    __asm__ volatile (

         NGX_SMP_LOCK//多核架构下首先锁住总线
         /*将*lock的值与eax寄存器中的old向比较，如果相等，则置*lock为set*/
    "    cmpxchgl  %3, %1;   "//可以直接使用占位符%来引用C语言中的变量，最多10个，%0~%9
    "    sete      %0;       "//cmpxchgl 的比较若是相等，则把zf标志位1写入res变量，否则res为0

    : "=a" (res) : "m" (*lock), "a" (old), "r" (set) : "cc", "memory");

    return res;
}


/*
 * "xaddl  r, [m]"://执行后[m]值将为r和[m]之和，而r中的值为原[m]值
 *
 *     temp = [m];
 *     [m] += r;
 *     r = temp;
 *
 *
 * The "+r" means the general register.
 * The "cc" means that flags were changed.
 */


#if !(( __GNUC__ == 2 && __GNUC_MINOR__ <= 7 ) || ( __INTEL_COMPILER >= 800 ))

/*
 * icc 8.1 and 9.0 compile broken code with -march=pentium4 option:
 * ngx_atomic_fetch_add() always return the input "add" value,
 * so we use the gcc 2.7 version.
 *
 * icc 8.1 and 9.0 with -march=pentiumpro option or icc 7.1 compile
 * correct code.
 */

static ngx_inline ngx_atomic_int_t
ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
{
    __asm__ volatile (

         NGX_SMP_LOCK //锁住总线
    "    xaddl  %0, %1;   "//*value的值将会等于原先*value与add之和，而add为原*value值

    : "+r" (add) : "m" (*value) : "cc", "memory");

    return add;
}


#else

/*
 * gcc 2.7 does not support "+r", so we have to use the fixed
 * %eax ("=a" and "a") and this adds two superfluous instructions in the end
 * of code, something like this: "mov %eax, %edx / mov %edx, %eax".
 */

static ngx_inline ngx_atomic_int_t
ngx_atomic_fetch_add(ngx_atomic_t *value, ngx_atomic_int_t add)
{
    ngx_atomic_uint_t  old;

    __asm__ volatile (

         NGX_SMP_LOCK
    "    xaddl  %2, %1;   "

    : "=a" (old) : "m" (*value), "a" (add) : "cc", "memory");

    return old;
}

#endif


/*
 * on x86 the write operations go in a program order, so we need only
 * to disable the gcc reorder optimizations
 */

#define ngx_memory_barrier()    __asm__ volatile ("" ::: "memory")

/* old "as" does not support "pause" opcode */
#define ngx_cpu_pause()         __asm__ (".byte 0xf3, 0x90")
