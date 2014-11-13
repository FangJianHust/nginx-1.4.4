#ifndef _NGX_SHMEM_H_INCLUDED_
#define _NGX_SHMEM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/* 共享内存结构体 */
typedef struct
 {
 	//指向共享内存的起始地址
    u_char      *addr;
    size_t       size;//长度
    ngx_str_t    name;
    ngx_log_t   *log;
    ngx_uint_t   exists;   /* 表示共享内存是否已经分配过，为1表示已经存在 */
} ngx_shm_t;

ngx_int_t ngx_shm_alloc(ngx_shm_t *shm);
void ngx_shm_free(ngx_shm_t *shm);

#endif /* _NGX_SHMEM_H_INCLUDED_ */
