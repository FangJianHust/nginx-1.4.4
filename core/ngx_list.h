
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;

//链表的一个元素，本身就是一个数组
struct ngx_list_part_s 
{	
	//数组的起始地址
    void             *elts;
	
	//数组中已经使用了多少个元素，nelts必须要小于ngx_list_t中的nalloc
    ngx_uint_t        nelts
    
    //下一个ngx_list_part_t的指针，把ngx_list_t中所有的ngx_list_part_t连接起来;
    ngx_list_part_t  *next;
};

//整个链表，链表中的元素是ngx_list_part_t数组,因此整个链表可以看作二维数组
typedef struct 
{
	/* 向链表的最后一个数组元素，也是当前正在使用的ngx_list_part_t，因为ngx_list_t只有last 指向
	的ngx_list_part_t空间没有被用完，每次用完时，会使用ngx_list_push分配一个新的ngx_list_part_t*/
    ngx_list_part_t  *last;

	//链表的首个数组元素
    ngx_list_part_t   part;

	//每一个ngx_list_part_t中数据的大小要小于等于size，即“二维数组”中的单个数据的最大空间
    size_t            size;

	//每一个ngx_list_part_t中数据的个数
    ngx_uint_t        nalloc;

	//链表中管理内存分配的内存池对象。用户要存放的数据占用的内存都是由pool分配的
    ngx_pool_t       *pool;
} ngx_list_t;


ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);//n相当于nalloc

////对链表进行初始化，此时链表已经创建成功
static ngx_inline ngx_int_t ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NGX_ERROR;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NGX_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


void *ngx_list_push(ngx_list_t *list);

#endif /* _NGX_LIST_H_INCLUDED_ */
