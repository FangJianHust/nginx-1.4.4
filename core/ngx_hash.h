
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    void             *value;//指向用户定义的数据的指针，如果当前ngx_hash_elt_t槽为空，则value为0
    u_short           len;//元素关键字的长度
    u_char            name[1];//元素关键字的首地址
} ngx_hash_elt_t;


typedef struct 
{
	//指向散列表的首地址，也就是第1个槽的地址
    ngx_hash_elt_t  **buckets;
    ngx_uint_t        size;//槽的总数
} ngx_hash_t;

//用于表示前置或后置的散列表
typedef struct {
    ngx_hash_t        hash;//基本散列表
    void             *value;//当使用这个ngx_hash_wildcard_t通配符散列表作为某容器的元素时，可以使用这个value指针指向用户数据
} ngx_hash_wildcard_t;


typedef struct {
    ngx_str_t         key;//元素关键字
    ngx_uint_t        key_hash;//由散列方法算出来的关键码
    void             *value;//指向实际的用户数据
} ngx_hash_key_t;


typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);//用于计算key的方法，data是数据首地址，可以通过把任意的数据结构强制转换为u_char*并传给ngx_hash_key_t，len是元素关键字的长度


typedef struct 
{
    ngx_hash_t            hash;//用于精确匹配的基本散列表
    ngx_hash_wildcard_t  *wc_head;//用于查询前置通配符的散列表

	//用于查询后置通配符散列表
    ngx_hash_wildcard_t  *wc_tail;
} ngx_hash_combined_t;


typedef struct {
    ngx_hash_t       *hash;//指向通用的完全匹配散列表
    ngx_hash_key_pt   key;//用于初始化预添加元素的散列方法

    ngx_uint_t        max_size;//散列表中槽的最大数目
    ngx_uint_t        bucket_size;//散列表中一个槽的空间大小，它限制了每个散列表元素关键字的最大长度

    char             *name;//散列表的名称
    ngx_pool_t       *pool;//内存池，它分配散列表(最多3个，包括1个普通散列表、1个前置通配符散列表、1个后置通配符散列表)中的所有槽
    ngx_pool_t       *temp_pool;//临时内存池，它仅存在于初始化散列表之前。它主要用于分配一些临时的动态数组，带通配符的元素在初始化时需要用到这些数组
} ngx_hash_init_t;


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


typedef struct {
    ngx_uint_t        hsize;//下面的keys_hash、dns_wc_head_hash、dns_wc_tail_hash都是简易散列表，而hsize指明了散列表的槽的个数，其简易散列表方法也需要对hsize求余

    ngx_pool_t       *pool;//内存池，用于分配永久性内存，到目前为止，该成员没有意义
    ngx_pool_t       *temp_pool;//临时内存池，下面的动态数组需要的内存都由temp_pool内存池分配

    ngx_array_t       keys;//用动态数组以ngx_hash_key_t结构体保存着不含通配符关键字的元素
    ngx_array_t      *keys_hash;//一个极其简易的散列表，它以数组的形式保存着jsize个元素，每个元素都是ngx_array_t动态数组。在用户添加元素过程中，会根据关键码将用户的ngx_str_t类型的关键字添加到ngx_array_t动态数组中。这里所有的用户元素的关键字都不可以带通配符，表示精确匹配

    ngx_array_t       dns_wc_head;//用动态数组以ngx_hash_key_t结构体保存着含有前置关键字的元素生成的中间关键字
    ngx_array_t      *dns_wc_head_hash;//一个极其简易的散列表，它以数组的形式保存着jsize个元素，每个元素都是ngx_array_t动态数组。在用户添加元素过程中，会根据关键码将用户的ngx_str_t类型的关键字添加到ngx_array_t动态数组中。这里所有的用户元素的关键字都带前置通配符


    ngx_array_t       dns_wc_tail;//用动态数组以ngx_hash_key_t结构体保存着含有后置关键字的元素生成的中间关键字
    ngx_array_t      *dns_wc_tail_hash;//一个极其简易的散列表，它以数组的形式保存着jsize个元素，每个元素都是ngx_array_t    动态数组。在用户添加元素过程中，会根据关键码将用户的ngx_str_t类型的关键字添加到ngx_array_	t动态数组中。这里所有的用户元素的关键字都带后置通配符
} ngx_hash_keys_arrays_t;

/* ngx_table_elt_t可以是某个散列表的结构中的成员(如ngx_hash_t),但主要是用于HTTP头部。
其中：key存储头部名称(如content-length),value存储对应的值,lowcase_key是为了忽略大小写，
hash用于快速检索头部 */
typedef struct 
{
    ngx_uint_t        hash;
    ngx_str_t         key;
    ngx_str_t         value;
    u_char           *lowcase_key;
} ngx_table_elt_t;


void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);
void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)
ngx_uint_t ngx_hash_key(u_char *data, size_t len);
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);


ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */
