
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_RADIX_TREE_H_INCLUDED_
#define _NGX_RADIX_TREE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_RADIX_NO_VALUE   (uintptr_t) -1

typedef struct ngx_radix_node_s  ngx_radix_node_t;

struct ngx_radix_node_s {
    ngx_radix_node_t  *right;
    ngx_radix_node_t  *left;
    ngx_radix_node_t  *parent;
    uintptr_t          value;//瀛樺偍鐨勬槸鐢ㄦ埛瀹氫箟鐨勬暟鎹粨鏋?濡傛灉杩欎釜鑺傜偣杩樻病浣跨敤锛寁alue鐨勫€煎皢鏄疦GX_RADIX_NO_VALUE
};

//鍩烘暟鏍?typedef struct {
    ngx_radix_node_t  *root;//鏍硅妭鐐?    ngx_pool_t        *pool;//鍐呭瓨姹?璐熻矗缁欏熀鏁版爲鍒嗛厤鍐呭瓨
    ngx_radix_node_t  *free;//绠＄悊鍛樺凡缁忓垎閰嶄絾鏆傛椂鏈娇鐢?涓嶅啀鏍戜腑)鐨勮妭鐐?free瀹為檯涓婃槸鎵€鏈変笉鍦ㄦ爲涓妭鐐圭殑鍗曢摼琛?    char              *start;//宸插垎閰嶅唴瀛樹腑杩樻湭浣跨敤鍐呭瓨鐨勯鍦板潃
    size_t             size;//宸插垎閰嶅唴瀛樹腑杩樻湭浣跨敤鐨勫唴瀛樺ぇ灏?} ngx_radix_tree_t;


ngx_radix_tree_t *ngx_radix_tree_create(ngx_pool_t *pool,
    ngx_int_t preallocate);

ngx_int_t ngx_radix32tree_insert(ngx_radix_tree_t *tree,
    uint32_t key, uint32_t mask, uintptr_t value);
ngx_int_t ngx_radix32tree_delete(ngx_radix_tree_t *tree,
    uint32_t key, uint32_t mask);
uintptr_t ngx_radix32tree_find(ngx_radix_tree_t *tree, uint32_t key);

#if (NGX_HAVE_INET6)
ngx_int_t ngx_radix128tree_insert(ngx_radix_tree_t *tree,
    u_char *key, u_char *mask, uintptr_t value);
ngx_int_t ngx_radix128tree_delete(ngx_radix_tree_t *tree,
    u_char *key, u_char *mask);
uintptr_t ngx_radix128tree_find(ngx_radix_tree_t *tree, u_char *key);
#endif


#endif /* _NGX_RADIX_TREE_H_INCLUDED_ */
