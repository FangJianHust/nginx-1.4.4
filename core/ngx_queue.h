
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>


#ifndef _NGX_QUEUE_H_INCLUDED_
#define _NGX_QUEUE_H_INCLUDED_


typedef struct ngx_queue_s  ngx_queue_t;

/* 鍙屽悜閾捐〃鐨勬瘡涓€涓厓绱?鍏剁被鍨嬪彲浠ユ槸浠绘剰鐨剆truct缁撴瀯浣?浣嗚繖涓粨鏋勪綋蹇呴』瑕佹湁涓€涓猲gx_queue_t绫诲瀷鐨勬垚鍛?鍦ㄥ悜閾捐〃瀹瑰櫒涓坊鍔犮€佸垹闄ゅ厓绱犳椂閮芥槸浣跨敤缁撴瀯浣撲腑ngx_queue_t绫诲瀷鎴愬憳鐨勬寚閽?鍙互浣跨敤涓嬮潰鐨勫畯瀵硅缁撴瀯浣撹繘琛屾搷浣?*/
struct ngx_queue_s {
    ngx_queue_t  *prev;
    ngx_queue_t  *next;
};


#define ngx_queue_init(q)                                                     \
    (q)->prev = q;                                                            \
    (q)->next = q


#define ngx_queue_empty(h)                                                    \
    (h == (h)->prev)


#define ngx_queue_insert_head(h, x)                                           \
    (x)->next = (h)->next;                                                    \
    (x)->next->prev = x;                                                      \
    (x)->prev = h;                                                            \
    (h)->next = x


#define ngx_queue_insert_after   ngx_queue_insert_head


#define ngx_queue_insert_tail(h, x)                                           \
    (x)->prev = (h)->prev;                                                    \
    (x)->prev->next = x;                                                      \
    (x)->next = h;                                                            \
    (h)->prev = x


#define ngx_queue_head(h)                                                     \
    (h)->next


#define ngx_queue_last(h)                                                     \
    (h)->prev


#define ngx_queue_sentinel(h)                                                 \
    (h)


#define ngx_queue_next(q)                                                     \
    (q)->next


#define ngx_queue_prev(q)                                                     \
    (q)->prev


#if (NGX_DEBUG)

#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next;                                              \
    (x)->prev = NULL;                                                         \
    (x)->next = NULL

#else

#define ngx_queue_remove(x)                                                   \
    (x)->next->prev = (x)->prev;                                              \
    (x)->prev->next = (x)->next

#endif


#define ngx_queue_split(h, q, n)                                              \
    (n)->prev = (h)->prev;                                                    \
    (n)->prev->next = n;                                                      \
    (n)->next = q;                                                            \
    (h)->prev = (q)->prev;                                                    \
    (h)->prev->next = h;                                                      \
    (q)->prev = n;


#define ngx_queue_add(h, n)                                                   \
    (h)->prev->next = (n)->next;                                              \
    (n)->next->prev = (h)->prev;                                              \
    (h)->prev = (n)->prev;                                                    \
    (h)->prev->next = h;

/* q涓洪摼琛ㄤ腑鏌愪竴涓厓绱犵粨鏋勪綋鐨刵gx_queue_t鎴愬憳鐨勬寚閽堬紝type涓洪摼琛ㄥ厓绱犵殑缁撴瀯浣撶被鍨嬫垚鍛?璇ョ粨鏋勪綋蹇呴』鍖呭惈ngx_queue_t绫诲瀷鐨勬垚鍛?,link鏄笂闈㈣繖涓粨鏋勪綋涓璶gx_queue_t绫诲瀷鐨勬垚鍛樺悕瀛?*/
#define ngx_queue_data(q, type, link)                                         \
    (type *) ((u_char *) q - offsetof(type, link))//offsetof杩斿洖link鍦╰ype涓亸绉婚噺锛岄€氳繃ngx_queue_t绫诲瀷鐨勬寚閽堝噺鍘籰ink鐨勫亸绉婚噺锛屽氨寰楀埌浜嗙粨鏋勪綋type鐨勫湴鍧€


ngx_queue_t *ngx_queue_middle(ngx_queue_t *queue);
void ngx_queue_sort(ngx_queue_t *queue,
    ngx_int_t (*cmp)(const ngx_queue_t *, const ngx_queue_t *));


#endif /* _NGX_QUEUE_H_INCLUDED_ */
