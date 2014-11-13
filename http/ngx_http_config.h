#ifndef _NGX_HTTP_CONFIG_H_INCLUDED_
#define _NGX_HTTP_CONFIG_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* HTTP模块存储所有配置项结构体的结构体*/
typedef struct 
{
	//指针数组，数组中的每个元素指向所有HTTP模块create_main_conf方法产生的全局配置项结构体，它们存放着解析直属http{}块内的main级别的配置项参数
    void        **main_conf;

	/*指针数组，数组中的每个元素指向所有HTTP模块create_srv_conf方法产生的与server相关的结构体
	，它们或存放main级别配置项，或存放srv级别配置项，这与当前的ngx_http_conf_ctx_t是在解析http{}
	或者server{}块时创建的有关*/
    void        **srv_conf;

	//指针数组，数组中的每个元素指向所有HTTP模块create_loc_conf方法产生的与location相关的结构体，它们可能存放着main、srv、loc级别的配置项，这与当前啊的ngx_http_conf_ctx_t是在解析http{}、server{}或者location{}块时创建的有关
    void        **loc_conf;

} ngx_http_conf_ctx_t;

/* HTTP框架在读取、重载配置文件时定义了由ngx_http_module_t接口描述的8个阶段，HTTP框架在启动过程中会在每个阶段中调用
   ngx_http_module_t中的相应方法,不过这8个阶段的调用顺序与定义的顺序是不同的,在Nginx启动过程中，HTTP框架调用这些回
   调方法的实际顺序和nginx.conf配置项有关 */
typedef struct
 {	
 	//解析http{……}内的配置项前调用
    ngx_int_t   (*preconfiguration)(ngx_conf_t *cf);

	//完成http{……}解析后调用
	ngx_int_t   (*postconfiguration)(ngx_conf_t *cf);

	/* 当需要创建数据结构用于存储main级别(直属于http{...}块的配置项)的全局配置项时，可以通过
	create_main_conf回调方法创建存储全局配置项的结构体 */
    void       *(*create_main_conf)(ngx_conf_t *cf);

	//解析完main配置项后调用，常用于初始化main级别配置项
	char       *(*init_main_conf)(ngx_conf_t *cf, void *conf);

	/*当需要创建数据结构用于存储main、srv级别(直属于虚拟机server{...}块的配置项)的配置项时，
	可以通过create_srv_conf回调方法创建存储全局配置项的结构体 */
    void       *(*create_srv_conf)(ngx_conf_t *cf);

	//合并main级别和srv级别下的同名配置项
	char       *(*merge_srv_conf)(ngx_conf_t *cf, void *prev, void *conf);

	/*当需要创建数据结构用于存储loc级别(直属于location{...}块的配置项)的配置项时，可以通过
	create_loc_conf回调方法创建存储全局配置项的结构体 */
    void       *(*create_loc_conf)(ngx_conf_t *cf);

	//用于合并srv级别和loc级别下的同名配置项
	char       *(*merge_loc_conf)(ngx_conf_t *cf, void *prev, void *conf);
} ngx_http_module_t;


#define NGX_HTTP_MODULE           0x50545448   /* "HTTP" */

#define NGX_HTTP_MAIN_CONF        0x02000000
#define NGX_HTTP_SRV_CONF         0x04000000
#define NGX_HTTP_LOC_CONF         0x08000000
#define NGX_HTTP_UPS_CONF         0x10000000
#define NGX_HTTP_SIF_CONF         0x20000000
#define NGX_HTTP_LIF_CONF         0x40000000
#define NGX_HTTP_LMT_CONF         0x80000000


#define NGX_HTTP_MAIN_CONF_OFFSET  offsetof(ngx_http_conf_ctx_t, main_conf)
#define NGX_HTTP_SRV_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, srv_conf)
#define NGX_HTTP_LOC_CONF_OFFSET   offsetof(ngx_http_conf_ctx_t, loc_conf)

//由ngx_cycle_t核心结构体中找到main级别的配置结构体
#define ngx_http_get_module_main_conf(r, module)                             \
    (r)->main_conf[module.ctx_index]
#define ngx_http_get_module_srv_conf(r, module)  (r)->srv_conf[module.ctx_index]
#define ngx_http_get_module_loc_conf(r, module)  (r)->loc_conf[module.ctx_index]


#define ngx_http_conf_get_module_main_conf(cf, module)                        \
    ((ngx_http_conf_ctx_t *) cf->ctx)->main_conf[module.ctx_index]
#define ngx_http_conf_get_module_srv_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->srv_conf[module.ctx_index]
#define ngx_http_conf_get_module_loc_conf(cf, module)                         \
    ((ngx_http_conf_ctx_t *) cf->ctx)->loc_conf[module.ctx_index]

#define ngx_http_cycle_get_module_main_conf(cycle, module)                    \
    (cycle->conf_ctx[ngx_http_module.index] ?                                 \
        ((ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index])      \
            ->main_conf[module.ctx_index]:                                    \
        NULL)


#endif /* _NGX_HTTP_CONFIG_H_INCLUDED_ */
