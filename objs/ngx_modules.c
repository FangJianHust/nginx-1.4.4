
#include <ngx_config.h>
#include <ngx_core.h>



extern ngx_module_t  ngx_core_module;
extern ngx_module_t  ngx_errlog_module;
extern ngx_module_t  ngx_conf_module;
extern ngx_module_t  ngx_events_module;
extern ngx_module_t  ngx_event_core_module;
extern ngx_module_t  ngx_epoll_module;
extern ngx_module_t  ngx_regex_module;
extern ngx_module_t  ngx_http_module;
extern ngx_module_t  ngx_http_core_module;
extern ngx_module_t  ngx_http_log_module;
extern ngx_module_t  ngx_http_upstream_module;
extern ngx_module_t  ngx_http_static_module;
extern ngx_module_t  ngx_http_autoindex_module;
extern ngx_module_t  ngx_http_index_module;
extern ngx_module_t  ngx_http_auth_basic_module;
extern ngx_module_t  ngx_http_access_module;
extern ngx_module_t  ngx_http_limit_conn_module;
extern ngx_module_t  ngx_http_limit_req_module;
extern ngx_module_t  ngx_http_geo_module;
extern ngx_module_t  ngx_http_map_module;
extern ngx_module_t  ngx_http_split_clients_module;
extern ngx_module_t  ngx_http_referer_module;
extern ngx_module_t  ngx_http_rewrite_module;
extern ngx_module_t  ngx_http_proxy_module;
extern ngx_module_t  ngx_http_fastcgi_module;
extern ngx_module_t  ngx_http_uwsgi_module;
extern ngx_module_t  ngx_http_scgi_module;
extern ngx_module_t  ngx_http_memcached_module;
extern ngx_module_t  ngx_http_empty_gif_module;
extern ngx_module_t  ngx_http_browser_module;
extern ngx_module_t  ngx_http_upstream_ip_hash_module;
extern ngx_module_t  ngx_http_upstream_least_conn_module;
extern ngx_module_t  ngx_http_upstream_keepalive_module;
extern ngx_module_t  ngx_http_write_filter_module;
extern ngx_module_t  ngx_http_header_filter_module;
extern ngx_module_t  ngx_http_chunked_filter_module;
extern ngx_module_t  ngx_http_range_header_filter_module;
extern ngx_module_t  ngx_http_gzip_filter_module;
extern ngx_module_t  ngx_http_postpone_filter_module;
extern ngx_module_t  ngx_http_ssi_filter_module;
extern ngx_module_t  ngx_http_charset_filter_module;
extern ngx_module_t  ngx_http_userid_filter_module;
extern ngx_module_t  ngx_http_headers_filter_module;
extern ngx_module_t  ngx_http_copy_filter_module;
extern ngx_module_t  ngx_http_range_body_filter_module;
extern ngx_module_t  ngx_http_not_modified_filter_module;

//默认安装的模块
ngx_module_t *ngx_modules[] = {
	/* 全局core模块 */
    &ngx_core_module,
    &ngx_errlog_module,
    &ngx_conf_module,

    /* event模块 */
    &ngx_events_module,
    &ngx_event_core_module,
    &ngx_epoll_module,

    /* 正则模块 */
    &ngx_regex_module,

	/* http模块 */
    &ngx_http_module,
    &ngx_http_core_module,
    &ngx_http_log_module,
    &ngx_http_upstream_module,/*简单的说，ngx_http_upstream_module模块用来定义一个服务器群，而 proxy_pass、fastcgi_pass
    							以及memcached_pass 模块则引用上面定义的服务器群来实现相应的功能*/
    
    /* http handler模块 */
   	&ngx_http_static_module,/* 从某种程度上来说，此模块可以算的上是“最正宗的”，“最古老”的content handler。因为本模块的作用就是读取
   								磁盘上的静态文件，并把文件内容作为产生的输出 */
   	&ngx_http_autoindex_module,/*列出目录中的文件。 一般当ngx_http_index_module模块找不到默认主页的时候，会把请求转给
   								ngx_http_autoindex_module模块去处理*/
    &ngx_http_index_module,//定义将要被作为默认页的文件
    &ngx_http_auth_basic_module,//提供最简单的用户名/密码认证
    &ngx_http_access_module,/*允许(限制)某些IP地址的客户端访问。该模块的作用是提供对于特定host的客户端的访问控制。可以限定特定host
    						的客户端对于服务端全部，或者某个server，或者是某个location的访问。*/
    &ngx_http_limit_conn_module,
    &ngx_http_limit_req_module,/*该模块针对IP地址限制并发请求数 */
    &ngx_http_geo_module,/*这个模块可以定义一些变量，这些变量的值将与客户端IP地址关联，这样nginx针对不同的地区的客户端(根据IP地址判断)
    						返回不一样的结果，例如不同地区显示不同语言的网页*/
    &ngx_http_map_module,/*这个模块可以建立一个key/value映射表，不同的key得到相应的value，这样可以针对不同的URL做特殊处理。例如:
    						返回302重定向时，可以期望URL不同时返回的Location字段也不同*/
    &ngx_http_split_clients_module,/*根据客户端的信息，例如IP地址、header头、cookie等来区分处理*/
    &ngx_http_referer_module, /*提供HTTP请求在nginx服务器内部的重定向功能，依赖PCRE库*/
    &ngx_http_rewrite_module,
    &ngx_http_proxy_module, /*提供基本的HTTP反向代理功能*/
    &ngx_http_fastcgi_module,/*提供FastCGI功能*/
    &ngx_http_uwsgi_module,
    &ngx_http_scgi_module,/*提供SCGI功能*/
    &ngx_http_memcached_module,/*该模块可以使得nginx直接由上游的memcached服务器读取数据，并简单地适配成HTTP响应返回给客户端*/
    &ngx_http_empty_gif_module,/*该模块可以使得nginx在收到无效请求时，立刻返回内存中的1*1像素的GIF图片。这种好处在于，对于明显的
    							无效请求不会去试图浪费服务器资源*/
    &ngx_http_browser_module,/*该模块会根据HTTP请求中的user-agent字段(该字段通常由浏览器填写)来识别浏览器*/
    &ngx_http_upstream_ip_hash_module,/*该模块提供当nginx与后端server建立连接时，会根据IP地址做散列运算决定与后端哪台server通信，这样可以实现负载均衡*/
    &ngx_http_upstream_least_conn_module,
    &ngx_http_upstream_keepalive_module,
    
    
    /* http filter模块 */
    &ngx_http_write_filter_module,
    &ngx_http_header_filter_module,
    &ngx_http_chunked_filter_module,
    &ngx_http_range_header_filter_module,/* 范围请求的头部过滤模块 */
    &ngx_http_gzip_filter_module,/*在服务器发出的HTTP响应包中，这个模块可以按照配置文件制定的conntent-type对特定大小的HTTP响应包体执行gzip压缩*/
    &ngx_http_postpone_filter_module,
    &ngx_http_ssi_filter_module,//该模块可以在向用户返回的HTTP响应包体中加入特定的内容，如HTML文件中固定的页头和页尾
    &ngx_http_charset_filter_module,//这个模块可以将服务器发出的HTTP响应重编码
    &ngx_http_userid_filter_module,//这个模块可以通过HTTP请求头部信息里的一些字段认证用户信息，以确定请求是否合法
    &ngx_http_headers_filter_module,
    
    /* 第三方filter模块 */
    &ngx_http_copy_filter_module,
    &ngx_http_range_body_filter_module,/* 范围请求的包体过滤模块 */
    &ngx_http_not_modified_filter_module,//头过滤链上的第一个过滤模块，处理if-Modified-since和if-unmodified-since首部
    NULL
};

