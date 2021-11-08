# DNS安全概览

对这块一直很感兴趣，但是拖延了确实很久，本篇开始系统学习一些DNS安全的皮毛。

## 大纲

借用Tr0y师傅系列文章[1]的大纲：

<img src="https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20201104095104408.png!blog" alt="img" style="zoom: 33%;" />

图：DNS安全大纲



## DNS基础

### DNS服务器类型

-   Local DNS server（本地DNS服务器）
    -   路由器的，机子本地的
-   Root DNS server（DNS根服务器）
    -   全球的，分布式，总共13个（集群）
-   TLD DNS server / Top-level DNS server（DNS顶级域名服务器）
    -   熟知的.com、.org等。又会分为一般通用顶级域（e.g. `.com`,）、国家顶级域（e.g. `.cn`）和特殊域（e.g. `arpa`）
-   Autoritative DNS server（DNS权威服务器）
    -   实际持有并负责DNS资源记录的服务器，大公司会自建，商业DNS服务器也大多为这一类

### DNS解析流程

#### 查询的方法

-   递归查询
    -   你问A，A问B，B问C......直到有答案，再相反顺利传话直到传达到你
-   迭代查询
    -   你问A，A让你问B，B让你问C......知道你问到答案为止

DNS解析会组合以上的两种查询方法进行。从你的设备开始，刚开始递归，后面开始迭代，具体顺序参考下面

#### 查询的顺序

-   Device ==Domian?==> Host file / Local DNS
    -   if Host file cached this domain's record ==domian:ip==> Device

-   Local DNS server ====> Root DNS server
    -   if Local DNS server cached TLD DNS server's record ====> TLD DNS server
-   Root DNS server ==TLD DNS server==>  Local DNS server
    -   If Local DNS server cached Authoritative DNS server's record ====> Auhoritative DNS server
-   Local DNS server ====> TLD DNS server
-   TLD DNS server ==Authoritative DNS server==> Local DNS server
-   Local DNS server ====> Authoritative DNS server
-   Authoritative DNS server ==domain : ip==> Local DNS server
-   Local DNS server ==domain:ip==> Device 



### DNS缓存机制

DNS的缓存分布：

![img](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200930044333857.png!blog)

图：DNS缓存分布图[1	]



### DNS解析类型

-   A
-   CNAME
-   MX
-   TXT
-   NS
-   AAAA
-   SOA
-   PTR
-   AXFR、IXFR



### DNS报文机构

```text
DNS报文：|QID|问题区|应答区|权威区|附加区|
```

// TODO 待补充，参考：https://zhuanlan.zhihu.com/p/92899876



### 其他概念

- 负载均衡

- 区域分布

- 业介入点

- DoT和DoH

- DDNS

- EDNS



## 针对DNS的攻击

### DNS放大攻击

以CVE-2020-8616为例，DNS方法攻击是指：

>   当DNS递归服务器在处理DNS请求时会向权威服务器请求解析结果，权威服务器可能会进行子域名委派，而BIND的原始设计并未充分限制处理委派响应的查询次数。恶意攻击者可以利用漏洞给DNS递归服务器回复一个巨大的委派列表，达到降低DNS递归服务器的性能，造成DNS放大攻击的目的。
>
>   https://www.huaweicloud.com/notice/20200520174720491.html

具体来说，是DNS需要执行递归查询，而递归的实现需要DNS服务能处理引荐报文（Referrals），类似于介绍信，例如权威服务器A处理不了这个DNS查询，它就会开出一封推荐信，自己派人去查下一个权威服务器B去问他，如果B也不知道，B会再开一封去问下一个权威服务器。

但是有一个设计上的疏漏，就是没有限制好这个“推荐信”的查询数量。这样的话，攻击者可以构造一大堆“推荐信”，让权威服务器A一次性去查很多家，这样的话，A的性能就受到影响了。而且因为查询是递归的，所以1查10，10查100，这个权威服务器A就被拿来当放大镜来发起放大攻击攻击了。



### DNS劫持

这种攻击类型不是官方的定义，用来这里是来描述发起DNS查询的客户端所遭受攻击的情况。注意与DNS服务器本身遭受攻击的区别。

其中一种是大规模的宽带路由器DNS篡改行为，简单来说是利用路由器的软件缺陷，比如对DNS可信列表的绕过，对服务器提供DNS修改接口的CSRF攻击等，修改路由器配置的DNS域名服务器，从而使得上网用户的请求被劫持解析，返回错误的落地页。

还有一种情况是在流量层面的劫持。DNS响应的特点是先到先接收，设计之初是为了最好的查询速度，但是攻击者如果在通信流量上做了手脚，在正确的DNS服务器和客户端之间插入一个恶意的“节点”，使得恶意的“节点”更快响应客户端的DNS查询请求，那么先到的恶意DNS响应就会使得后到的正确DNS响应失效，从而给客户端带来错误的DNS解析。



### DNS缓存投毒

DNS缓存投毒也包括多种手法，一种就上述提到的，直接对客户端进行DNS劫持，因为DNS协议具有缓存特性，因此恶意的DNS解析也会缓存一段时间，直到TTL超时、缓存失效。

这个思路之下，最有名的、影响范围最大的莫过于2008年Dan Kaminsky提出的DNS缓存投毒攻击。// TODO 具体分析待补充，参考：https://zhuanlan.zhihu.com/p/92899876



### DNS域传送漏洞

### DNS欺骗

### DNS沉洞（Sinkhole）



## 利用DNS进行攻击

### 隐蔽隧道

### Fast-flux

### Double-flux

### DGA

### DNS重绑定攻击

### DDoS方法




## References

\[1] DNS 安全（三）：利用 DNS 协议发起的攻与防，Tr0y，https://www.tr0y.wang/tags/DNS/
