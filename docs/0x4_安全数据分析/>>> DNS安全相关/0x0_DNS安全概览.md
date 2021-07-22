# DNS安全概览

对这块一直很感兴趣，但是拖延了确实很久，本篇开始系统学习一些DNS安全的皮毛。

## 大纲

借用Tr0y师傅系列文章[1]的大纲：

![img](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20201104095104408.png!blog)

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





### 其他概念

- 负载均衡

- 区域分布

- 业介入点

- DoT和DoH

- DDNS

- EDNS




## 针对DNS的攻击

### DNS域传送漏洞

### DNS欺骗

### DNS劫持

### DNS沉洞（Sinkhole）

### DNS缓存投毒



## 利用DNS进行攻击

### 隐蔽隧道

### Fast-flux

### Double-flux

### DGA

### DNS重绑定攻击

### DDoS方法




## References

\[1] DNS 安全（三）：利用 DNS 协议发起的攻与防，Tr0y，https://www.tr0y.wang/tags/DNS/
