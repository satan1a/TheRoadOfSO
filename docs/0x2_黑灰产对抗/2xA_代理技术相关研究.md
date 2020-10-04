# [Doing] 代理技术相关研究

计划研究时间：2天

## 0. 前言

代理技术本质上是关于**IP资源**的对抗。IP资源作为黑灰产基础设施之一， 也是企业进行安全防护的一个重要切入点。本篇从研究代理技术出发，计划依次整理以下几个部分：

-   代理技术
-   黑灰产常用解决方案
-   对抗手段
    -   风控相关
    -   安全攻防相关
-   体系建设思路
    -   现有思路整理
    -   发现思路
    -   分类思路
    -   情报体系
    -   指标计算体系
-   展望

## 1. 代理技术

### 1.1 按匿名程度区分

以下是按代理技术的匿名程度作分类，这里我们回顾一下HTTP请求头中的三个参数：

-   REMOTE_ADDR
    -   客户端跟服务器“握手”时候的IP，即访问客户端的 IP 地址
-   HTTP_VIA
    -   如果存在该信息, 则表明访问端主动承认其为代理服务器，数值即为代理服务器的IP
-   HTTP_X_FORWARDED_FOR
    -   HTTP扩展头部，表明代理端的IP，可能存在，可伪造[1]

#### 透明代理

透明代理，Transparent Proxies。

简单讲，就是被访问端能识别其为代理服务，且能识别真实IP。

>   EMOTE_ADDR = ProxyIP，HTTP_VIA = ProxyIP，HTTP_X_FORWARDED_FOR = YourIP

#### 普匿代理

普通匿名代理，Anonymous Proxies。

简单讲，就是被访问端识别其使用了代理服务，但隐藏了真实IP。

>   REMOTE_ADDR = ProxyIP，HTTP_VIA = ProxyIP，HTTP_X_FORWARDED_FOR = ProxyIP

#### 高匿代理

高级匿名代理，High Anonymity Proxies (Elite proxies)。

简单讲，就是被访问端不知道访问端使用了代理服务，也不知道其真实IP。

>   REMOTE_ADDR = ProxyIP，HTTP_VIA = NULL，HTTP_X_FORWARDED_FOR = NULL

#### 欺骗性代理

欺骗性代理，Distorting Proxies。

简单讲，就是告知被访问端使用了代理服务，但使用虚拟的随机IP代替真实IP，从而达到欺骗的效果。

>   REMOTE_ADDR = ProxyIP，HTTP_VIA = ProxyIP，HTTP_X_FORWARDED_FOR = RandomIP





## References

\[1] 如何取得wap和web用户的真实IP，[Albert陈凯](https://cloud.tencent.com/developer/user/1558124)，https://cloud.tencent.com/developer/article/1350545