# 安全系统整理

本篇整理一些安全相关的软硬件系统。

## IDS

IDS（Intrusion detection system），入侵检测设备

### 应用场景

工作在网络层，旁路部署，通过抓取和分析网络流量来发现攻击[1]



## IPS

IPS（Intrusion Prevention System），入侵预防系统；

### 应用场景

一般在网络层旁路，可以理解为**具备阻断能力的IDS**，是IDS的升级版（也有IDS检测到攻击通知阻断设备执行阻断动作的设备联动模式），可以覆盖网络层和应用层[1]

常见的场景是封禁网站（如非法网站的封禁）、篡改网页内容（运营商插广告）、阻断端口扫描和漏洞攻击（IPS），实施链路劫持的人必须控制某段网络。[1]

### 原理概述

在网络层旁路部署，例如使用端口镜像。使用链路劫持的方式，抓取网络上的流量进行分析，发现符合**规则**的流量则**冒充**服务端回报响应客户端实现欺骗的效果，从而进行阻断和替换。




## WAF

WAF（Web Application Firewall），网站应用防火墙、网站应用级入侵防御系统；

### 应用场景

WAF是在应用层防护Web攻击的程序，一般是跟Web接入层对接，可旁路可串行，仅能覆盖应用层[1]



## EDR 

Endpoint Detection and Response, 端点检测与响应，通过在主机端上部署agent，然后由agent采集数据，对大量数据进行分类、进行处理，然后对事件进行分析、分析、响应。



## NAT

Network Traffic Analysis，常指网络流量分析产品，它将网络通信流量作为基础数据源，输出威胁事件，与IDS的不同是其模型检测为核心，IDS以特征检测为核心[1]



## 堡垒机/跳板机（Jump Server）

跳板机，国内也称堡垒机，也叫做运维安全审计系统，“核心功能是4A”[2]：

-   身份验证 Authentication

-   账号管理 Account

-   授权控制 Authorization

-   安全审计 Audit

"简单总结一句话：堡垒机是用来控制哪些人可以登录哪些资产（事先防范和事中控制），以及录像记录登录资产后做了什么事情（事后溯源）。"[2] 比较出名的是开源堡垒机软件：[jumpserver](https://github.com/jumpserver/jumpserver)



## SOAR

SOAR(Security Orchestration, Automation, and Response)，是指一组软件解决方案和工具，最初是由Gartner定义，旨在在三个关键领域进行安全运营工作的简化：威胁和漏洞管理、事件响应（Response）和安全运营自动化（Automation）。SOAR允许公司从各个来源收集与威胁相关的数据，并进行自动响应。





## References

[1] 网络层绕过IDS/IPS的一些探索, lake2（腾讯安全应急响应中心），https://mp.weixin.qq.com/s/QJeW7K-KThYHggWtJ-Fh3w

\[2] 堡垒机是干什么的？(知乎提问的回答)，maninhill，https://www.zhihu.com/question/21036511/answer/918763192

