# T1190-JumpServer v2.6.1 RCE攻击检测

## 来自ATT&CK的描述

使用软件，数据或命令来利用面向Internet的计算机系统或程序中的弱点，从而导致意外或无法预期的行为。系统的弱点可能是错误、故障或设计漏洞。这些应用程序通常是网站，但是可以包括数据库（例如SQL），标准服务（例如SMB 或SSH）以及具有Internet可访问开放的任何其他应用程序，例如Web服务器和相关服务。根据所利用的缺陷，这可能包括“利用防御防卫”。

如果应用程序托管在基于云的基础架构上，则对其进行利用可能会导致基础实际应用受到损害。这可以使攻击者获得访问云API或利用弱身份和访问管理策略的路径。

对于网站和数据库，OWASP排名前10位和CWE排名前25位突出了最常见的基于Web的漏洞。

## JumpServer v2.6.1 RCE(远程代码执行)

JumpServer 是一款开源的堡垒机，是符合4A规范的运维安全审计系统，通俗来说就是跳板机.

2021年1月15日，JumpServer 发布安全更新，修复了一处远程命令执行漏洞。由于 JumpServer某些接口未做授权限制，攻击者可构造恶意请求获取敏感信息，或者执行相关操作控制其中所有机器，执行任意命令。

### 影响版本

JumpServer < v2.6.2

JumpServer < v2.5.4

JumpServer < v2.4.5

JumpServer = v1.5.9

### 测试案例

请参考：

JumpServer v2.6.1 RCE(远程代码执行) 复现总结

<https://www.cnblogs.com/w0x68y/p/14340249.html>

Jumpserver-RCE复现及告警规则

<https://www.freebuf.com/vuls/261199.html>

### 检测日志

访问日志

### 测试复现

请参考：

JumpServer v2.6.1 RCE(远程代码执行) 复现总结

<https://www.cnblogs.com/w0x68y/p/14340249.html>

### 测试留痕

暂无

### 检测规则/思路

modsecurity判定规则

在这种场景下，基本上看到这个uri请求我们就可以断言这是一个报警，因此编写规则如下:

SecRule REQUEST_URI "/ws/ops/tasks/log" "id:11111111,phase:1,id:52,t:none,t:urlDecode,t:lowercase,t:normalizePath,msg:'jump-rce'"

## 备注

本文内容多数摘自互联网网络，未经过本人实际环境测试，慎重上线使用。

ModSecurity是一个开源的跨平台Web应用程序防火墙（WAF）引擎，用于Apache，IIS和Nginx，由Trustwave的SpiderLabs开发。作为WAF产品，ModSecurity专门关注HTTP流量，当发出HTTP请求时，ModSecurity检查请求的所有部分，如果请求是恶意的，它会被阻止和记录。

## 参考推荐

MITRE-ATT&CK-T1190

<https://attack.mitre.org/techniques/T1190/>

JumpServer v2.6.1 RCE(远程代码执行) 复现总结

<https://www.cnblogs.com/w0x68y/p/14340249.html>

Jumpserver-RCE复现及告警规则

<https://www.freebuf.com/vuls/261199.html>