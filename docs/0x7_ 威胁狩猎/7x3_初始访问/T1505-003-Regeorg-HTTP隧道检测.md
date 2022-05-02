# T1505-003-Regeorg-HTTP隧道检测

## 来自ATT&CK的描述

攻击者可能会通过Web Shell为web服务器创建后门，以便实现对系统的持久访问。Web Shell是攻击者放置在可公开访问的web服务器上的web脚本，以便通过web服务器进入网络。Web Shell可以提供一套待执行的函数，或是为web服务器所在系统提供命令行界面。

除服务器端脚本之外，Web Shell可能还有客户端接口程序，用于与web服务器通信，例如：[China Chopper](https://attack.mitre.org/software/S0020)（引自：Lee 2013）

## ReGeorg简介

reGeorg是reDuh的继承者，利用了会话层的socks5协议，效率更高结合Proxifier使用；Proxifier是一款功能非常强大的socks5客户端，可以让不支持通过代理服务器工作的网络程序能通过HTTPS或SOCKS代理或代理链。

## 测试案例

reGeorg搭建HTTP隧道和流量分析

<https://cloud.tencent.com/developer/article/1779195>

## 检测日志

HTTP_log

## 测试复现

参考测试案例文章链接

## 测试留痕

kali

在kali上抓包，然后访问内网，tcpdump抓包，分析流量

tcpdump -ieth0 -wkali.pcap
然后打开wireshark追踪tcp流，看流量

```yml
...............P.........PGET /login.php HTTP/1.1
Host: 172.17.0.2
User-Agent: curl/7.68.0
Accept: */*
HTTP/1.1 200 OK
Date: Thu, 17 Dec 2020 16:39:09 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.25
Set-Cookie: PHPSESSID=7mhcg05sbeerpgjvthqad6r7t6; path=/
Expires: Tue, 23 Jun 2009 12:00:00 GMT
Cache-Control: no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: PHPSESSID=7mhcg05sbeerpgjvthqad6r7t6; path=/; httponly
Set-Cookie: security=impossible; httponly
Vary: Accept-Encoding
Content-Length: 1567
Content-Type: text/html;charset=utf-8
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
```

serverA

在serverA上抓包第一个流可以看到服务器A作为跳板，表明服务器与哪台内网主机的哪个端口连接cmd=connecttarget=172.17.0.2 目标内网ipport=80 端口为80

```yml
POST http://182.x.x.x:8080/tunnel.jsp?
cmd=connect&target=172.17.0.2&port=80 HTTP/1.1
Host: 182.x.x.x:8080
Accept-Encoding: identity
Content-Length: 0
X-CMD: CONNECT
X-PORT: 80
X-TARGET: 172.17.0.2
User-Agent: python-urllib3/1.26.2
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
Set-Cookie: JSESSIONID=C71AAD9AFD48C0E4796514EF6835F2B4; Path=/; HttpOnly
X-STATUS: OK
Content-Type: text/html
Content-Length: 0
Date: Thu, 17 Dec 2020 16:44:45 GMT
```

下一条流cmd=read,代表是去访问内网的内容

Accept-Encoding: identity请求的HTTP头通告其内容编码，只要没有被明确禁止

服务器就不能发回406 Not Acceptable错误

响应包头：Transfer-Encoding: chunked代表是分块传输

```yml
POST /tunnel.jsp?cmd=read HTTP/1.1
Host: 182.x.x.x:8080
Accept-Encoding: identity
Content-Length: 0
X-CMD: READ
Cookie: JSESSIONID=C71AAD9AFD48C0E4796514EF6835F2B4; Path=/; HttpOnly
Connection: Keep-Alive
User-Agent: python-urllib3/1.26.2
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
X-STATUS: OK
Content-Type: text/html
Transfer-Encoding: chunked
Date: Thu, 17 Dec 2020 16:44:45 GMT
```

接下来这条流就是cmd=forward，转发到内网

```yml
POST /tunnel.jsp?cmd=forward HTTP/1.1
Host: 182.92.73.106:8080
Accept-Encoding: identity
Content-Length: 83
Content-Type: application/octet-stream
X-CMD: FORWARD
Cookie: JSESSIONID=C71AAD9AFD48C0E4796514EF6835F2B4; Path=/; HttpOnly
Connection: Keep-Alive
User-Agent: python-urllib3/1.26.2
GET /login.php HTTP/1.1
Host: 172.17.0.2
User-Agent: curl/7.68.0
Accept: */*
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
X-STATUS: OK
Content-Type: text/html
Content-Length: 0
Date: Thu, 17 Dec 2020 16:44:45 GMT
```

最后就是cmd=disconnect关闭连接

```yml
POST /tunnel.jsp?cmd=disconnect HTTP/1.1
Host: 182.x.x.x:8080
Accept-Encoding: identity
X-CMD: DISCONNECT
Cookie: JSESSIONID=C71AAD9AFD48C0E4796514EF6835F2B4; Path=/; HttpOnly
User-Agent: python-urllib3/1.26.2
HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
X-STATUS: OK
Content-Type: text/html
Content-Length: 0
Date: Thu, 17 Dec 2020 16:44:45 GMT
```

内网服务器

在内网服务器上抓包,看到服务器A向内网请求了login.php

```yml
GET /login.php HTTP/1.1
Host: 172.17.0.2
User-Agent: curl/7.68.0
Accept: */*
HTTP/1.1 200 OK
Date: Thu, 17 Dec 2020 16:53:17 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.25
Set-Cookie: PHPSESSID=65ehap87lgj2sk84poopt0aep3; path=/
Expires: Tue, 23 Jun 2009 12:00:00 GMT
Cache-Control: no-cache, must-revalidate
Pragma: no-cache
Set-Cookie: PHPSESSID=65ehap87lgj2sk84poopt0aep3; path=/; httponly
Set-Cookie: security=impossible; httponly
Vary: Accept-Encoding
Content-Length: 1567
Content-Type: text/html;charset=utf-8
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
```

以上内容摘自<https://cloud.tencent.com/developer/article/1779195>

## 检测规则/思路

### sigma规则

```yml
title: Webshell ReGeorg HTTP隧道检测
status: 测试状态
description: 通过请求路径内的内容进行检测，基于url参数检测
references:
    - https://cloud.tencent.com/developer/article/1779195
    - https://github.com/sensepost/reGeorg
logsource:
    category: webserver
detection:
    selection:
        uri_query|contains: #url中包含此类特征
            - '*cmd=read*'
            - '*connect&target*'
            - '*cmd=connect*'
            - '*cmd=disconnect*'
            - '*cmd=forward*'
    filter:
        referer: null
        useragent: null
        method: POST
    condition: selection and filter
fields:
    - uri_query
    - referer
    - method
    - useragent
falsepositives:
    - web applications that use the same URL parameters as ReGeorg
level: high
tags:
    - attack.persistence
    - attack.t1100
    - attack.t1505.003
```

## 建议

多数安全设备已支持检测此类隧道行为。

## 相关TIP
[[T1505-003-web服务产生的可疑进程]]
[[T1505-003-windows下webshell检测]]
[[T1566-001-win-可疑的MS Office子进程]]

## 参考推荐

MITRE-ATT&CK-T1505-003

<https://attack.mitre.org/techniques/T1505/003/>

reGeorg搭建HTTP隧道和流量分析

<https://cloud.tencent.com/developer/article/1779195>