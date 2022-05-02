# T1190- Apache Log4j2漏洞利用检测

## 来自ATT&CK的描述

使用软件，数据或命令来利用面向Internet的计算机系统或程序中的弱点，从而导致意外或无法预期的行为。系统的弱点可能是错误、故障或设计漏洞。这些应用程序通常是网站，但是可以包括数据库（例如SQL），标准服务（例如SMB 或SSH）以及具有Internet可访问开放的任何其他应用程序，例如Web服务器和相关服务。根据所利用的缺陷，这可能包括“利用防御防卫”。

如果应用程序托管在基于云的基础架构上，则对其进行利用可能会导致基础实际应用受到损害。这可以使攻击者获得访问云API或利用弱身份和访问管理策略的路径。

对于网站和数据库，OWASP排名前10位和CWE排名前25位突出了最常见的基于Web的漏洞。

##  Apache Log4j2漏洞

2021年12月，Apache开源组件Log4j（Apache Log4j2是一款优秀的Java日志框架。）被发现两个相关漏洞，分别为任意代码执行漏洞和拒绝服务攻击漏洞，攻击者可以通过构造特殊的请求进行任意代码执行，以达到控制服务器的目的，或者通过构造特殊的请求进行DoS攻击，以达到影响服务器正常运行的目的，影响面十分广泛。

影响范围：Apache Log4j 2.x < 2.15.0-rc2

## 测试案例

网络上已经公开的利用方法比较多，这里不再添加相关案例信息，可自行查找。

## 检测日志

HTTP流量

## 测试复现

无

## 测试留痕

HTTP流量检测规则基于payload关键词进行检测

## 检测规则/思路

### Splunk检测规则

```yml
((cs-User-Agent="*$${jndi:ldap:/*" OR cs-User-Agent="*$${jndi:rmi:/*" OR cs-User-Agent="*$${jndi:ldaps:/*" OR cs-User-Agent="*$${jndi:dns:/*" OR cs-User-Agent="*/$$%7bjndi:*" OR cs-User-Agent="*%24%7bjndi:*" OR cs-User-Agent="*$$%7Bjndi:*" OR cs-User-Agent="*%2524%257Bjndi*" OR cs-User-Agent="*%2F%252524%25257Bjndi%3A*" OR cs-User-Agent="*$${jndi:$${lower:*" OR cs-User-Agent="*$${::-j}$${*" OR cs-User-Agent="*$${jndi:nis*" OR cs-User-Agent="*$${jndi:nds*" OR cs-User-Agent="*$${jndi:corba*" OR cs-User-Agent="*$${jndi:iiop*" OR cs-User-Agent="*$${$${env:BARFOO:-j}*" OR cs-User-Agent="*$${::-l}$${::-d}$${::-a}$${::-p}*" OR cs-User-Agent="*$${base64:JHtqbmRp*") (user-agent="*$${jndi:ldap:/*" OR user-agent="*$${jndi:rmi:/*" OR user-agent="*$${jndi:ldaps:/*" OR user-agent="*$${jndi:dns:/*" OR user-agent="*/$$%7bjndi:*" OR user-agent="*%24%7bjndi:*" OR user-agent="*$$%7Bjndi:*" OR user-agent="*%2524%257Bjndi*" OR user-agent="*%2F%252524%25257Bjndi%3A*" OR user-agent="*$${jndi:$${lower:*" OR user-agent="*$${::-j}$${*" OR user-agent="*$${jndi:nis*" OR user-agent="*$${jndi:nds*" OR user-agent="*$${jndi:corba*" OR user-agent="*$${jndi:iiop*" OR user-agent="*$${$${env:BARFOO:-j}*" OR user-agent="*$${::-l}$${::-d}$${::-a}$${::-p}*" OR user-agent="*$${base64:JHtqbmRp*") (cs-uri="*$${jndi:ldap:/*" OR cs-uri="*$${jndi:rmi:/*" OR cs-uri="*$${jndi:ldaps:/*" OR cs-uri="*$${jndi:dns:/*" OR cs-uri="*/$$%7bjndi:*" OR cs-uri="*%24%7bjndi:*" OR cs-uri="*$$%7Bjndi:*" OR cs-uri="*%2524%257Bjndi*" OR cs-uri="*%2F%252524%25257Bjndi%3A*" OR cs-uri="*$${jndi:$${lower:*" OR cs-uri="*$${::-j}$${*" OR cs-uri="*$${jndi:nis*" OR cs-uri="*$${jndi:nds*" OR cs-uri="*$${jndi:corba*" OR cs-uri="*$${jndi:iiop*" OR cs-uri="*$${$${env:BARFOO:-j}*" OR cs-uri="*$${::-l}$${::-d}$${::-a}$${::-p}*" OR cs-uri="*$${base64:JHtqbmRp*") (cs-referrer="*$${jndi:ldap:/*" OR cs-referrer="*$${jndi:rmi:/*" OR cs-referrer="*$${jndi:ldaps:/*" OR cs-referrer="*$${jndi:dns:/*" OR cs-referrer="*/$$%7bjndi:*" OR cs-referrer="*%24%7bjndi:*" OR cs-referrer="*$$%7Bjndi:*" OR cs-referrer="*%2524%257Bjndi*" OR cs-referrer="*%2F%252524%25257Bjndi%3A*" OR cs-referrer="*$${jndi:$${lower:*" OR cs-referrer="*$${::-j}$${*" OR cs-referrer="*$${jndi:nis*" OR cs-referrer="*$${jndi:nds*" OR cs-referrer="*$${jndi:corba*" OR cs-referrer="*$${jndi:iiop*" OR cs-referrer="*$${$${env:BARFOO:-j}*" OR cs-referrer="*$${::-l}$${::-d}$${::-a}$${::-p}*" OR cs-referrer="*$${base64:JHtqbmRp*"))
```

### Elastic search检测规则

```yml
(cs-User-Agent:(*$\{jndi\:ldap\:\/* OR *$\{jndi\:rmi\:\/* OR *$\{jndi\:ldaps\:\/* OR *$\{jndi\:dns\:\/* OR *\/$%7bjndi\:* OR *%24%7bjndi\:* OR *$%7Bjndi\:* OR *%2524%257Bjndi* OR *%2F%252524%25257Bjndi%3A* OR *$\{jndi\:$\{lower\:* OR *$\{\:\:\-j\}$\{* OR *$\{jndi\:nis* OR *$\{jndi\:nds* OR *$\{jndi\:corba* OR *$\{jndi\:iiop* OR *$\{$\{env\:BARFOO\:\-j\}* OR *$\{\:\:\-l\}$\{\:\:\-d\}$\{\:\:\-a\}$\{\:\:\-p\}* OR *$\{base64\:JHtqbmRp*) AND user_agent.original:(*$\{jndi\:ldap\:\/* OR *$\{jndi\:rmi\:\/* OR *$\{jndi\:ldaps\:\/* OR *$\{jndi\:dns\:\/* OR *\/$%7bjndi\:* OR *%24%7bjndi\:* OR *$%7Bjndi\:* OR *%2524%257Bjndi* OR *%2F%252524%25257Bjndi%3A* OR *$\{jndi\:$\{lower\:* OR *$\{\:\:\-j\}$\{* OR *$\{jndi\:nis* OR *$\{jndi\:nds* OR *$\{jndi\:corba* OR *$\{jndi\:iiop* OR *$\{$\{env\:BARFOO\:\-j\}* OR *$\{\:\:\-l\}$\{\:\:\-d\}$\{\:\:\-a\}$\{\:\:\-p\}* OR *$\{base64\:JHtqbmRp*) AND cs-uri:(*$\{jndi\:ldap\:\/* OR *$\{jndi\:rmi\:\/* OR *$\{jndi\:ldaps\:\/* OR *$\{jndi\:dns\:\/* OR *\/$%7bjndi\:* OR *%24%7bjndi\:* OR *$%7Bjndi\:* OR *%2524%257Bjndi* OR *%2F%252524%25257Bjndi%3A* OR *$\{jndi\:$\{lower\:* OR *$\{\:\:\-j\}$\{* OR *$\{jndi\:nis* OR *$\{jndi\:nds* OR *$\{jndi\:corba* OR *$\{jndi\:iiop* OR *$\{$\{env\:BARFOO\:\-j\}* OR *$\{\:\:\-l\}$\{\:\:\-d\}$\{\:\:\-a\}$\{\:\:\-p\}* OR *$\{base64\:JHtqbmRp*) AND http.request.referrer:(*$\{jndi\:ldap\:\/* OR *$\{jndi\:rmi\:\/* OR *$\{jndi\:ldaps\:\/* OR *$\{jndi\:dns\:\/* OR *\/$%7bjndi\:* OR *%24%7bjndi\:* OR *$%7Bjndi\:* OR *%2524%257Bjndi* OR *%2F%252524%25257Bjndi%3A* OR *$\{jndi\:$\{lower\:* OR *$\{\:\:\-j\}$\{* OR *$\{jndi\:nis* OR *$\{jndi\:nds* OR *$\{jndi\:corba* OR *$\{jndi\:iiop* OR *$\{$\{env\:BARFOO\:\-j\}* OR *$\{\:\:\-l\}$\{\:\:\-d\}$\{\:\:\-a\}$\{\:\:\-p\}* OR *$\{base64\:JHtqbmRp*))
```


### Zeek检测规则

```yml
(event.dataset:"zeek.http" AND cs-User-Agent:(*$\{jndi\:ldap\:\/* OR *$\{jndi\:rmi\:\/* OR *$\{jndi\:ldaps\:\/* OR *$\{jndi\:dns\:\/* OR *\/$%7bjndi\:* OR *%24%7bjndi\:* OR *$%7Bjndi\:* OR *%2524%257Bjndi* OR *%2F%252524%25257Bjndi%3A* OR *$\{jndi\:$\{lower\:* OR *$\{\:\:\-j\}$\{* OR *$\{jndi\:nis* OR *$\{jndi\:nds* OR *$\{jndi\:corba* OR *$\{jndi\:iiop* OR *$\{$\{env\:BARFOO\:\-j\}* OR *$\{\:\:\-l\}$\{\:\:\-d\}$\{\:\:\-a\}$\{\:\:\-p\}* OR *$\{base64\:JHtqbmRp*) AND user_agent.original:(*$\{jndi\:ldap\:\/* OR *$\{jndi\:rmi\:\/* OR *$\{jndi\:ldaps\:\/* OR *$\{jndi\:dns\:\/* OR *\/$%7bjndi\:* OR *%24%7bjndi\:* OR *$%7Bjndi\:* OR *%2524%257Bjndi* OR *%2F%252524%25257Bjndi%3A* OR *$\{jndi\:$\{lower\:* OR *$\{\:\:\-j\}$\{* OR *$\{jndi\:nis* OR *$\{jndi\:nds* OR *$\{jndi\:corba* OR *$\{jndi\:iiop* OR *$\{$\{env\:BARFOO\:\-j\}* OR *$\{\:\:\-l\}$\{\:\:\-d\}$\{\:\:\-a\}$\{\:\:\-p\}* OR *$\{base64\:JHtqbmRp*) AND url.original:(*$\{jndi\:ldap\:\/* OR *$\{jndi\:rmi\:\/* OR *$\{jndi\:ldaps\:\/* OR *$\{jndi\:dns\:\/* OR *\/$%7bjndi\:* OR *%24%7bjndi\:* OR *$%7Bjndi\:* OR *%2524%257Bjndi* OR *%2F%252524%25257Bjndi%3A* OR *$\{jndi\:$\{lower\:* OR *$\{\:\:\-j\}$\{* OR *$\{jndi\:nis* OR *$\{jndi\:nds* OR *$\{jndi\:corba* OR *$\{jndi\:iiop* OR *$\{$\{env\:BARFOO\:\-j\}* OR *$\{\:\:\-l\}$\{\:\:\-d\}$\{\:\:\-a\}$\{\:\:\-p\}* OR *$\{base64\:JHtqbmRp*) AND http.request.referrer:(*$\{jndi\:ldap\:\/* OR *$\{jndi\:rmi\:\/* OR *$\{jndi\:ldaps\:\/* OR *$\{jndi\:dns\:\/* OR *\/$%7bjndi\:* OR *%24%7bjndi\:* OR *$%7Bjndi\:* OR *%2524%257Bjndi* OR *%2F%252524%25257Bjndi%3A* OR *$\{jndi\:$\{lower\:* OR *$\{\:\:\-j\}$\{* OR *$\{jndi\:nis* OR *$\{jndi\:nds* OR *$\{jndi\:corba* OR *$\{jndi\:iiop* OR *$\{$\{env\:BARFOO\:\-j\}* OR *$\{\:\:\-l\}$\{\:\:\-d\}$\{\:\:\-a\}$\{\:\:\-p\}* OR *$\{base64\:JHtqbmRp*))
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1190

<https://attack.mitre.org/techniques/T1190/>

Apache Log4j2漏洞利用检测

<https://www.socinvestigation.com/apache-log4j-vulnerability-detection-and-mitigation/>

Log4j漏洞分析

<https://blog.csdn.net/a1290320893/article/details/121914678>


