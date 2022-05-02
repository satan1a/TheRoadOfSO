# T1505-003-webshell-冰蝎

## 来自ATT&CK的描述

Webshell是一个Web脚本，放置在可公开访问的Web服务器上，允许攻击者将Web服务器用作网络的网关。 Web shell可以提供多种功能，如虚拟终端、文件管理、数据库连接等。 除了服务器端脚本之外，Webshell可能还有一个客户端接口程序，用于与管理Web服务器的通信（例如，中国菜刀、C刀、蚁剑、冰蝎等）。

## 测试案例

暂无，可自行本地测试；

## 检测日志

HTTP流量

## 测试复现

暂无，建议自行本地测试；

## 测试留痕

暂无，建议本地自行测试，抓取流量数据；

## 检测规则/思路

### suricata规则

参考来源：<https://github.com/suricata-rules/suricata-rules/tree/master/Behinder>

```yml
alert http any any -> any any  (msg: "Behinder3 PHP HTTP Request"; flow: established, to_server; content:".php"; http_uri;  pcre:"/[a-zA-Z0-9+/]{1000,}=/i"; flowbits:set,behinder3;noalert; classtype:shellcode-detect; sid: 3016017; rev: 1; metadata:created_at 2020_08_17,by al0ne;)
alert http any any -> any any (msg: "Behinder3  PHP HTTP Response"; flow: established,to_client; content:"200"; http_stat_code; flowbits: isset,behinder3; pcre:"/[a-zA-Z0-9+/]{100,}=/i"; classtype:shellcode-detect; sid: 3016018; rev: 1; metadata:created_at 2020_08_17,by al0ne;)
```

### 自定义检测规则

```
自定义规则进行防护：(uri_path * rco \.(jsp|jspx|php)$)&&(method * belong POST)&&(request_body * req ^[\w+/]{1000,}=?=?$)
```

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1505-003

<https://attack.mitre.org/techniques/T1505/003/>

冰蝎3.0流量特征分析附特征

<https://mp.weixin.qq.com/s/XMLK5OCpH9pICD9EL9nugA>

冰蝎的前世今生:3.0新版本下的一些防护思考

<https://mp.weixin.qq.com/s/WYM3J3daMTFODr4BSkKzxg>
