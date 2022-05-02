# T1505-003-webshell-冰蝎

## 来自ATT&CK的描述

Webshell是一个Web脚本，放置在可公开访问的Web服务器上，允许攻击者将Web服务器用作网络的网关。 Web shell可以提供多种功能，如虚拟终端、文件管理、数据库连接等。 除了服务器端脚本之外，Webshell可能还有一个客户端接口程序，用于与管理Web服务器的通信（例如，中国菜刀、C刀、蚁剑、冰蝎等）。

## 测试案例

PHP网站（Phpstudy+DVWA）

冰蝎V1.0/V2.0（客户端+自带shell）

wireshark（必备）

## 检测日志

HTTP流量

## 测试复现

利用DVWA相关漏洞，上传冰蝎默认webshell，利用冰蝎客户端对webshell进行管理，抓取冰蝎客户端与web服务器上的脚本之间的通讯流量。

## 测试留痕

### 冰蝎V1.0

#### 1）正常流量

**GET请求包**a

```http
GET /1.php HTTP/1.1

Host: 192.168.66.136

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2

Accept-Encoding: gzip, deflate

Referer: <http://192.168.66.136/>

DNT: 1

Connection: keep-alive

Upgrade-Insecure-Requests: 1

Cache-Control: max-age=0
```

**GET请求返回包**a

```http
HTTP/1.1 200 OK

Date: Tue, 20 Aug 2019 02:50:43 GMT

Server: Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.4.45

X-Powered-By: PHP/5.4.45

Content-Length: 4

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive

Content-Type: text/html

test
```

**POST请求包**a

```http
POST /DVWA/vulnerabilities/exec/ HTTP/1.1

Host: 192.168.66.136

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 40

DNT: 1

Connection: keep-alive

Referer: <http://192.168.66.136/DVWA/vulnerabilities/exec/>

Cookie: security=low; PHPSESSID=190krorgsuckk0elaa1tk0v891

Upgrade-Insecure-Requests: 1

ip=127.0.0.1+%26%26+whoami&Submit=Submit
```

**POST返回包**a

```http
HTTP/1.1 200 OK

Date: Tue, 20 Aug 2019 02:52:47 GMT

Server: Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.4.45

X-Powered-By: PHP/5.4.45

Expires: Tue, 23 Jun 2009 12:00:00 GMT

Cache-Control: no-cache, must-revalidate

Pragma: no-cache

Content-Length: 5161

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive

Content-Type: text/html;charset=utf-8

!DOCTYPE html PUBLIC "-//W3C//DTD（此处省略更多字符信息）
```

#### 2）冰蝎客户端与服务端通信流量

**GET请求包**

```pacp
GET /shell.php?pass=1 HTTP/1.1

User-Agent: Java/1.8.0_211

Host: 192.168.66.136

Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2

Connection: keep-alive
```

**GET返回包**

```http
HTTP/1.1 200 OK

Date: Sun, 21 Jul 2019 02:51:55 GMT

Server: Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.4.45

X-Powered-By: PHP/5.4.45

Set-Cookie: PHPSESSID=6dclf3mic9i86q7r6snpk34ef1; path=/

Expires: Thu, 19 Nov 1981 08:52:00 GMT

Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0

Pragma: no-cache

Content-Length: 16

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive

Content-Type: text/html

f52eb8c003a3991b
```

**POST请求包**

```pacp

POST /shell.php HTTP/1.1

Content-Type: application/octet-stream

Cookie: null;PHPSESSID=6dclf3mic9i86q7r6snpk34ef1; path=/

Cache-Control: no-cache

Pragma: no-cache

User-Agent: Java/1.8.0_211

Host: 192.168.66.136

Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2

Connection: keep-alive

Content-Length: 1624

D3dH8lwIFCCGYS9Yca  （此处省略加密字符信息）
```

**POST返回包**

```http
HTTP/1.1 200 OK

Date: Sun, 21 Jul 2019 02:51:55 GMT

Server: Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.4.45

X-Powered-By: PHP/5.4.45

Expires: Thu, 19 Nov 1981 08:52:00 GMT

Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0

Pragma: no-cache

Keep-Alive: timeout=5, max=99

Connection: Keep-Alive

Transfer-Encoding: chunked

Content-Type: text/html

1f4c0（此处省略加密字符信息）
```

#### 3）正常流量VS冰蝎通讯流量

从中可以看到冰蝎V1.0版本在初期交互通讯时，特征较为明显，user-agent与正常业务流量明显不同。可以通过对**user-agent**进行检测分析。其次在POST返回包中相对正常流量多了**Transfer-Encoding: chunked**，Transfer-Encoding主要是用来改变报文格式，这里指的是利用分块进行传输。你可以基于此特征值进行检测，当然，你也可以用更简单的方法进行检测，比如url中包含**.php?pass=**来进行检测。

### 冰蝎V2.1

从冰蝎V1.1开始新增随机UserAgent支持，每次会话会从17种常见UserAgent中随机选取。冰蝎最新版本为V2.1，可以通过对2.1版本服务端与客户端的通信流量，进行捕获，对比正常流量进行分析。

#### 1）正常流量a

**GET请求包**a

同冰蝎V1.0章节

**GET请求返回包**a

同冰蝎V1.0章节

**POST请求包**a

同冰蝎V1.0章节

**POST返回包**a

同冰蝎V1.0章节

#### 2）冰蝎客户端与服务端通信流量a

**GET请求包**a

```pacp
GET /DVWA/hackable/uploads/shell.php?pass=673 HTTP/1.1

Content-type: application/x-www-form-urlencoded

User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; InfoPath.3)

Host: 192.168.66.136

Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2

Connection: keep-alive

**GET请求返回包**a

HTTP/1.1 200 OK

Date: Mon, 19 Aug 2019 09:34:36 GMT

Server: Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.4.45

X-Powered-By: PHP/5.4.45

Set-Cookie: PHPSESSID=m0agat42tmo0i4srnda5ssfq94; path=/

Expires: Thu, 19 Nov 1981 08:52:00 GMT

Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0

Pragma: no-cache

Content-Length: 16

Keep-Alive: timeout=5, max=100

Connection: Keep-Alive

Content-Type: text/html

03befc81cbefda94
```

**POST请求包**

```pcap
POST /DVWA/hackable/uploads/shell.php HTTP/1.1

Content-Type: application/x-www-form-urlencoded

Cookie: PHPSESSID=bv5lv0681hq09ggt8rfj1peio5; path=/

User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; InfoPath.3)

Cache-Control: no-cache

Pragma: no-cache

Host: 192.168.66.136

Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2

Connection: keep-alive

Content-Length: 2220

ltEi32XJreSl8Y5Hhzk08Wgjfe8bLPr3x8n4qlJ（此处省略加密字符信息）
```

**POST返回包**

```http
HTTP/1.1 200 OK

Date: Mon, 19 Aug 2019 09:34:36 GMT

Server: Apache/2.4.23 (Win32) OpenSSL/1.0.2j PHP/5.4.45

X-Powered-By: PHP/5.4.45

Expires: Thu, 19 Nov 1981 08:52:00 GMT

Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0

Pragma: no-cache

Keep-Alive: timeout=5, max=97

Connection: Keep-Alive

Transfer-Encoding: chunked

Content-Type: text/html

21dc0gfUOcrBcH7jint5L0pmkDxT5ypIbjLnIsXnDxHGjofQk3g（此处省略加密字符信息）
```

### 3）正常流量VS冰蝎通讯流量a

通过对比可以看到，冰蝎V2.1在初期交互通讯时流量中多了**Transfer-Encoding: chunked**，Transfer-Encoding主要是用来改变报文格式，这里指的是利用分块进行传输。你可以基于此特征值进行检测，当然，你也可以用更简单的方法进行检测，比如url中包含**.php?pass=**来进行检测。

## 检测特征/思路

### 冰蝎V1.0a

基于GET请求包的检测特征：url包含.php?pass=，useragent包含Java/*；

基于POST请求包的检测特征：useragent包含Java/* ，返回包包含：Transfer-Encoding: chunked；

### 冰蝎V2.1a

基于GET请求包的检测特征：url包含.php?pass=；（如果与业务冲突，误报较大）

基于POST返回包的检测特征：Transfer-Encoding: chunked；

## 相关TIP
[[T1505-003-webshell-冰蝎v3.0]]
[[T1505-003-windows下webshell检测]]
[[T1505-003-web服务产生的可疑进程]]


## 参考推荐

MITRE-ATT&CK-T1505-003

<https://attack.mitre.org/techniques/T1505/003/>

冰蝎下载地址

<https://github.com/rebeyond/Behinder/releases>
