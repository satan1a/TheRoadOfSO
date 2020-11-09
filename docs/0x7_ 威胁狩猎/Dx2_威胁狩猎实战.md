# 威胁狩猎实战

通过监控学校的官网，发现了一个访问次数非常大的一个IP：`115.239.194.82`，以此为目标来进行Hunting。

## 通过TI平台查询

### 通过微步查询该IP

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814163558.png)

可以看到这个IP标签为：

-   僵尸网络
-   扫描
-   垃圾邮件
-   装库
-   撞库
-   网关

### 通过内部系统查看

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814165945.png)

提供内部系统查询该IP的解析信息，发现了`edu.cn`，`vpn.zjxz.edu.cn`等域名，疑似为教育系统的资产。



#### 提出假设

是浙师大行知学院（独立学院）那边的VPN地址，然后行知的学生通过它来连接浙师大的官网`zjnu.edu.cn`，请求的量很大，所以被识别为了僵尸网络





## Graph分析![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814164934.png)



![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814183602.png)

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814182821.png)

可以看到，该IP关联出来的，曾经绑定过的域名为：`www-zjxz-edu-cn.cname.saaswaf.com`，它的域为`saaswaf.com`，这个带有waf字样，且与其他的几个明显不同，因此需要进行下一步分析

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814183422.png)

通过ICP备案，查询到该此为安恒的玄武盾云WAF。



## 主机信息搜集

### 发现主机地址位置

发现其地理位置为：中国 浙江 金华



### 反查域名信息

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814164210.png)

查看该IP域名反查记录，发现其绑定过`www.zjxz.cn`域名，该域名指向“浙江师范大学 行知学院（独立学院）”的相关信息。通过查询，浙师行知学院的官方域名是`www.zjxz.edu.cn`。



###  发现端口信息（被动探测）

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814165844.png)

通过被动扫描信息，发现这个IP开着两个端口：4443和10443端口。接下来分析该端口服务的特征。

### 分析端口服务（被动探测）

#### 分析4443端口

4443端口，提供查询，发现该端口与一个内网穿透服务`ngork`一致，ngork是开源，项目地址是：https://github.com/inconshreveable/ngrok

>   **什么是ngrok呢？ngrok是一个反向代理，它能够让你本地的web服务或tcp服务通过公共的端口和外部建立一个安全的通道，使得外网可以访问本地的计算机服务。** 也就是说，我们提供的服务（比如web站点）无需搭建在外部服务器，只要通过ngrok把站点映射出去，别人即可直接访问到我们的服务。[1]

#### 分析10443端口

通过[SpeedGuide](https://www.speedguide.net/)查询到该端口通常当作备用的SSL端口，且其被用于Fortinet SSL VPN的备用端口

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814170807.png)

图：[来源](https://www.speedguide.net/port.php?port=10443#)

#### 综合分析

通过被动扫描信息发现，该IP地址总共开放两个端口：4443和10443。前者疑似为一个内网穿透服务，后者疑似为VPN SSL端口。

所以总体来说，通过被动端口探测，是疑似为VPN服务。



### 发现端口信息（主动探测）

使用Nmap探测该IP的开放端口信息（部分）

注：Nmap默认扫描从1到1024再加上nmap-services（nmap-services是一个包含大约2200个著名的服务的数据库）列出的端口

```bash
$ sudo proxychains nmap -sS 115.239.194.82
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-14 09:21 UTC
Nmap scan report for 115.239.194.82
Host is up (0.054s latency).
Not shown: 994 closed ports
PORT     STATE    SERVICE
22/tcp   filtered ssh
23/tcp   filtered telnet
80/tcp   filtered http
445/tcp  filtered microsoft-ds
4443/tcp open     pharos
4444/tcp filtered krb524
```

探测全部的开放端口信息，指定全部端口（1-65535）

```bash
sudo proxychains nmap -sS 115.239.194.82 -p 1-65535
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-14 09:28 UTC

PORT      STATE    SERVICE
22/tcp    filtered ssh
23/tcp    filtered telnet
80/tcp    filtered http
445/tcp   filtered microsoft-ds
3288/tcp  open     cops
4443/tcp  open     pharos
4444/tcp  filtered krb524
5554/tcp  filtered sgi-esphttp
8118/tcp  open     privoxy
8887/tcp  open     unknown
10443/tcp open     unknown
40442/tcp open     unknown
44430/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 159.40 seconds
```



### 分析端口服务（主动探测）

#### 分析被过滤端口

通过上面的主动探测，可以看到在Nmap的STATE中，22、23、80、445、4444、5554、44430都显示为filtered（被过滤）状态，这些端口都是相对“高危”的，可以看到是有意进行过防护。

注：Nmap状态——filtered(被过滤的)，表示由于包过滤阻止探测报文到达端口， Nmap无法确定该端口是否开放。过滤可能来自专业的防火墙设备，路由器规则或者主机上的软件防火墙。[2]

以下是Nmap探测到的，被过滤的端口：

-   22，SSH服务
-   23，telnet服务
-   80，http服务
-   445，重点，通常用于SMB（Server Message Block）协议，进行文件共享，常在老版本的Microsoft Server上发现，该端口比较“高危”
-   4444，重点，该端口是众多木马的特征，主动或被动地在进行监听，但被过滤，可以看出其进行了防护
-   5554，重点，该端口也是木马监听端口，Sasser Worm FTP Server，同样也进行了防护
-   44430，未发现明显特征



#### 分析8118端口

还可以发现，该IP开放了8118端口，疑似为代理服务`Privoxy`

>   Privoxy是一款不进行网页缓存且自带过滤功能的代理服务器，针对HTTP、HTTPS协议。通过其过滤功能，用户可以保护隐私、对网页内容进行过滤、管理Cookie，以及拦阻各种广告等。Privoxy可以单机使用，也可以应用到多用户的网络。[3]

#### 分析8887端口

通过[SpeedGuide](https://www.speedguide.net/)查询到该端口用于I2P领域：

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814180030.png)

另外，在中文论坛搜索到了以下相关的信息，来源于华为企业互动社区的提问，再次出现了“VPN”关键词：

>   USG6000系列防火墙外网扫公司的接口地址发现开了8888端口，可是这个我没有做端口映射啊，现在怀疑是不是开了L2TP  VPN导致的，可是记得L2TP VPN采用的是1701端口啊，我怎么才能知道这个端口是什么应用，现在VPN一直用着，也不敢关？[4]

#### 分析40442端口

没有找到明确的服务，通过[SpeedGuide](https://www.speedguide.net/)查询到的信息：

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814180420.png)



## 相关信息验证

### 相关资产信息

我们的假设是该IP为浙师大行知的VPN服务器，所以查看该学校利采用的VPN

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814184749.png)

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814184949.png)

可以发现，该学校采用了深信服的EasyConnect VPN服务。

![](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200814185734.png)

## 结论

-   该IP很有可能是学校的资产
-   该IP可能是VPN的出口IP或者学校买的“安恒”设备的IP（注：请看Graph分析）
    -   但安全设备种类太多，还不太能确定具体是什么类型的设备
-   至于TI平台上显示的该IP的“种种劣迹”，可能是有人挂着该VPN对`zjnu.edu.cn`内网进行了渗透操作，也可能是对其他站
-   以上这些我做的步骤，主要是威胁狩猎的信息搜集部分，威胁狩猎的最终目的呢，是要产出一个关于攻击者的调查报告之类，描述攻击者的情况。主要的重点在于攻击者，依据“每个攻击后面都对应着一个攻击者”的思路。



## References

\[1] https://morongs.github.io/2016/12/28/dajian-ngrok/

\[2] https://nmap.org/man/zh/man-port-scanning-basics.html

\[3] https://zh.wikipedia.org/wiki/Privoxy

\[4] https://forum.huawei.com/enterprise/zh/thread-417025-1-1.html