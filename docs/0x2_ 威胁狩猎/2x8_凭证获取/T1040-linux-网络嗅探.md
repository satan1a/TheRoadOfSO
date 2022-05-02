# T1040-linux-网络嗅探

## 来自ATT&CK的描述

网络嗅探是指使用系统上的网络接口来监视或捕获通过有线或无线连接发送的信息。攻击者可以将网络接口置于混杂模式以通过网络被动地访问传输中的数据，或者使用跨接端口来捕获更大量的数据。

通过该技术可以捕获的数据包括用户凭证，尤其是通过不安全的未加密协议发送的凭证；网络嗅探还可以获取到配置细节，例如运行服务，版本号以及后续横向移动和防御逃避活动所需的其他网络特征（例如：IP寻址，主机名，VLAN ID）。

## 测试案例

tcpdump -c 5 -nnni #{网卡接口}

tshark -c 5 -i #{网卡接口}

## 检测日志

linux /var/log/message （值得注意的是：Ubuntu下默认不开启message日志，需要手动开启）

## 测试复现

### 场景一

```bash
root@icbc:~# tcpdump -c 5 -nnni ens33
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on ens33, link-type EN10MB (Ethernet), capture size 262144 bytes
10:37:34.347544 IP 192.168.66.1.60886 > 239.255.255.250.1900: UDP, length 137
10:37:37.355725 IP 192.168.66.1.60886 > 239.255.255.250.1900: UDP, length 137
10:37:40.356238 IP 192.168.66.1.60886 > 239.255.255.250.1900: UDP, length 137
10:37:43.356969 IP 192.168.66.1.60886 > 239.255.255.250.1900: UDP, length 137
10:37:49.808569 IP 192.168.66.148.59150 > 192.168.66.2.53: 15476+ [1au] A? connectivity-check.ubuntu.com. (58)
5 packets captured
5 packets received by filter
0 packets dropped by kernel
```

### 场景二

```bash
root@icbc:~# tshark -c 5 -i ens33
Running as user "root" and group "root". This could be dangerous.
Capturing on 'ens33'
    1 0.000000000 192.168.66.148 → 192.168.66.2 DNS 100 Standard query 0xe349 A connectivity-check.ubuntu.com OPT
    2 0.038532840 Vmware_e8:11:b3 → Broadcast    ARP 60 Who has 192.168.66.148? Tell 192.168.66.2
    3 0.038552195 Vmware_02:d5:c7 → Vmware_e8:11:b3 ARP 42 192.168.66.148 is at 00:0c:29:02:d5:c7
    4 0.038758293 192.168.66.2 → 192.168.66.148 DNS 132 Standard query response 0xe349 A connectivity-check.ubuntu.com A 35.224.99.156 A 35.222.85.5 OPT
    5 0.039670671 192.168.66.148 → 35.222.85.5  TCP 74 57812 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=136575048 TSecr=0 WS=128
5 packets captured
```

## 测试留痕

### 0x1

message日志

Jul 19 10:37:33 icbc kernel: [  298.396406] device ens33 entered promiscuous mode

### 0x2

message日志

Jul 19 10:47:42 icbc systemd[1]: Started Cleanup of Temporary Directories.
Jul 19 10:47:50 icbc kernel: [  915.199848] device ens33 left promiscuous mode
Jul 19 10:47:50 icbc start.sh[734]: 2019-07-19 10:47:50,165: DEBUG helpers.application.health RAM: 65MB

## 检测规则/思路

### splunk检测规则

index=linux sourcetype=syslog entered promiscuous mode | table host,message

index=linux sourcetype=syslog left promiscuous mode | table host,message

### 建议

暂无

## 参考推荐

MITRE-ATT&CK-T1040: 

<https://attack.mitre.org/techniques/T1040/>
