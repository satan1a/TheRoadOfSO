# T1557-002-linux-ARP网络嗅探

## 来自ATT&CK的描述

攻击者可能会在地址解析协议（ARP）缓存中下毒，将自己置于两个或多个联网设备的通信之间。这种活动可能被用来实现后续的攻击行为，如网络嗅探或传输数据操纵。

ARP协议用于将IPv4地址解析为链路层地址，如媒体访问控制（MAC）地址。本地网段中的设备通过使用链路层地址相互通信。如果一个联网设备没有特定联网设备的链路层地址，它可以向本地网络发出广播ARP请求，将IP地址翻译成MAC地址。拥有相关IP地址的设备会直接回复其MAC地址。发出ARP请求的联网设备就会使用以及在其ARP缓存中存储该信息。

攻击者可能会被动地等待一个ARP请求，以毒害请求设备的ARP缓存。攻击者可能会用他们的MAC地址进行回复，从而欺骗受害者，让他们相信他们正在与预定的网络设备进行通信。攻击者要毒害ARP缓存，他们的回复必须比合法IP地址所有者的回复快。攻击者也可以发送一个无偿的ARP回复，恶意地向本地网段的所有设备宣布某个IP地址的所有权。

ARP协议是无状态的，不需要认证。因此，设备可能会错误地添加或更新其ARP缓存中的IP地址的MAC地址。

攻击者可能利用ARP缓存中毒作为中间人（MiTM）网络流量的一种手段。这种活动可能被用来收集或转发数据，如证书，特别是那些通过不安全的、未加密的协议发送的数据。

## 测试案例

linux下arp命令执行

ARP -A,查询系统中缓存的ARP表。ARP表用来维护IP地址与MAC地址的一一对应。

## 检测日志

linux audit日志

## 测试复现

暂无

## 测试留痕

```yml
type=SYSCALL msg=audit(1604994496.155:92733): arch=c000003e syscall=59 success=yes exit=0 a0=558e251634a0 a1=558e25162a50 a2=558e25160800 a3=8 items=2 ppid=29002 pid=1631 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=104 comm="arp" exe="/usr/sbin/arp" key=(null)
type=EXECVE msg=audit(1604994496.155:92733): argc=2 a0="arp" a1="-a"
type=CWD msg=audit(1604994496.155:92733): cwd="/home/wardog"
type=PATH msg=audit(1604994496.155:92733): item=0 name="/usr/sbin/arp" inode=13181 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1604994496.155:92733): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=29514 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PROCTITLE msg=audit(1604994496.155:92733): proctitle=617270002D61
type=SYSCALL msg=audit(1604994496.155:92734): arch=c000003e syscall=59 success=yes exit=0 a0=558e251634a0 a1=558e25163720 a2=558e25160800 a3=558e2500a010 items=2 ppid=29002 pid=1632 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=104 comm="grep" exe="/bin/grep" key=(null)
type=EXECVE msg=audit(1604994496.155:92734): argc=3 a0="grep" a1="-v" a2="^?"
type=CWD msg=audit(1604994496.155:92734): cwd="/home/wardog"
type=PATH msg=audit(1604994496.155:92734): item=0 name="/bin/grep" inode=61 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PATH msg=audit(1604994496.155:92734): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=29514 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0
type=PROCTITLE msg=audit(1604994496.155:92734): proctitle=67726570002D76005E3F
```

## 检测规则/思路

检测audit日志中arp命令的使用情况。

```yml
type=SYSCALL msg=audit(1604994496.155:92733): arch=c000003e syscall=59 success=yes exit=0 a0=558e251634a0 a1=558e25162a50 a2=558e25160800 a3=8 items=2 ppid=29002 pid=1631 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=104 comm="arp" exe="/usr/sbin/arp" key=(null)
type=EXECVE msg=audit(1604994496.155:92733): argc=2 a0="arp" a1="-a"
```

### 建议

监测网络流量，看是否有不寻常的ARP流量，无偿的ARP回复可能是可疑的。

考虑收集各端点ARP缓存的变化，以发现ARP中毒的迹象。例如，如果多个IP地址映射到一个MAC地址，这可能是ARP缓存被投毒的一个指标。

## 参考推荐

MITRE-ATT&CK-T1557-002

<https://attack.mitre.org/techniques/T1557/002>

测试留痕数据来源

<https://github.com/OTRF/Security-Datasets/tree/master/datasets/small/linux>
