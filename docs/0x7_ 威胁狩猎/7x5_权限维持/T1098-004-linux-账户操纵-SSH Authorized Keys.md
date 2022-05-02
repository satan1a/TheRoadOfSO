# T1098-004-linux-账户操纵-SSH Authorized Keys

## 来自ATT&CK的描述

攻击者可能会修改SSH `authorized_keys`文件来维持对目标主机的持久访问。 Linux发行版和macOS通常会对远程管理的SSH会话采用基于密钥的身份验证过程。SSH中的`authorized_keys`文件指定了登录用户账户（该文件就是为此账户而配置）需要用到的SSH密钥。此文件通常位于用户home目录中的`<user-home>/.ssh/authorized_keys`下（引自：SSH Authorized Keys）。用户可能会编辑系统的SSH配置文件，将PubkeyAuthentication 和RSAAuthentication 设置为“yes”来启用公钥和RSA身份验证。SSH配置文件通常位于`/etc/ssh/sshd_config`下。

攻击者可能会直接通过脚本或shell命令修改SSH `authorized_keys`文件，添加他们自己提供的公共密钥。然后，拥有相应私钥的攻击者就可以通过SSH以现有用户身份登录（引自：Venafi SSH Key Abuse）（引自：Cybereason Linux Exim Worm）。

## 测试案例

### 通过写入SSH公钥在Linux系统上实现持久化

#### 攻击机生成公钥

首先在Kali攻击机生成公钥和私钥，其中id_rsa.pub为公钥，id_rsa为私钥。

```
ssh-keygen -t rsa
```

#### 在靶机写入公钥

将kali攻击机中生成的公钥id_rsa.pub内容写入到靶机中

`echo "xxx" >> ~/.ssh/authorized_keys`

#### 攻击机实现免密码登录靶机

使用`ssh`命令直接连接靶机

`ssh root@10.255.30.21`

## 检测日志

无

## 测试复现

无

## 测试留痕

无

## 检测规则/思路

### 建议

使用文件完整性监控来检测系统上每个用户对`authorized_keys`文件所做的更改。监控可疑进程是否修改了`authorized_keys`文件。

监控修改`/etc/ssh/sshd_config`的更改和可疑进程。

## 相关TIP
[[Threathunting-book/5-权限维持/T1098-win-万能密码]]
[[Threathunting-book/5-权限维持/T1098-win-账户操作]]
[[T1098-win-AdminSDHolder]]

## 参考推荐

MITRE-ATT&CK-T1098-001

<https://attack.mitre.org/techniques/T1098/001/>