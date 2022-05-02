# T1548-001-linux-Setuid and Setgid

## 来自ATT&CK的描述

攻击者可以使用setuid或setgid位执行shell转义或利用应用程序中的漏洞来获取在不同用户上下文中运行的代码。在Linux或macOS上，当为应用程序设置了setuid或setgid位时，该应用程序将分别以拥有用户或组的特权运行。通常，应用程序是在当前用户的上下文中运行的，而不管哪个用户或组拥有该应用程序。但是，在某些情况下，需要在提升权限的上下文中执行程序才能正常运行，但运行它们的用户不需要提升权限。

任何用户都可以为自己的应用程序设置setuid或setgid标志，而不必在sudoers文件中创建条目（必须由root用户完成）。通过查看文件属性时，这些位用“s”而不是“x”表示ls -l。该chmod程序能够经由bitmasking设置这些位与，chmod 4777 [file]或通过速记命名，chmod u+s [file]。

攻击者可以对自己的恶意软件使用此机制，以确保他们将来能够在提升的环境中执行。

### 关于Setuid and Setgid详解

文件权限的机制是Linux系统的一大特色，对于初学Linux的人对可读（r）、可写（w）、可执行（x）这都是比较基本的权限。一个文件的权限有十个位，分为三组来表示。第一个位为一组，表示文件的类型：

-：表示一般文件

d：表示目录文件

l：表示链接文件

b：表示块设备

c：表示字符设备

p：表示管道

s：表示套接字

但是Linux还有三个比较特殊的权限，分别是：setuid，setgid，stick bit （粘滞位）。

 setuid: 设置使文件在执行阶段具有文件所有者的权限. 典型的文件是 /usr/bin/passwd. 如果一般用户执行该文件, 则在执行过程中, 该文件可以获得root权限, 从而可以更改用户的密码。

 setgid: 该权限只对目录有效. 目录被设置该位后, 任何用户在此目录下创建的文件都具有和该目录所属的组相同的组。

 stick bit: 该位可以理解为防删除位. 一个文件是否可以被某用户删除, 主要取决于该文件所属的组是否对该用户具有写权限. 如果没有写权限, 则这个目录下的所有文件都不能被删除, 同时也不能添加新的文件. 如果希望用户能够添加文件但同时不能删除文件, 则可以对文件使用stick bit位. 设置该位后, 就算用户对目录具有写权限, 也不能删除该文件。

## 测试案例

操作这些标志与操作文件权限的命令是一样的, 都是 chmod. 有两种方法来操作：

### 方法一

chmod u+s xxx # 设置setuid权限，加上setuid标志(setuid 只对文件有效)

chmod g+s xxx # 设置setgid权限，加上setgid标志 (setgid 只对目录有效)

chmod o+t xxx # 设置stick bit权限，针对目录

### 方法二

 采用八进制方式. 对一般文件通过三组八进制数字来置标志, 如 666, 777, 644等. 如果设置这些特殊标志, 则在这组

数字之外外加一组八进制数字. 如4666, 2777等

chmod 4775 xxx # 设置setuid权限

chmod 2775 xxx # 设置setgid权限

chmod 1775 xxx # 设置stick bit权限，针对目录

 在这里只讲第一位8进制代表权限

0: 不设置特殊权限

1：只设置sticky

2：只设置SGID

3：只设置SGID和sticky

4：只设置SUID

5：只设置SUID和sticky

6：只设置SUID和SGID

7：设置3种权限

设置完这些标志后, 可以用 ls -l 来查看. 如果有这些标志, 则会在原来的执行标志位置上显示。那么原来的执行标志x到哪里去了呢? 系统是这样规定的, 如果本来在该位上有x, 则这些特殊标志显示为小写字母 (s, s, t). 否则, 显示为大写字母 (S, S, T)。

注：在UNIX系统家族里，文件或目录权限的控制分别以读取，写入，执行3种一般权限来区分，另有3种特殊权限

可供运用，再搭配拥有者与所属群组管理权限范围。您可以使用chmod指令去变更文件与目录的权限，设置方式

采用文字或数字代号皆可。符号连接的权限无法变更，如果您对符号连接修改权限，其改变会作用在被连接的原始

文件。权限范围的表示法如下：

　　u：User，即文件或目录的拥有者。

　　g：Group，即文件或目录的所属群组。

　　o：Other，除了文件或目录拥有者或所属群组之外，其他用户皆属于这个范围。

　　a：All，即全部的用户，包含拥有者，所属群组以及其他用户。

　　有关权限代号的部分，列表于下：

　　r：读取权限，数字代号为"4"。

　　w：写入权限，数字代号为"2"。

　　x：执行或切换权限，数字代号为"1"。

　　-：不具任何权限，数字代号为"0"。

　　s：特殊?b>功能说明：变更文件或目录的权限。

## 检测日志

bash历史记录

## 测试复现

### 方法一/

icbc@icbc:/hacker$ ls -l

-rw-r--r--  1 root root    0 7月  19 17:22 bas.txt

icbc@icbc:/hacker$ sudo chmod u+s bas.txt

icbc@icbc:/hacker$ ls -l

-rwSr--r--  1 root root    0 7月  19 17:22 bas.txt

icbc@icbc:/hacker$ sudo chmod g+s bas.txt

icbc@icbc:/hacker$ ls -l

-rwSr-Sr--  1 root root    0 7月  19 17:22 bas.txt

### 方法二/

icbc@icbc:/hacker$ ls -l

-rwxr-xr-x  1 root root    0 8月  28 15:16 admin.txt

icbc@icbc:/hacker$ sudo chmod 4777 admin.txt

icbc@icbc:/hacker$ ls -l

-rwsrwxrwx  1 root root    0 8月  28 15:16 admin.txt

icbc@icbc:/hacker$ sudo chmod 2777 admin.txt

icbc@icbc:/hacker$ ls -l

-rwxrwsrwx  1 root root    0 8月  28 15:16 admin.txt

## 测试留痕

### 方法一 /

icbc@icbc:/hacker$ history

650  chmod u+s bas.txt

651  sudo chmod u+s bas.txt

652  ls -l

653  sudo chmod g+s bas.txt

### 方法二 /

icbc@icbc:/hacker$ history

683  sudo chmod 4777 admin.txt

684  ls -l

685  sudo chmod 2777 admin.txt

## 检测规则/思路

splunk检测规则：index=linux sourcetype=bash_history "chmod `4***`" OR "chmod `2***`" OR "chmod u+s" OR "chmod g+s" | table host,user_name,bash_command

## 参考推荐

MITRE-ATT&CK-T1548-001

<https://attack.mitre.org/techniques/T1548/001/>

linux文件特殊权限

<https://www.cnblogs.com/patriot/p/7874725.html>

linux中chmod命令详解

<https://www.cnblogs.com/lianstyle/p/8571975.html>

linux下的chmod参数详解

<https://blog.csdn.net/taiyang1987912/article/details/41121131>
