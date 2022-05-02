# T8000-win-使用User_Del删除用户

## 测试案例

参考下文中提到的User_Del.exe程序删除用户。

<https://github.com/Ryze-T/Windows_API_Tools>

作用：删除用户

用法：User_Del.exe Username

## 检测日志

 windows sysmon / Windows security

## 测试复现

测试环境说明：Windows server 2012

```shell
C:\Windows_API_Tools-main>net user wang TOpsec.098 /add
命令成功完成。

C:\Windows_API_Tools-main>User_Del.exe wang
success
```

## 测试留痕

Windows sysmon EventID：1 进程创建

```log
Process Create:
RuleName: technique_id=T1059,technique_name=Command-Line Interface
UtcTime: 2022-03-24 08:43:02.668
ProcessGuid: {4a363fee-2f16-623c-79a3-4e0000000000}
ProcessId: 4084
Image: C:\Windows_API_Tools-main\User_Del.exe
FileVersion: -
Description: -
Product: -
Company: -
OriginalFileName: -
CommandLine: User_Del.exe  wang
CurrentDirectory: C:\Windows_API_Tools-main\
User: WEIDONG\Administrator
LogonGuid: {4a363fee-2447-623c-df16-080000000000}
LogonId: 0x816DF
TerminalSessionId: 1
```

windows security EventID：4733、4729、4726

```log
4733
已从启用了安全性的本地组中删除某个成员。

使用者:
 安全 ID:  WEIDONG\Administrator
 帐户名:  Administrator
 帐户域:  WEIDONG
 登录 ID:  0x816DF

成员:
 安全 ID:  WEIDONG\wang
 帐户名:  -

组:
 安全 ID:  BUILTIN\Users
 组名:  Users
 组域:  Builtin

附加信息:

4729
已从启用了安全性的全局组中删除某个成员。

使用者:
 安全 ID:  WEIDONG\Administrator
 帐户名:  Administrator
 帐户域:  WEIDONG
 登录 ID:  0x816DF

成员:
 安全 ID:  WEIDONG\wang
 帐户名:  -

组:
 安全 ID:  WEIDONG\None
 组名:  None
 组域:  WEIDONG

附加信息:

4726
已删除用户帐户。

使用者:
 安全 ID:  WEIDONG\Administrator
 帐户名:  Administrator
 帐户域:  WEIDONG
 登录 ID:  0x816DF

目标帐户:
 安全 ID:  WEIDONG\wang
 帐户名:  wang
 帐户域:  WEIDONG

附加信息:
 特权 
```

## 检测规则/思路

整体上看特征还是很明显的，重点关注账户删除日志。

## 参考推荐

系统监视器(Sysmon)工具的使用

<https://blog.csdn.net/ducc20180301/article/details/119350200>

Windows_API_Tools

<https://github.com/Ryze-T/Windows_API_Tools>
