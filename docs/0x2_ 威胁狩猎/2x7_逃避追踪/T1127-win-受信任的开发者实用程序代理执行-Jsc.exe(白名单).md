# T1127-win-受信任的开发者实用程序代理执行-Jsc.exe(白名单)

## 来自ATT&CK的描述
攻击者可能会利用受信任的开发人员使用的程序来代理执行恶意载荷。有许多用于软件开发相关任务的实用程序可用于执行各种形式的代码，以协助开发、调试和逆向工程。这些实用程序通常可能使用合法证书进行签名，允许它们在系统上执行并通过有效绕过应用程序控制解决方案的受信任进程代理执行恶意代码。

## 测试案例
jsc.exe是Microsoft Corporation开发的Microsoft®JScript .NET的一部分，用来将javascript代码编译为.exe或.dll格式的二进制文件。

路径：
```
- C:\Windows\Microsoft.NET\Framework\v4.0.30319\Jsc.exe
- C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Jsc.exe
- C:\Windows\Microsoft.NET\Framework\v2.0.50727\Jsc.exe
- C:\Windows\Microsoft.NET\Framework64\v2.0.50727\Jsc.exe
```

使用jsc.exe编译存储在scriptfile.js中的javascript代码并输出scriptfile.exe。
```
jsc.exe scriptfile.js
```

用例：在系统上编译攻击者代码。绕过防御性反措施。  
所需权限： 用户  
操作系统：Windows vista、Windows 7、Windows 8、Windows 8.1、Windows 10

  
使用jsc.exe编译存储在Library.js中的javascript代码并输出Library.dll。  

```
jsc.exe /t:library Library.js
```

用例：在系统上编译攻击者代码。绕过防御性反措施。  
所需权限： 用户  
操作系统：Windows vista、Windows 7、Windows 8、Windows 8.1、Windows 10

## 检测日志

windows security

## 测试复现
无
## 测试留痕
无
## 检测规则/思路
除非用于开发，否则Jsc.exe通常不应在系统中运行。

## 参考推荐

MITRE-ATT&CK-T1127

<https://attack.mitre.org/techniques/T1127>

Jsc.exe

<https://lolbas-project.github.io/lolbas/Binaries/Jsc/>

远控免杀专题(67)-白名单(113个)总结篇

<http://www.smatrix.org/forum/forum.php?mod=viewthread&tid=316>
