# T1566-001-win-可疑的MS Office子进程

## 来自ATT&CK的描述

攻击者可能发送带有恶意附件的鱼叉式电子邮件，以试图访问受害者系统。鱼叉式附件与其他形式的鱼叉式附件的不同之处在于，它使用了附加到电子邮件的恶意软件。所有形式的鱼叉式广告都是以电子方式交付的针对特定个人，公司或行业的社会工程学。在这种情况下，攻击者会将文件附加到欺骗性电子邮件中，并且通常依靠用户执行来获得执行。

附件有很多选项，例如Microsoft Office文档，可执行文件，PDF或存档文件。打开附件（并可能单击过去的保护）后，攻击者的有效负载会利用漏洞或直接在用户的系统上执行。鱼叉式电子邮件的文本通常试图给出一个合理的原因来解释为什么应该打开该文件，并且可能会解释如何绕开系统保护措施。该电子邮件还可能包含有关如何解密附件（例如zip文件密码）的说明，以逃避电子邮件边界防御。攻击者经常操纵文件扩展名和图标，以使附加的可执行文件看起来像文档文件，或者利用一个应用程序的文件看起来像是另一文件的文件。

## 测试案例

暂无

## 检测日志

windows安全日志/sysmon日志

## 测试复现

暂无测试案例

## 测试留痕

暂无，可参看windows 4688进程创建日志样例，辅助理解。

```yml
Pre-Windows 2016/10
A new process has been created.

Subject:

   Security ID:  WIN-R9H529RIO4Y\Administrator
   Account Name:  Administrator
   Account Domain:  WIN-R9H529RIO4Y
   Logon ID:  0x1fd23

Process Information:

   New Process ID:  0xed0
   New Process Name: C:\Windows\System32\notepad.exe
   Token Elevation Type: TokenElevationTypeDefault (1)
   Mandatory Label: Mandatory Label\Medium Mandatory Level
   Creator Process ID: 0x8c0
   Creator Process Name: c:\windows\system32\explorer.exe
   Process Command Line: C:\Windows\System32\notepad.exe c:\sys\junk.txt
```

## 检测规则/思路

### Elastic rule query

```yml
event.action:"Process Create (rule: ProcessCreate)" and
process.parent.name:(eqnedt32.exe or excel.exe or fltldr.exe or
msaccess.exe or mspub.exe or powerpnt.exe or winword.exe) and
process.name:(Microsoft.Workflow.Compiler.exe or arp.exe or
atbroker.exe or bginfo.exe or bitsadmin.exe or cdb.exe or certutil.exe
or cmd.exe or cmstp.exe or cscript.exe or csi.exe or dnx.exe or
dsget.exe or dsquery.exe or forfiles.exe or fsi.exe or ftp.exe or
gpresult.exe or hostname.exe or ieexec.exe or iexpress.exe or
installutil.exe or ipconfig.exe or mshta.exe or msxsl.exe or
nbtstat.exe or net.exe or net1.exe or netsh.exe or netstat.exe or
nltest.exe or odbcconf.exe or ping.exe or powershell.exe or pwsh.exe
or qprocess.exe or quser.exe or qwinsta.exe or rcsi.exe or reg.exe or
regasm.exe or regsvcs.exe or regsvr32.exe or sc.exe or schtasks.exe or
systeminfo.exe or tasklist.exe or tracert.exe or whoami.exe or
wmic.exe or wscript.exe or xwizard.exe)
```

### 建议

可自行转换为sigma格式，来实现对多个平台的支持。

## 参考推荐

MITRE-ATT&CK-T1566-001

<https://attack.mitre.org/techniques/T1566/001/>

检测可疑的MS Office子进程

<https://www.elastic.co/guide/en/siem/guide/current/suspicious-ms-office-child-process.html>