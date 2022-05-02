# T1590-win-DNS记录获取

## 来自ATT&CK的描述

在攻击受害者之前，攻击者可能会收集有关受害者DNS的信息，这些信息可在目标确定期间使用。

在域渗透中，对域环境的信息搜集很关键，如果我们获得了域内管理员的权限，那么如何能够快速了解域内的网络架构呢？DNS记录无疑是一个很好的参考。

## 测试案例

本文包含以下内容：

- 通过dnscmd获取DNS记录

dnscmd：用来管理DNS服务器的命令行接口，支持远程连接

默认安装的系统：

- Windows Server 2003
- Windows Server 2008
- Windows Server 2003 R2
- Windows Server 2008 R2
- Windows Server 2012
- Windows Server 2003 with SP1
- …

参考资料：

<https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/cc772069(v=ws.11)>

Win7系统在使用时需要安装Remote Server Administration Tools (RSAT)

参考地址：

<https://support.microsoft.com/en-us/help/2693643/remote-server-administration-tools-rsat-for-windows-operating-systems>

RSAT下载地址：

<https://www.microsoft.com/en-us/download/details.aspx?id=7887>

## 检测日志

Windows安全日志

## 测试复现

### 常用命令

未能实现三好学生大佬说的效果，同样我的Windows server 2008R2并不支持dnscmd这个命令。很无奈。在Windows server 2016中并没有"."，值得注意。

```yml
C:\Users\12306br0>dnscmd ./ZoneInfo 361a.com
指定了未知的命令“361a.com” -- 键入 DnsCmd -?。


在将来的 Windows 版本中，Microsoft 可能会删除 dnscmd.exe。

如果你当前使用 dnscmd.exe 配置和管理 DNS 服务器，
Microsoft 建议你过渡到 Windows PowerShell。

若要查看 DNS 服务器管理命令列表，请在
Windows PowerShell 提示符处键入 "Get-Command -Module DnsServer"。
有关适用于 DNS 的 Windows PowerShell 命令的详细信息，请参阅
http://go.microsoft.com/fwlink/?LinkId=217627。

用法: DnsCmd <ServerName> <Command> [<Command Parameters>]

<ServerName>:
  IP 地址或主机名    -- 远程或本地 DNS 服务器。
  .                  -- 本地计算机上的 DNS 服务器
<Command>:
  /Info                      -- 获取服务器信息
  /Config                    -- 重置服务器或区域配置
  /EnumZones                 -- 枚举区域
  /Statistics                -- 查询/清除服务器统计信息数据
  /ClearCache                -- 清除 DNS 服务器缓存
  /WriteBackFiles            -- 写入所有区域或根提示数据文件
  /StartScavenging           -- 开始服务器清理
  /IpValidate                -- 验证远程 DNS 服务器
  /EnumKSPs                  -- 枚举可用的密钥存储提供程序
  /ResetListenAddresses      -- 将服务器 IP 地址设置为服务 DNS 请求
  /ResetForwarders           -- 将 DNS 服务器设置为转发递归查询
  /ZoneInfo                  -- 查看区域信息
  /ZoneAdd                   -- 在 DNS 服务器上创建新区域
  /ZoneDelete                -- 从 DNS 服务器或 DS 删除区域
  /ZonePause                 -- 暂停区域
  /ZoneResume                -- 恢复区域
  /ZoneReload                -- 从其数据库(文件或 DS)重新加载区域
  /ZoneWriteBack             -- 将区域写回到文件
  /ZoneRefresh               -- 强制刷新主机的辅助区域
  /ZoneUpdateFromDs          -- 使用来自 DS 的数据更新 DS 集成区域
  /ZonePrint                 -- 显示区域中的所有记录
  /ZoneResetType             -- 更改区域类型
  /ZoneResetSecondaries      -- 重置区域的辅助\通知信息
  /ZoneResetScavengeServers  -- 重置区域的清理服务器
  /ZoneResetMasters          -- 重置辅助区域的主服务器
  /ZoneExport                -- 将区域导出到文件
  /ZoneChangeDirectoryPartition -- 将区域移动到另一目录分区
  /ZoneSeizeKeymasterRole    -- 占用区域的密钥主机角色
  /ZoneTransferKeymasterRole -- 传送区域的密钥主机角色
  /ZoneEnumSKDs              -- 枚举区域的签名密钥描述符
  /ZoneAddSKD                -- 为区域创建新的签名密钥描述符
  /ZoneDeleteSKD             -- 删除区域的签名密钥描述符
  /ZoneModifySKD             -- 修改区域的签名密钥描述符
  /ZoneValidateSigningParameters -- 验证区域的 DNSSEC 联机签名参数
  /ZoneSetSKDState           -- 为区域的签名密钥描述符设置活动和/或待机密钥
  /ZoneGetSKDState           -- 检索区域的签名密钥描述符的动态状态
  /ZonePerformKeyRollover    -- 在区域的签名密钥描述符中触发密钥滚动更新
  /ZonePokeKeyRollover       -- 在区域的签名密钥描述符中触发密钥滚动更新
  /ZoneSign                  -- 使用 DNSSEC 联机签名参数为区域签名
  /ZoneUnsign                -- 从已签名的区域中删除 DNSSEC 签名
  /ZoneResign                -- 在已签名的区域中重新生成 DNSSEC 签名
  /EnumRecords               -- 枚举同一名称的记录
  /RecordAdd                 -- 在区域或根提示中创建记录
  /RecordDelete              -- 从区域、根提示或缓存中删除记录
  /NodeDelete                -- 删除同一名称的所有记录
  /AgeAllRecords             -- 对区域中的节点进行强制老化
  /TrustAnchorAdd            -- 在 DNS 服务器上创建新的信任密钥区域
  /TrustAnchorDelete         -- 从 DNS 服务器或 DS 删除信任密钥区域
  /EnumTrustAnchors          -- 显示信任定位点的状态信息
  /TrustAnchorsResetType     -- 更改信任密钥区域的区域类型
  /EnumDirectoryPartitions   -- 枚举目录分区
  /DirectoryPartitionInfo    -- 获取有关目录分区的信息
  /CreateDirectoryPartition  -- 创建目录分区
  /DeleteDirectoryPartition  -- 删除目录分区
  /EnlistDirectoryPartition  -- 将 DNS 服务器添加到分区复制作用域
  /UnenlistDirectoryPartition -- 从复制作用域中删除 DNS 服务器
  /CreateBuiltinDirectoryPartitions -- 创建内置分区
  /ExportSettings            -- 将设置输出到 DNS 服务器数据库目录中的 DnsSettings.txt
  /OfflineSign               -- 脱机签名区域文件，包括密钥生成/删除
  /EnumTrustPoints           -- 显示所有信任点的有效刷新信息
  /ActiveRefreshAllTrustPoints -- 立即对所有信任点执行有效刷新
  /RetrieveRootTrustAnchors  -- 通过 HTTPS 检索根信任定位点

<Command Parameters>:
  DnsCmd <CommandName> /? -- 有关特定命令的帮助信息

在将来的 Windows 版本中，Microsoft 可能会删除 dnscmd.exe。

如果你当前使用 dnscmd.exe 配置和管理 DNS 服务器，
Microsoft 建议你过渡到 Windows PowerShell。

若要查看 DNS 服务器管理命令列表，请在
Windows PowerShell 提示符处键入 "Get-Command -Module DnsServer"。
有关适用于 DNS 的 Windows PowerShell 命令的详细信息，请参阅
http://go.microsoft.com/fwlink/?LinkId=217627。
```

## 测试留痕

```yml
已创建新进程。

创建者主题:
 安全 ID:  361A\12306br0
 帐户名:  12306br0
 帐户域:  361A
 登录 ID:  0x36D7FD

目标主题:
 安全 ID:  NULL SID
 帐户名:  -
 帐户域:  -
 登录 ID:  0x0

进程信息:
 新进程 ID:  0x111c
 新进程名称: C:\Windows\System32\dnscmd.exe
 令牌提升类型: %%1938
 强制性标签:  Mandatory Label\Medium Mandatory Level
 创建者进程 ID: 0xb40
 创建者进程名称: C:\Windows\System32\cmd.exe
 进程命令行: dnscmd  /ZoneInfo 361a.com
```

## 检测规则/思路

### 建议

最简单的办法就是检测相关命令行及进程，但这似乎不是很靠谱。

## 参考推荐

MITRE-ATT&CK-T1590

<https://attack.mitre.org/techniques/T1590/>

域渗透——DNS记录的获取

<https://3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-DNS%E8%AE%B0%E5%BD%95%E7%9A%84%E8%8E%B7%E5%8F%96>
