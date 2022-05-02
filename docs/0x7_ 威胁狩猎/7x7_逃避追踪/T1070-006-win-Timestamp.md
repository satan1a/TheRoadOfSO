# T1070-006-win-Timestamp

## 来自ATT&CK的描述

Timestomping是一种修改文件时间(创建时间,修改时间)的技术,通常来将恶意文件和本文件夹其他的文件弄成相同的时间。

##  测试案例

具体参考下方测试复现过程(均需要拥有文件的所有权限)。主要涉及到touch命令的使用。

```
sos@sos-pc:/$ touch --help
用法：touch [选项]... 文件...
将所指定的每个文件的访问时间和修改时间更改为当前时间。

除非提供 -c 或 -h 选项，否则指定不存在的文件将会被创建为空文件。

如果所指定文件名为 - 则特殊处理，程序将更改与标准输出相关联的文件的
访问时间。

必选参数对长短选项同时适用。
  -a			只更改访问时间
  -c, --no-create	不创建任何文件
  -d, --date=字符串	使用指定字符串表示时间而非当前时间
  -f			(忽略)
  -h, --no-dereference		会影响符号链接本身，而非符号链接所指示的目的地
				(当系统支持更改符号链接的所有者时，此选项才有用)
  -m			只更改修改时间
  -r, --reference=文件   使用指定文件的时间属性而非当前时间
  -t 时间戳              使用给定 [[CC]YY]MMDDhhmm[.ss] 的时间戳而非当前时间
      --time=类型        修改指定类型的时间：
                           若所指定类型是 access、atime 或 use：与 -a 等效
                           若所指定类型是 modify 或 mtime：与 -m 等效
      --help		显示此帮助信息并退出
      --version		显示版本信息并退出

请注意，-d 和-t 选项可接受不同的时间/日期格式。

GNU coreutils 在线帮助：<https://www.gnu.org/software/coreutils/>
请向 <http://translationproject.org/team/zh_CN.html> 报告 touch 的翻译错误
完整文档请见：<https://www.gnu.org/software/coreutils/touch>
或者在本地使用：info '(coreutils) touch invocation'

```

## 检测日志

Linux Audit、History

## 测试复现

### 测试1 SET A FILE’S ACCESS TIMESTAMP

```
touch -a -t 197001010000.00 #{target_filename}
```

查看

```
sos@sos-pc:/hacker$ sudo touch -a -t 197001010000.00 test.txt 
sos@sos-pc:/hacker$ stat test.txt 
  文件：test.txt
  大小：0         	块：0          IO 块：4096   普通空文件
设备：805h/2053d	Inode：3018665     硬链接：1
权限：(0644/-rw-r--r--)  Uid：(    0/    root)   Gid：(    0/    root)
最近访问：1970-01-01 00:00:00.000000000 +0800
最近更改：2022-01-09 19:47:00.397395450 +0800
最近改动：2022-01-09 19:47:09.966100333 +0800
创建时间：-

```

成功复现

### 测试2 SET A FILE’S MODIFICATION TIMESTAMP

```
touch -m -t 197001010000.00 #{target_filename}
```

查看

```
sos@sos-pc:/hacker$ stat test.txt 
  文件：test.txt
  大小：0         	块：0          IO 块：4096   普通空文件
设备：805h/2053d	Inode：3018665     硬链接：1
权限：(0644/-rw-r--r--)  Uid：(    0/    root)   Gid：(    0/    root)
最近访问：1970-01-01 00:00:00.000000000 +0800
最近更改：2090-01-01 00:00:00.000000000 +0800
最近改动：2022-01-09 19:48:28.929618189 +0800
创建时间：-
```

成功复现

### 测试3 SET A FILE’S CREATION TIMESTAMP

先修改系统时间,然后创建文件,然后再把系统时间修改过来

```
date -s "1990-01-01 00:00:00"
touch #{target_filename}
date -s "$NOW"
```

未复现成功

### 测试4 MODIFY FILE TIMESTAMPS USING REFERENCE FILE

```
touch -acmr #{reference_file_path} {target_file_path}
```

查看

```
sos@sos-pc:/hacker$ sudo touch -acmr /hacker/hfish/config.ini /hacker/one.txt 
sos@sos-pc:/hacker$ stat one.txt 
  文件：one.txt
  大小：0         	块：0          IO 块：4096   普通空文件
设备：805h/2053d	Inode：3018666     硬链接：1
权限：(0644/-rw-r--r--)  Uid：(    0/    root)   Gid：(    0/    root)
最近访问：2021-02-02 17:57:52.294812586 +0800
最近更改：2020-12-21 16:54:40.000000000 +0800
最近改动：2022-01-09 19:55:55.945380351 +0800
创建时间：-
```

成功复现

## 日志留痕

```
918  sudo touch -a -t 197001010000.00 test.txt 
919  stat test.txt 
920  sudo touch -m -t 209001010000.00  test.txt 
921  stat test.txt 

```

## 检测规则/思路
### sigma规则

对相关命令进行检测是一种简单的方法，但是会存在绕过风险。

### 建议

现有的取证技术可以检测出时间戳被修改的文件的各个方面。可以使用文件修改监控来检测时间戳，该监控收集文件打开的信息，并可以比较时间戳值。

## 参考推荐
MITRE-ATT&CK-T1036

<https://attack.mitre.org/techniques/T1070/006>

跟着ATT&CK学安全之defense-evasion

<https://snappyjack.github.io/articles/2020-01/%E8%B7%9F%E7%9D%80ATT&CK%E5%AD%A6%E5%AE%89%E5%85%A8%E4%B9%8Bdefense-evasion>

